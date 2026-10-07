import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from anthropic import APIConnectionError
from pydantic import ValidationError

from src.cases import load_and_validate_cases
from src.runner import run_eval
from src.triage import FinalTriageReport, Status


def test_run_eval_aborts_before_execution_on_invalid_cases_yaml(tmp_path):
    """スキーマ違反のケースYAMLを渡すと読み込み段階で例外が発生し、LLM実行関数が1回も呼ばれずに中断すること"""
    invalid_yaml = tmp_path / "invalid_cases.yaml"
    # cve_id が欠落したスキーマ違反のYAML
    invalid_yaml.write_text(
        """
- id: case_999
  cell: 1
  description: テストケース
  profile_path: stack-profile.yaml
  alas_path: ALAS2023-2026-3091.txt
  expected:
    status: 対応不要
    missing_config_keys: []
""",
        encoding="utf-8",
    )

    mock_llm_func = MagicMock()

    # スキーマ検証エラー（ValidationError）が発生すること
    with pytest.raises(ValidationError):
        run_eval(cases_path=invalid_yaml, llm_func=mock_llm_func, output_dir=tmp_path)

    mock_llm_func.assert_not_called()


def test_run_eval_executes_specified_repeat_count_per_case(tmp_path):
    """4件x5回=計20回ループが正しく実行され、FinalTriageReportがjson.dump可能に変換されて保存されること"""
    # Pydanticモデルを返すモック
    mock_report = FinalTriageReport.model_construct(
        overall_triage_result=Status.NOT_NEEDED,
        notes="テスト用理由",
        cve_results=[],
    )
    mock_llm_func = MagicMock(return_value=mock_report)
    cases_path = Path("evals/cases.yaml")
    expected_count = len(load_and_validate_cases(cases_path)) * 5

    results = run_eval(
        cases_path=cases_path,
        llm_func=mock_llm_func,
        output_dir=tmp_path,
        repeat_count=5,
    )

    assert mock_llm_func.call_count == expected_count
    assert len(results) == expected_count

    # ディスクに正しくjson化されて保存されているかチェック
    saved_files = list(tmp_path.glob("*.json"))
    assert len(saved_files) == expected_count
    saved_data = json.loads(saved_files[0].read_text(encoding="utf-8"))
    assert saved_data["status"] == "SUCCESS"
    assert saved_data["detail"]["overall_triage_result"] == "対応不要"


def test_run_eval_persists_results_incrementally_on_interruption(tmp_path):
    """3回目で想定外の例外(RuntimeError)が発生しても、1〜2回目までの実行結果が逐次保存されており、かつ例外が外へ送出されること"""
    call_count = 0

    def llm_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise RuntimeError("想定外のコードバグ発生")
        return {"status": "対応不要"}

    with pytest.raises(RuntimeError, match="想定外のコードバグ発生"):
        run_eval(
            cases_path=Path("evals/cases.yaml"),
            llm_func=llm_side_effect,
            output_dir=tmp_path,
            repeat_count=5,
        )

    saved_files = list(tmp_path.glob("*.json"))
    assert len(saved_files) == 2


def test_run_eval_saves_api_error_result_and_continues(tmp_path):
    """APIエラー発生時、その実行回が「ケースID・何回目か・APIエラー種別」を含む失敗レコードとして1件ディスクに保存され、残りの実行が継続すること"""
    req = httpx.Request("POST", "https://api.anthropic.com")

    def llm_side_effect(*args, **kwargs):
        raise APIConnectionError(request=req)

    cases_path = Path("evals/cases.yaml")
    expected_count = len(load_and_validate_cases(cases_path)) * 5

    results = run_eval(
        cases_path=cases_path,
        llm_func=llm_side_effect,
        output_dir=tmp_path,
        repeat_count=5,
    )

    assert len(results) == expected_count

    # ディスク上の保存ファイル群および失敗レコードの中身を検証
    saved_files = list(tmp_path.glob("*.json"))
    assert len(saved_files) == expected_count

    saved_data = json.loads(saved_files[0].read_text(encoding="utf-8"))
    assert saved_data["status"] == "API_ERROR"
    assert "case_id" in saved_data
    assert "run_index" in saved_data


def test_run_eval_saves_validation_failure_result_and_continues(tmp_path):
    """検証失敗時、その実行回が「ケースID・何回目か・検証失敗種別」を含む失敗レコードとして1件ディスクに保存され、残りの実行が継続すること"""

    def llm_side_effect(*args, **kwargs):
        raise ValidationError.from_exception_data(
            title="Output ValidationError", line_errors=[]
        )

    cases_path = Path("evals/cases.yaml")
    expected_count = len(load_and_validate_cases(cases_path)) * 5

    results = run_eval(
        cases_path=cases_path,
        llm_func=llm_side_effect,
        output_dir=tmp_path,
        repeat_count=5,
    )

    assert len(results) == expected_count

    # ディスク上の保存ファイル群および失敗レコードの中身を検証
    saved_files = list(tmp_path.glob("*.json"))
    assert len(saved_files) == expected_count

    saved_data = json.loads(saved_files[0].read_text(encoding="utf-8"))
    assert saved_data["status"] == "VALIDATION_ERROR"
    assert "case_id" in saved_data
    assert "run_index" in saved_data
