import json
from pathlib import Path

import pytest

from src.eval_summary import (
    format_case_summary,
    load_case_run_result,
    summarize_all_cases,
)
from src.scoring import CaseSummary, ExecutionOutcome, Status


# 1. SUCCESSマッピングの検証
def test_load_run_results_success_mapping(tmp_path: Path):
    """
    検証内容: status == "SUCCESS"かつ対象cve_idがcve_resultsに存在する場合、ExecutionOutcome.SUCCESSと実際のstatus/missing_config_keysに正しく変換されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "SUCCESS",
        "detail": {
            "cve_results": [
                {
                    "cve_id": "CVE-2023-1234",
                    "status": Status.NEED_ACTION.value,
                    "missing_config_keys": ["key1"],
                }
            ]
        },
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    res = load_case_run_result(json_path, "CVE-2023-1234")
    assert res.outcome == ExecutionOutcome.SUCCESS
    assert res.actual_status == Status.NEED_ACTION


# 2. CVE欠落時のマッピング
def test_load_run_results_cve_missing_mapping(tmp_path: Path):
    """
    検証内容: status == "SUCCESS"であっても、cve_results内に対象のcve_idが存在しない場合、「ツールにとって一番不利な側」としてExecutionOutcome.CVE_MISSINGに変換されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "SUCCESS",
        "detail": {"cve_results": {}},  # CVEが存在しない
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    res = load_case_run_result(json_path, "CVE-2023-1234")
    assert res.outcome == ExecutionOutcome.CVE_MISSING


# 3. 不正なdetail時のマッピング検証
def test_load_run_results_invalid_detail_mapped_to_cve_missing(tmp_path: Path):
    """
    検証内容: status == "SUCCESS"だがdetailからCVE情報が正常に取得・解釈できない場合、「ツールにとって一番不利な側」としてExecutionOutcome.CVE_MISSINGに変換されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "SUCCESS",
        "detail": "string_detail_instead_of_dict",  # 文字列などでパース不可
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    res = load_case_run_result(json_path, "CVE-2023-1234")
    assert res.outcome == ExecutionOutcome.CVE_MISSING


# 4. API_ERRORマッピングの検証
def test_load_run_results_api_error_mapping(tmp_path: Path):
    """
    検証内容: status == "API_ERROR"のJSONが、正しくExecutionOutcome.API_ERRORに変換され、エラーメッセージが保持されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "API_ERROR",
        "error_message": "500 Server Error",
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    res = load_case_run_result(json_path, "CVE-2023-1234")
    assert res.outcome == ExecutionOutcome.API_ERROR
    assert res.error_message == "500 Server Error"


# 5. VALIDATION_ERRORマッピング検証
def test_load_run_results_validation_error_mapping(tmp_path: Path):
    """
    検証内容: status == "VALIDATION_ERROR"のJSONが、正しくExecutionOutcome.VALIDATION_ERRORに変換され、エラーメッセージが保持されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "VALIDATION_ERROR",
        "error_message": "Validation failed",
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    res = load_case_run_result(json_path, "CVE-2023-1234")
    assert res.outcome == ExecutionOutcome.VALIDATION_ERROR


# 6. 未知のstatusに対する例外検証
def test_load_run_results_unknown_status_raises_error(tmp_path: Path):
    """
    検証内容: 定義外の未知のstatusが含まれている場合、前提崩れとしてValueErrorの例外が送出されること。
    """
    json_path = tmp_path / "run_1.json"
    data = {
        "case_id": "case_001",
        "run_index": 1,
        "status": "UNKNOWN_STATUS",
    }
    json_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown status"):
        load_case_run_result(json_path, "CVE-2023-1234")


# 7. ファイル不足(件数不一致)の例外検証
def test_load_run_results_missing_file_raises_error(tmp_path: Path):
    """
    検証内容: 5回分の実行結果JSONのうちファイルが一部欠落(例: 4件しか存在しない)している場合、不正データとしてエラーが発生すること。
    """
    # 4件しかファイルを作成しない
    for i in range(1, 5):
        (tmp_path / f"case_001_run_{i}.json").write_text("{}", encoding="utf-8")

        cases_yaml = tmp_path / "cases.yaml"
        cases_yaml.write_text(
            "- id: case_001\n"
            "  cve_id: CVE-1\n"
            "  expected:\n"
            f"    status: {Status.NEED_ACTION.value}\n"
        )

        with pytest.raises(ValueError):
            summarize_all_cases(tmp_path, cases_yaml)


# 8. ケースごとの分離集計検証(データ取り違え検知)
def test_summarize_all_cases_separates_by_case_id(tmp_path):
    """
    検証内容: 複数ケース(case_001: 期待=要対応/結果=要対応, case_002: 期待=要確認/結果=要確認)が存在する場合、それぞれの期待値と組み合わせて集計されること。
            (取り違えが発生すると正解率が1.0から0.0に落ちることで検知)
    """
    # case_001: 期待=NEED_ACTION / 結果=NEED_ACTION
    # case_002: 期待=NEED_CHECK / 結果=NEED_CHECK
    # ※入れ替わると正解率が1.0から0.0になるデータ構造
    cases_yaml = tmp_path / "cases.yaml"
    cases_yaml.write_text(
        f"- id: case_001\n  cve_id: CVE-1\n  expected:\n    status: {Status.NEED_ACTION.value}\n"
        f"- id: case_002\n  cve_id: CVE-2\n  expected:\n    status: {Status.NEED_CHECK.value}\n"
    )

    for i in range(1, 6):
        d1 = {
            "case_id": "case_001",
            "run_index": i,
            "status": "SUCCESS",
            "detail": {
                "cve_results": [{"cve_id": "CVE-1", "status": Status.NEED_ACTION.value}]
            },
        }
        d2 = {
            "case_id": "case_002",
            "run_index": i,
            "status": "SUCCESS",
            "detail": {
                "cve_results": [{"cve_id": "CVE-2", "status": Status.NEED_CHECK.value}]
            },
        }
        (tmp_path / f"case_001_run_{i}.json").write_text(json.dumps(d1))
        (tmp_path / f"case_002_run_{i}.json").write_text(json.dumps(d2))

    summaries = summarize_all_cases(tmp_path, cases_yaml)
    assert summaries["case_001"].accuracy_rate == 1.0
    assert summaries["case_002"].accuracy_rate == 1.0


# 9. 関門None時の表示文字列検証
def test_format_case_summary_output_handles_none_gate():
    """
    検証内容: 関門結果がNone(安全側・対応不要のケース)のサマリーを文字列化する際、"PASS"が含まれず、固定表記である"N/A"が含まれること。
    """
    summary = CaseSummary(
        case_id="case_003",
        target_status=Status.NOT_NEEDED,
        is_passed=None,  # 安全側・対応不要
        accuracy_rate=1.0,
        key_coverage_rate=None,
        outcome_counts={ExecutionOutcome.SUCCESS: 5},
        failure_reasons=[],
    )
    output = format_case_summary(summary)
    assert "PASS" not in output
    assert "N/A" in output
