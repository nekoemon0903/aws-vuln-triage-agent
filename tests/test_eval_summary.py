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
        "detail": {
            "cve_results": [
                {
                    "cve_id": "CVE-9999-9999",  # 違うCVE
                    "status": "要確認",
                    "missing_config_keys": [],
                }
            ]
        },
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
        "detail": "500 Server Error",
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
    # 本番の配置を再現 (ALASはルート、cases.yamlは evals/ ディレクトリ内)
    evals_dir = tmp_path / "evals"
    evals_dir.mkdir()

    alas_file = tmp_path / "ALAS2023-2025-1318.txt"
    alas_file.write_text("CVE-1", encoding="utf-8")

    cases_yaml = evals_dir / "cases.yaml"
    cases_yaml.write_text(
        "- id: case_001\n"
        "  cell: 1\n"
        "  description: dummy\n"
        "  profile_path: stack-profile.yaml\n"
        "  alas_path: ALAS2023-2025-1318.txt\n"
        "  cve_id: CVE-1\n"
        "  expected:\n"
        f"    status: {Status.NEED_ACTION.value}\n"
    )

    # 4件しかファイルを作成しない
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    for i in range(1, 5):
        (results_dir / f"case_001_run_{i}.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        summarize_all_cases(results_dir, cases_yaml)


# 8. ケースごとの分離集計検証(データ取り違え検知)
def test_summarize_all_cases_separates_by_case_id(tmp_path: Path):
    """
    検証内容: 複数ケース(case_001: 期待=要対応/結果=要対応, case_002: 期待=要確認/結果=要確認)が存在する場合、それぞれの期待値と組み合わせて集計されること。
            (取り違えが発生すると正解率が1.0から0.0に落ちることで検知)
    """
    # 本番の配置を再現 (ALASはルート、cases.yamlは evals/ ディレクトリ内)
    evals_dir = tmp_path / "evals"
    evals_dir.mkdir()

    alas_file = tmp_path / "ALAS2023-2025-1318.txt"
    alas_file.write_text("CVE-1 CVE-2", encoding="utf-8")

    cases_yaml = evals_dir / "cases.yaml"
    cases_yaml.write_text(
        f"- id: case_001\n"
        f"  cell: 1\n"
        f"  description: dummy1\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NEED_ACTION.value}\n"
        f"- id: case_002\n"
        f"  cell: 2\n"
        f"  description: dummy2\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-2\n"
        f"  expected:\n"
        f"    status: {Status.NEED_CHECK.value}\n"
        f'    missing_config_keys: ["key1"]\n'
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

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
        (results_dir / f"case_001_run_{i}.json").write_text(json.dumps(d1))
        (results_dir / f"case_002_run_{i}.json").write_text(json.dumps(d2))

    summaries = summarize_all_cases(results_dir, cases_yaml)
    assert summaries["case_001"].accuracy_rate == 1.0
    assert summaries["case_002"].accuracy_rate == 1.0


# 9. 関門None時の表示文字列検証
def test_format_case_summary_output_handles_none_gate():
    """
    検証内容: 関門結果がNone(安全側・対応不要のケース)のサマリーを文字列化する際、"PASS"が含まれず、固定表記である"N/A"が含まれること。
    """
    summary = CaseSummary(
        case_id="case_003",
        is_passed=None,  # 安全側・対応不要
        accuracy_rate=1.0,
        key_coverage_rate=None,
        outcome_counts={ExecutionOutcome.SUCCESS: 5},
        failure_reasons=[],
    )
    output = format_case_summary(summary)
    assert "PASS" not in output
    assert "N/A" in output


# 10. 結果0件ケースのスキップ検証
def test_summarize_all_cases_skips_zero_result_cases(tmp_path: Path):
    """検証内容: 結果ファイルが0件のケースはエラーにならず除外され、5件揃っているケースのみ集計されること。"""
    evals_dir = tmp_path / "evals"
    evals_dir.mkdir()
    alas_file = tmp_path / "ALAS2023-2025-1318.txt"
    alas_file.write_text("CVE-1", encoding="utf-8")

    cases_yaml = evals_dir / "cases.yaml"
    cases_yaml.write_text(
        f"- id: case_001\n"
        f"  cell: 1\n"
        f"  description: dummy1\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NEED_ACTION.value}\n"
        f"- id: case_002\n"
        f"  cell: 4\n"
        f"  description: dummy2\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NOT_NEEDED.value}\n"
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    for i in range(1, 6):
        d = {
            "case_id": "case_001",
            "run_index": i,
            "status": "SUCCESS",
            "detail": {
                "cve_results": [{"cve_id": "CVE-1", "status": Status.NEED_ACTION.value}]
            },
        }
        (results_dir / f"case_001_run_{i}.json").write_text(json.dumps(d))

    summaries = summarize_all_cases(results_dir, cases_yaml)
    assert "case_001" in summaries
    assert "case_002" not in summaries
    assert len(summaries) == 1


# 11. スキップされたケースIDの出力検証
def test_summarize_all_cases_prints_skipped_case_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """検証内容: 0件でスキップされたケースがある場合、標準出力に未実行ケースIDが出力されること。"""
    evals_dir = tmp_path / "evals"
    evals_dir.mkdir()
    alas_file = tmp_path / "ALAS2023-2025-1318.txt"
    alas_file.write_text("CVE-1", encoding="utf-8")

    cases_yaml = evals_dir / "cases.yaml"
    cases_yaml.write_text(
        f"- id: case_001\n"
        f"  cell: 1\n"
        f"  description: dummy1\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NEED_ACTION.value}\n"
        f"- id: case_002\n"
        f"  cell: 4\n"
        f"  description: dummy2\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NOT_NEEDED.value}\n"
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    for i in range(1, 6):
        d = {
            "case_id": "case_001",
            "run_index": i,
            "status": "SUCCESS",
            "detail": {
                "cve_results": [{"cve_id": "CVE-1", "status": Status.NEED_ACTION.value}]
            },
        }
        (results_dir / f"case_001_run_{i}.json").write_text(json.dumps(d))

    summarize_all_cases(results_dir, cases_yaml)
    captured = capsys.readouterr()
    assert "未実行" in captured.out
    assert "case_002" in captured.out


# 12. 途中脱落(1〜4件)の例外送出を保護する検証
def test_summarize_all_cases_raises_on_partial_result_cases(tmp_path: Path):
    """検証内容: 1〜4件しか結果ファイルが存在しないケースは途中脱落としてValueErrorを送出すること。"""
    evals_dir = tmp_path / "evals"
    evals_dir.mkdir()
    alas_file = tmp_path / "ALAS2023-2025-1318.txt"
    alas_file.write_text("CVE-1", encoding="utf-8")

    cases_yaml = evals_dir / "cases.yaml"
    cases_yaml.write_text(
        f"- id: case_001\n"
        f"  cell: 1\n"
        f"  description: dummy1\n"
        f"  profile_path: stack-profile.yaml\n"
        f"  alas_path: ALAS2023-2025-1318.txt\n"
        f"  cve_id: CVE-1\n"
        f"  expected:\n"
        f"    status: {Status.NEED_ACTION.value}\n"
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # 3件のみ表示
    for i in range(1, 4):
        (results_dir / f"case_001_run_{i}.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="must have exactly 5 run result files"):
        summarize_all_cases(results_dir, cases_yaml)
