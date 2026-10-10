import json
from pathlib import Path

import yaml

from src.scoring import (
    CaseRunResult,
    CaseSummary,
    ExecutionOutcome,
    Status,
    summarize_case_evaluation,
)


def load_case_run_result(json_path: Path, cve_id: str) -> CaseRunResult:
    data = json.loads(json_path.read_text(encoding="utf-8"))

    case_id = data.get("case_id", "")
    run_index = data.get("run_index", 0)
    raw_status = data.get("status")
    detail = data.get("detail")

    if raw_status not in ("SUCCESS", "API_ERROR", "VALIDATION_ERROR"):
        raise ValueError(f"Unknown status: {raw_status}")

    error_message = data.get("error_message") or (
        detail if isinstance(detail, str) else None
    )

    if raw_status == "API_ERROR":
        return CaseRunResult(
            case_id=case_id,
            run_index=run_index,
            outcome=ExecutionOutcome.API_ERROR,
            error_message=error_message,
        )

    if raw_status == "VALIDATION_ERROR":
        return CaseRunResult(
            case_id=case_id,
            run_index=run_index,
            outcome=ExecutionOutcome.VALIDATION_ERROR,
            error_message=error_message,
        )

    if not isinstance(detail, dict):
        return CaseRunResult(
            case_id=case_id,
            run_index=run_index,
            outcome=ExecutionOutcome.CVE_MISSING,
            error_message="Detail is not a valid dict",
        )

    # 本番仕様: cve_results は list[dict]
    cve_results = detail.get("cve_results", [])
    target_res = None
    if isinstance(cve_results, list):
        for item in cve_results:
            if isinstance(item, dict) and item.get("cve_id") == cve_id:
                target_res = item
                break

    if target_res is None:
        return CaseRunResult(
            case_id=case_id,
            run_index=run_index,
            outcome=ExecutionOutcome.CVE_MISSING,
            error_message=f"Target CVE {cve_id} missing in results",
        )

    actual_status_str = target_res.get("status")
    actual_status = Status(actual_status_str) if actual_status_str else None
    actual_missing_keys = target_res.get("missing_config_keys", [])

    return CaseRunResult(
        case_id=case_id,
        run_index=run_index,
        outcome=ExecutionOutcome.SUCCESS,
        actual_status=actual_status,
        actual_missing_keys=actual_missing_keys,
    )


def summarize_all_cases(
    results_dir: Path, cases_yaml_path: Path
) -> dict[str, CaseSummary]:
    cases_data = yaml.safe_load(cases_yaml_path.read_text(encoding="utf-8"))
    summaries: dict[str, CaseSummary] = {}

    # 本番の cases.yaml は list 構造
    for case_info in cases_data:
        case_id = case_info["id"]
        target_cve = case_info["cve_id"]
        expected = case_info.get("expected", {})
        expected_status = Status(expected["status"])
        expected_keys = expected.get("missing_config_keys", []) or []

        json_files = sorted(results_dir.glob(f"{case_id}_run_*.json"))
        if len(json_files) != 5:
            raise ValueError(
                f"Case {case_id} must have exactly 5 run result files, found {len(json_files)}"
            )

        run_results = [load_case_run_result(f, target_cve) for f in json_files]
        summary = summarize_case_evaluation(expected_status, expected_keys, run_results)
        summaries[case_id] = summary

    return summaries


def format_case_summary(summary: CaseSummary) -> str:
    if summary.is_passed is True:
        gate_str = "PASS"
    elif summary.is_passed is False:
        gate_str = "FAIL"
    else:
        gate_str = "N/A"

    acc_str = (
        f"{summary.accuracy_rate * 100:.1f}%"
        if summary.accuracy_rate is not None
        else "N/A"
    )
    cov_str = (
        f"{summary.key_coverage_rate * 100:.1f}%"
        if summary.key_coverage_rate is not None
        else "N/A"
    )

    return f"[{summary.case_id}] Gate: {gate_str} | Accuracy: {acc_str} | Coverage: {cov_str}"
