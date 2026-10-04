from enum import Enum

from pydantic import BaseModel, Field

from src.triage import Status


class ExecutionOutcome(str, Enum):
    """ケース実行結果のOutcomeを表すEnum"""

    SUCCESS = "success"  # 正常完了
    API_ERROR = "api_error"  # APIエラー
    VALIDATION_ERROR = "validation_error"  # 出力検証失敗(パース崩れ等)
    CVE_MISSING = "cve_missing"  # CVE欠落


class CaseRunResult(BaseModel):
    """1回のケース実行結果を表す構造体"""

    case_id: str
    run_index: int  # 1〜5
    outcome: ExecutionOutcome
    actual_status: Status | None = None  # "要対応", "要確認", "対応不要"
    actual_missing_keys: list[str] = Field(default_factory=list)
    raw_response: dict | None = None
    error_message: str | None = None


class CaseSummary(BaseModel):
    case_id: str
    is_passed: bool | None
    accuracy_rate: float
    key_coverage_rate: float | None
    outcome_counts: dict[ExecutionOutcome, int]
    failure_reasons: list[str]


# === 判定ゲート評価ロジック ===
def evaluate_gate(
    expected_status: Status,
    run_results: list[CaseRunResult],
) -> tuple[bool, list[str]]:
    """関門セルの合否を判定する。

    - 実行結果が exactly 5 件でない場合は ValueError
    - expected_status が "対応不要"(安全側ケース)の場合は関門対象外とし(True, [])を返す
    - 危険側ケース(要対応/要確認)において、5回中1回でも以下が発生した場合は不合格(False):
        1. acutal_status == "対応不要"(見逃し)
        2. outcome == ExecutionOutcome.CVE_MISSING (CVE欠落)
    - APIエラーや検証失敗は不合格にはしないが、理由リストにエラーとして残す
    """
    if len(run_results) != 5:
        raise ValueError(
            f"run_results count must be exactly 5, but got {len(run_results)}"
        )

    # 安全側ケースは関門判定の対象外
    if expected_status == Status.NOT_NEEDED:
        return True, []

    is_passed = True
    failure_reasons = []

    for res in run_results:
        # 1. 危険側での見逃し(即Fail)
        if res.actual_status == Status.NOT_NEEDED:
            is_passed = False
            failure_reasons.append(
                f"Run {res.run_index}: 危険側ケースで'対応不要'(見逃し)が出力されました"
            )

        # 2. CVE欠落(即Fail)
        elif res.outcome == ExecutionOutcome.CVE_MISSING:
            is_passed = False
            failure_reasons.append(
                f"Run {res.run_index}: 結果から対象CVEが欠落しています"
            )

        # 3. APIエラーまたは検証失敗(不合格にはしないがログとして記録)
        elif res.outcome in {
            ExecutionOutcome.API_ERROR,
            ExecutionOutcome.VALIDATION_ERROR,
        }:
            failure_reasons.append(
                f"Run {res.run_index}: 実行時エラーが発生しました ({res.outcome.value}: {res.error_message})"
            )

    return is_passed, failure_reasons


def calculate_accuracy_rate(
    expected_status: Status,
    run_results: list[CaseRunResult],
) -> float:
    """Statusの正解率(一致数/全施行数5)を算出する"""
    if len(run_results) != 5:
        raise ValueError("run_results count must be exactly 5")

    expected = Status(expected_status)
    match_count = sum(
        1
        for res in run_results
        if res.outcome == ExecutionOutcome.SUCCESS and res.actual_status == expected
    )
    return match_count / 5.0


def calculate_key_coverage_rate(
    expected_missing_keys: list[str],
    run_results: list[CaseRunResult],
) -> float | None:
    """不足キーの網羅率を算出する

    - 正解の不足キーが空リストの場合はNone(対象外)
    - 失敗した実行や正解キーを含まない実行は網羅率0.0として分母(5)に含める
    """
    if len(run_results) != 5:
        raise ValueError("run_results count must be exactly 5")

    if not expected_missing_keys:
        return None

    expected_set = set(expected_missing_keys)
    total_coverage = 0.0

    for res in run_results:
        if res.outcome == ExecutionOutcome.SUCCESS and res.actual_missing_keys:
            actual_set = set(res.actual_missing_keys)
            hit_count = len(expected_set & actual_set)
            run_coverage = hit_count / len(expected_set)
            total_coverage += run_coverage

    return total_coverage / 5.0


def summarize_case_evaluation(
    expected_status: Status,
    expected_missing_keys: list[str],
    run_results: list[CaseRunResult],
) -> CaseSummary:
    """1ケース(5回実行)の採点サマリーを作成する"""
    if len(run_results) != 5:
        raise ValueError("run_results count must be exactly 5")

    case_id = run_results[0].case_id
    is_passed, failure_reasons = evaluate_gate(expected_status, run_results)
    accuracy = calculate_accuracy_rate(expected_status, run_results)
    coverage = calculate_key_coverage_rate(expected_missing_keys, run_results)

    outcome_counts = {outcome: 0 for outcome in ExecutionOutcome}
    for res in run_results:
        outcome_counts[res.outcome] += 1

    return CaseSummary(
        case_id=case_id,
        is_passed=is_passed,
        accuracy_rate=accuracy,
        key_coverage_rate=coverage,
        outcome_counts=outcome_counts,
        failure_reasons=failure_reasons,
    )
