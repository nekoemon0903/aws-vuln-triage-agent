import pytest

from src.scoring import (
    CaseRunResult,
    ExecutionOutcome,
    Status,
    calculate_accuracy_rate,
    calculate_key_coverage_rate,
    evaluate_gate,
    summarize_case_evaluation,
)


def make_run_result(
    run_index: int,
    outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS,
    actual_status: Status = Status.NEED_ACTION,
    error_message: str | None = None,
) -> CaseRunResult:
    """テストデータ作成用のヘルパー関数"""
    return CaseRunResult(
        case_id="case_001",
        run_index=run_index,
        outcome=outcome,
        actual_status=actual_status if outcome == ExecutionOutcome.SUCCESS else None,
        error_message=error_message,
    )


# 観点1: 危険側で、5回とも正解 → 合格
def test_evaluate_gate_all_success():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 6)
    ]
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is True
    assert len(reasons) == 0


# 観点2: 危険側で、1回だけ「対応不要」 → 不合格
def test_evaluate_gate_one_not_needed_fails():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 5)
    ]
    results.append(make_run_result(5, actual_status=Status.NOT_NEEDED))
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is False
    assert any(Status.NOT_NEEDED in r for r in reasons)


# 観点3: 危険側で、1回だけCVE欠落 → 不合格
def test_evaluate_gate_cve_missing_fails():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 5)
    ]
    results.append(
        make_run_result(
            5,
            outcome=ExecutionOutcome.CVE_MISSING,
            error_message="Target CVE not found",
        )
    )
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is False
    assert any("欠落" in r for r in reasons)


# 観点4: 危険側で、1回だけAPIエラーまたは検証失敗 → 合格(理由は残す)
def test_evaluate_gate_execution_error_passes_with_reasons():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 5)
    ]
    results.append(
        make_run_result(
            5,
            outcome=ExecutionOutcome.API_ERROR,
            error_message="500 Server Error",
        )
    )
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is True
    assert len(reasons) == 1
    assert "実行時エラー" in reasons[0]


# 観点5: 安全側(期待が「対応不要」)  → 関門の対象外(合格扱い)
def test_evaluate_gate_not_needed_target_ignored():
    results = [make_run_result(i, actual_status=Status.NOT_NEEDED) for i in range(1, 6)]
    is_passed, reasons = evaluate_gate(Status.NOT_NEEDED, results)
    assert is_passed is True
    assert len(reasons) == 0


# 観点6: 結果のリストが5件でない場合(例: 3件) → ValueError
def test_evaluate_gate_invalid_count_raises_error():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 4)
    ]
    with pytest.raises(ValueError, match="must be exactly 5"):
        evaluate_gate(Status.NEED_ACTION, results)


# 正解率のテスト: 5回中3回正解 → 0.6
def test_calculate_accuracy_rate():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 4)
    ]
    results.append(make_run_result(4, actual_status=Status.NEED_CHECK))
    results.append(make_run_result(5, outcome=ExecutionOutcome.API_ERROR))

    rate = calculate_accuracy_rate(Status.NEED_ACTION, results)
    assert rate == 0.6


# 網羅率のテスト: 正解キー空 → None
def test_calculate_key_coverage_rate_empty_expected():
    results = [make_run_result(i) for i in range(1, 6)]
    rate = calculate_key_coverage_rate([], results)
    assert rate is None


# 網羅率のテスト: 5回中一部失敗・不完全なキー抽出での計算
def test_calculate_key_coverage_rate_partial_hits():
    expected_keys = ["key1", "key2"]
    results = []
    for i in range(1, 4):
        r = make_run_result(i, actual_status=Status.NEED_CHECK)
        r.actual_missing_keys = ["key1", "key2"]
        results.append(r)

    r4 = make_run_result(4, actual_status=Status.NEED_CHECK)
    r4.actual_missing_keys = ["key1"]
    results.append(r4)

    results.append(make_run_result(5, outcome=ExecutionOutcome.API_ERROR))

    rate = calculate_key_coverage_rate(expected_keys, results)
    assert rate == 0.7


# サマリー関数のテスト
def test_summarize_case_evaluation():
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 6)
    ]
    summary = summarize_case_evaluation(Status.NEED_ACTION, [], results)

    assert summary.case_id == "case_001"
    assert summary.is_passed is True
    assert summary.accuracy_rate == 1.0
    assert summary.key_coverage_rate is None
    assert summary.outcome_counts[ExecutionOutcome.SUCCESS] == 5
