import pytest

from src.scoring import (
    CaseRunResult,
    ExecutionOutcome,
    Status,
    calculate_accuracy_rate,
    calculate_key_coverage_rate,
    evaluate_gate,
    normalize_key,
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


def make_5_run_results(
    actual_missing_keys: list[str],
    actual_status: Status = Status.NEED_CHECK,
) -> list[CaseRunResult]:
    """同じ actual_missing_keys を持つ5回分の成功結果を生成するヘルパー関数"""
    results = []
    for i in range(1, 6):
        r = make_run_result(i, actual_status=actual_status)
        r.actual_missing_keys = actual_missing_keys
        results.append(r)
    return results


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


# 観点5: 安全側(期待が「対応不要」)  → 関門の対象外
def test_evaluate_gate_returns_none_for_not_needed_target():
    results = [make_run_result(i, actual_status=Status.NOT_NEEDED) for i in range(1, 6)]
    is_passed, reasons = evaluate_gate(Status.NOT_NEEDED, results)
    assert is_passed is None
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


def test_evaluate_gate_passes_on_wrong_status_other_than_not_needed():
    """
    検証内容: 危険側(期待が「要対応」)において、「要確認」が出た場合でも、関門は合格(True)になること。
    振る舞い検証: 関門は「対応不要」のすり抜けのみを弾き、安全側へのズレで合否を落とさない(正解率で評価する)振る舞いを保証する。
    """
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 5)
    ]
    results.append(make_run_result(5, actual_status=Status.NEED_CHECK))
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is True
    assert len(reasons) == 0


def test_evaluate_gate_validation_error_passes_with_reasons():
    """
    検証内容: 実行結果にVALIDATION_ERRORが含まれる場合でも関門は合格(True)となり、理由メッセージが残ること。
    振る舞い検証: API_ERRORと同様、検証失敗も関門では不合格にせず、人が気づけるよう理由を残して正解率で評価する振る舞いを保証する。
    """
    results = [
        make_run_result(i, actual_status=Status.NEED_ACTION) for i in range(1, 5)
    ]
    results.append(
        make_run_result(
            5,
            outcome=ExecutionOutcome.VALIDATION_ERROR,
            error_message="Validation Error",
        )
    )
    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is True
    assert len(reasons) == 1
    assert "validation_error" in reasons[0]


@pytest.mark.parametrize("error_run_index", [1, 5])
def test_evaluate_gate_unaffected_by_result_order(error_run_index):
    """
    検証内容: 失敗(対応不要)の発生位置(1回目か5回目か)に関わらず不合格(False)になり、正しい発生回数が理由に残ること。
    振る舞い検証: 途中で早期returnしたり、最後の実行結果で上書きしたりするバグを防ぎ、発生位置を正確に記録できるかを検証する。
    """
    results = []
    for i in range(1, 6):
        if i == error_run_index:
            results.append(make_run_result(i, actual_status=Status.NOT_NEEDED))
        else:
            results.append(make_run_result(i, actual_status=Status.NEED_ACTION))

    is_passed, reasons = evaluate_gate(Status.NEED_ACTION, results)
    assert is_passed is False
    # エラーが発生した回数がメッセージに正しく含まれること
    assert len(reasons) == 1
    assert f"Run {error_run_index}" in reasons[0]


# === 概念一致マッチャのテスト ===


@pytest.mark.parametrize(
    ("expected_keys", "actual_keys"),
    [
        # 1. 導入有無(installed) - 双方向
        (["installed"], ["valkey_installed"]),
        (["installed"], ["httpd_installed"]),
        (["installed"], ["nginx_installed"]),
        (["installed"], ["openssh_installed"]),
        (["installed"], ["samba_installed"]),
        (["samba_installed"], ["installed"]),
        # 2. suexec (suexec_enabled) - 双方向
        (["suexec_enabled"], ["mod_suexec_enabled"]),
        (["mod_suexec_enabled"], ["suexec_enabled"]),
        # 3. SSI (ssi_enabled) - 双方向
        (["ssi_enabled"], ["mod_ssi_enabled"]),
        (["ssi_enabled"], ["mod_include_enabled"]),
        (["mod_ssi_enabled"], ["ssi_enabled"]),
        # 4. 複合ケース(CVE-2026-3238相当: 一部のみ表記揺れするパターン)
        (
            ["samba_installed", "check_password_script_u_substitution"],
            ["installed", "check_password_script_u_substitution"],
        ),
    ],
)
def test_calculate_key_coverage_rate_concept_match(
    expected_keys: list[str], actual_keys: list[str]
):
    """
    検証内容: 3概念(installed / suexec / SSI)の接頭辞・モジュール名の表記揺れが双方向で一致し、網羅率が1.0になること。
    振る舞い検証: 正解側・LLM出力側のどちらに揺れがあっても同一概念として吸収し、正当な指摘を取りこぼさないことを保証する。
    """
    results = make_5_run_results(actual_keys)
    assert calculate_key_coverage_rate(expected_keys, results) == pytest.approx(1.0)


@pytest.mark.parametrize(
    ("expected_keys", "actual_keys", "expected_rate"),
    [
        # mod_cgi_enabled と mod_cgid_enabled は別概念のまま維持する(case_007 / 008)
        (["mod_cgi_enabled"], ["mod_cgid_enabled"], 0.0),
        (["mod_cgid_enabled"], ["mod_cgi_enabled"], 0.0),
        # case_003形式: 片方だけ出力した場合は1.0ではなく0.5になること(水増し防止)
        (["mod_cgi_enabled", "mod_cgid_enabled"], ["mod_cgi_enabled"], 0.5),
        (["mod_cgi_enabled", "mod_cgid_enabled"], ["mod_cgid_enabled"], 0.5),
        # 反対語・類似名・スコープ外キーに誤爆しないこと
        (["installed"], ["not_installed"], 0.0),
        (["installed"], ["httpd_version"], 0.0),
        (["suexec_enabled"], ["sudo_enabled"], 0.0),
        (["ssi_enabled"], ["ssl_enabled"], 0.0),
    ],
)
def test_calculate_key_coverage_rate_does_not_match_different_concepts(
    expected_keys: list[str], actual_keys: list[str], expected_rate: float
):
    """
    検証内容: 別概念のキー(特に mod_cgi_enabled と mod_cgid_enabled)では同一視されず、期待通りの網羅率(0.0や0.5)になること。
    振る舞い検証: 列挙型辞書に登録されていない別概念や反対語を誤って同一視しないこと、および将来誤って cgi/cgid が統合された際に検知できることを保証する。
    """
    results = make_5_run_results(actual_keys)
    assert calculate_key_coverage_rate(expected_keys, results) == pytest.approx(
        expected_rate
    )


def test_calculate_key_coverage_rate_no_double_count_on_synonyms():
    """
    検証内容: LLMが同一概念の同義語を複数同時に出力した場合でも、重複カウントされず網羅率が1.0になること。
    振る舞い検証: 正規化後に集合(set)で積集合を取ることで、同義語の同時出力による網羅率の水増し(1.0超え)を防ぐ。
    """
    results = make_5_run_results(["installed", "samba_installed"])
    assert calculate_key_coverage_rate(["installed"], results) == pytest.approx(1.0)


def test_cases_yaml_expected_keys_do_not_merge_after_normalization():
    """
    検証内容: evals/cases.yaml の全ケースにおいて、正規化の前後で正解不足キーの要素数が変わらないこと。
    振る舞い検証: 同一ケース内に定義された異なる正解キー同士が、概念正規化によって誤って1つに合流し分母が減るバグがないことを保証する。
    """
    from pathlib import Path

    import yaml

    cases_path = Path(__file__).resolve().parent.parent / "evals" / "cases.yaml"
    assert cases_path.exists(), f"cases.yaml が見つかりません: {cases_path}"

    cases = yaml.safe_load(cases_path.read_text(encoding="utf-8"))
    for case in cases:
        keys = case.get("expected", {}).get("missing_config_keys") or case.get(
            "missing_config_keys", []
        )
        normalized_keys = {normalize_key(k) for k in keys}
        assert len(normalized_keys) == len(set(keys)), (
            f"{case.get('id')}: 正規化により正解キーが合流しました ({keys} -> {normalized_keys})"
        )
