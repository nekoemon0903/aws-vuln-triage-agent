"""評価対象ケースの絞り込みロジック、CLI引数パース、およびmain実行配線を検証するテスト"""

from unittest.mock import MagicMock

import pytest

# 実装予定の関数をインポート(未実装のためImportError / REDになる)
from src.runner import filter_cases, main, parse_args


# テスト用の簡易ケース生成ヘルパー
def _make_dummy_case(case_id: str, status: str):
    case = MagicMock()
    case.id = case_id
    case.expected.status = status
    return case


@pytest.fixture
def dummy_cases():
    """要対応・要確認・対応不要の3種を含めたテストデータ"""
    return [
        _make_dummy_case("case_001", "要対応"),
        _make_dummy_case("case_002", "要確認"),
        _make_dummy_case("case_003", "対応不要"),
        _make_dummy_case("case_004", "対応不要"),
    ]


# =====================================================================
# 1. フィルター単体テスト (filter_cases)
# =====================================================================


def test_filter_cases_returns_all_when_no_options_specified(dummy_cases):
    """オプション未指定(case_ids=None, gate=False)の場合、全件を元の順序で返す"""
    result = filter_cases(dummy_cases, case_ids=None, gate=False)
    assert [c.id for c in result] == [
        "case_001",
        "case_002",
        "case_003",
        "case_004",
    ]


def test_filter_cases_by_specific_case_ids(dummy_cases):
    """--case-idで指定したケースのみが抽出される"""
    result = filter_cases(dummy_cases, case_ids=["case_002", "case_004"])
    assert [c.id for c in result] == ["case_002", "case_004"]


def test_filter_cases_by_gate_selects_expected_status_not_equal_to_not_needed(
    dummy_cases,
):
    """
    --gate指定時、expected.statusが「対応不要」以外のケース(要対応・要確認)が全て抽出される
    セルの定義については[README 6.1](../evals/README.md)参照
    """
    result = filter_cases(dummy_cases, gate=True)
    # case_001(要対応)とcase_002(要確認)の両方が拾われること
    assert [c.id for c in result] == ["case_001", "case_002"]


def test_filter_cases_combines_case_ids_and_gate_as_union_preserving_order(dummy_cases):
    """--case-idと--gateの併用時、和集合(重複排除)が元のリストの順序を保持して抽出される"""
    # case_004(対応不要)とgate(case_001, case_002)を指定
    result = filter_cases(dummy_cases, case_ids=["case_004", "case_001"], gate=True)
    # 順序は元リストの順(case_001 -> case_002 -> case_004)、重複なし
    assert [c.id for c in result] == ["case_001", "case_002", "case_004"]


def test_filter_cases_raises_error_when_specified_id_not_found(dummy_cases):
    """指定されたケースIDの一部または全部が存在しない場合は即座にValueErrorを送出する"""
    # case_001は存在するがcase_000は存在しない
    with pytest.raises(
        ValueError, match="指定されたケースIDが見つかりません:.*case_000"
    ):
        filter_cases(dummy_cases, case_ids=["case_001", "case_000"])


# =====================================================================
# 2. CLI引数パース単体テスト (parse_args)
# =====================================================================


def test_parse_args_defaults():
    """引数なしの場合、case_idsはNone、gateはFalseになる"""
    args = parse_args([])
    assert args.case_ids is None
    assert args.gate is False


def test_parse_args_with_case_ids():
    """--case-idで複数のIDを指定できる"""
    args = parse_args(["--case-id", "case_001", "case_002"])
    assert args.case_ids == ["case_001", "case_002"]


def test_parse_args_with_gate_flag():
    """--gateフラグを指定するとTrueになる"""
    args = parse_args(["--gate"])
    assert args.gate is True


# =====================================================================
# 3. main 結合配線テスト (引数 -> パース -> フィルター -> 実行)
# =====================================================================


def test_main_runs_all_cases_by_default(monkeypatch, tmp_path):
    """引数なし実行時、全件が正しく絞り込みを通過し、実行エンジン(run_eval)で処理される"""
    monkeypatch.chdir(tmp_path)  # evals/resultsにゴミを残さないように隔離

    mock_cases = [
        _make_dummy_case("case_001", "要対応"),
        _make_dummy_case("case_002", "対応不要"),
    ]
    monkeypatch.setattr(
        "src.runner.load_and_validate_cases", lambda *a, **kw: mock_cases
    )
    monkeypatch.setattr("anthropic.Anthropic", MagicMock())

    # 実行されたケースIDを記録するスパイ(モック)関数
    executed_case_ids = []

    def spy_adapter(case):
        executed_case_ids.append(case.id)
        return {"status": "SUCCESS"}

    monkeypatch.setattr(
        "src.runner.create_triage_adapter", lambda *a, **kw: spy_adapter
    )

    # 実行
    main(argv=[])

    # repeat_count=5により複数回呼ばれるため、setで一意なIDを比較
    assert set(executed_case_ids) == {"case_001", "case_002"}


def test_main_wires_cli_args_through_filter_to_run_eval(monkeypatch, tmp_path):
    """CLI引数の指定(--case-idと--gate)がfilterを経由して、和集合のケースだけが実際に実行(run_eval)される"""
    monkeypatch.chdir(tmp_path)

    mock_cases = [
        _make_dummy_case("case_001", "要対応"),  # gate対象
        _make_dummy_case("case_002", "要確認"),  # gate対象
        _make_dummy_case("case_003", "対応不要"),  # gate対象外
    ]
    monkeypatch.setattr(
        "src.runner.load_and_validate_cases", lambda *a, **kw: mock_cases
    )
    monkeypatch.setattr("anthropic.Anthropic", MagicMock())

    executed_case_ids = []

    def spy_adapter(case):
        executed_case_ids.append(case.id)
        return {"status": "SUCCESS"}

    monkeypatch.setattr(
        "src.runner.create_triage_adapter", lambda *a, **kw: spy_adapter
    )

    # case_003(対応不要)と--gateを指定
    main(argv=["--case-id", "case_003", "--gate"])

    # gate(case_001, case_002)+指定(case_003)の全3件が実際に実行されたことを確認
    assert set(executed_case_ids) == {"case_001", "case_002", "case_003"}
