from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from src.cases import EvalCase, load_and_validate_cases
from src.triage import Status

VALID_CASE_DATA = {
    "id": "case_001",
    "cell": 1,
    "cve_id": "CVE-2025-12345",
    "description": "テスト用ケース",
    "profile_path": "stack-profile.yaml",
    "alas_path": "ALAS2023-2026-3091.txt",
    "expected": {
        "status": "対応不要",
        "missing_config_keys": [],
    },
}


def test_valid_case_passes():
    """検証内容: 正常なケースデータがエラーなくロードされ、正しい型として認識されること(正常系)"""
    case = EvalCase(**VALID_CASE_DATA)
    assert case.id == "case_001"
    assert case.cell == 1
    assert case.cve_id == "CVE-2025-12345"
    assert case.expected.status == Status.NOT_NEEDED


def test_missing_required_keys():
    """検証内容: cve_idやexpected.statusなどの必須キーが存在しない場合、必須キー欠落のエラー(ValidationError)になること"""
    data = VALID_CASE_DATA.copy()
    data.pop("cve_id")
    with pytest.raises(ValidationError):
        EvalCase(**data)


def test_forbid_extra_keys():
    """検証内容: スキーマにない未知のキーが含まれている場合、extra="forbid"による例外エラーになること"""
    data = {**VALID_CASE_DATA, "unknown_field": "invalid"}
    with pytest.raises(ValidationError):
        EvalCase(**data)


def test_invalid_status_value():
    """検証内容: statusに不正な文字列(例: "要確認"ではなく"要チェック"などの誤字)が指定された場合、値の不整合エラーになること"""
    data = VALID_CASE_DATA.copy()
    data["expected"] = {"status": "要チェック", "missing_config_keys": []}
    with pytest.raises(ValidationError):
        EvalCase(**data)


def test_out_of_range_cell():
    """検証内容: cellに7や0など(範囲外: 1-6以外)が指定された場合、範囲外エラーになること"""
    data = {**VALID_CASE_DATA, "cell": 7}
    with pytest.raises(ValidationError):
        EvalCase(**data)


def test_status_needs_check_requires_missing_config_keys():
    """検証内容: statusが"要確認"なのにmissing_config_keysが空(またはNone/欠落)の場合、「要確認にはmissing_config_keysが必須」という理由でエラーになること"""
    data = {
        **VALID_CASE_DATA,
        "expected": {"status": "要確認", "missing_config_keys": []},
    }
    with pytest.raises(ValidationError, match="missing_config_keysは必須です"):
        EvalCase(**data)


def test_real_cases_yaml_is_valid():
    """検証内容: 本物の evals/cases.yaml がエラーなく全件ロードでき、書き間違いが無いこと"""
    cases = load_and_validate_cases(Path("evals/cases.yaml"))
    assert len(cases) == 4


def test_invalid_cve_id_not_in_alas(tmp_path):
    """検証内容: cve_idが対象のALAS内に存在しない値の場合、「ALASに含まれない」旨のエラーになること"""
    # ダミーの ALAS ファイルを用意
    alas_file = tmp_path / "dummy_alas.txt"
    alas_file.write_text("ALAS content without that cve", encoding="utf-8")

    case_file = tmp_path / "dummy_cases.yaml"
    case_file.write_text(
        yaml.dump(
            [
                {
                    "id": "case_999",
                    "cell": 1,
                    "cve_id": "CVE-9999-99999",
                    "description": "テストケース",
                    "profile_path": "stack-profile.yaml",
                    "alas_path": alas_file.name,
                    "expected": {"status": "対応不要", "missing_config_keys": []},
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ALAS.*内に存在しません"):
        load_and_validate_cases(case_file, base_dir=tmp_path)


def test_duplicate_ids_detected(tmp_path):
    """検証内容: ケースリストの中に同じidが重複して存在する場合、重複エラー(ID上書き防止)になること"""
    # ケースが参照する ALAS ファイルを用意
    alas_file = tmp_path / VALID_CASE_DATA["alas_path"]
    alas_file.write_text("CVE-2025-12345", encoding="utf-8")

    case_file = tmp_path / "dummy_cases.yaml"
    duplicate_data = [
        VALID_CASE_DATA,
        VALID_CASE_DATA,
    ]
    case_file.write_text(yaml.dump(duplicate_data), encoding="utf-8")

    with pytest.raises(ValueError, match="IDが重複しています"):
        load_and_validate_cases(case_file, base_dir=tmp_path)


def test_alas_file_not_found(tmp_path):
    """検証内容: 指定されたalas_pathのファイルが存在しない場合、FileNotFoundErrorが発生すること"""
    case_file = tmp_path / "dummy_cases.yaml"
    case_file.write_text(
        yaml.dump(
            [
                {
                    "id": "case_999",
                    "cell": 1,
                    "cve_id": "CVE-2025-12345",
                    "description": "テストケース",
                    "profile_path": "stack-profile.yaml",
                    "alas_path": "non_existent_alas.txt",
                    "expected": {"status": "対応不要", "missing_config_keys": []},
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        FileNotFoundError, match="指定されたALASファイルが見つかりません"
    ):
        load_and_validate_cases(case_file, base_dir=tmp_path)
