import pytest
from pydantic import ValidationError

from src.triage import CVEResult, Status, UrgencyLevel


def test_need_check_with_empty_keys_raises_error():
    """要確認 なのに missing_config_keys が空の場合は拒否"""
    with pytest.raises(ValidationError) as exc_info:
        CVEResult(
            cve_id="CVE-2025-0001",
            status=Status.NEED_CHECK,
            reason="情報不足",
            missing_config_keys=[],
        )
    assert "statusが'要確認'の場合" in str(exc_info.value)


def test_not_needed_with_keys_raises_error():
    """対応不要 なのに missing_config_keys が存在する場合は拒否"""
    with pytest.raises(ValidationError) as exc_info:
        CVEResult(
            cve_id="CVE-2025-0002",
            status=Status.NOT_NEEDED,
            reason="影響なし",
            missing_config_keys=["dummy_key"],
        )
    assert "missing_config_keysは空リスト [] である必要があります" in str(
        exc_info.value
    )


def test_need_action_with_keys_raises_error():
    """要対応 なのに missing_config_keys が存在する場合は拒否"""
    with pytest.raises(ValidationError) as exc_info:
        CVEResult(
            cve_id="CVE-2025-0003",
            status=Status.NEED_ACTION,
            urgency_level=UrgencyLevel.HIGH,
            reason="要対応",
            missing_config_keys=["dummy_key"],
        )
    assert "missing_config_keysは空リスト [] である必要があります" in str(
        exc_info.value
    )
