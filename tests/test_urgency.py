import pytest
from pydantic import ValidationError

from src.triage import CVEResult


@pytest.mark.parametrize(
    "status, urgency_level, is_valid",
    [
        ("要対応", "Critical", True),
        ("要対応", None, False),
        ("要確認", None, True),
        ("要確認", "Critical", False),
        ("対応不要", None, True),
        ("対応不要", "Critical", False),
    ],
)
def test_urgency_level_validation(status, urgency_level, is_valid):
    # 要確認の場合はキーが必須、それ以外は空配列
    missing_keys = ["mod_cgi_enabled"] if status == "要確認" else []

    data = {
        "cve_id": "CVE-2025-00000",
        "status": status,
        "urgency_level": urgency_level,
        "reason": "test reason",
        "missing_config_keys": missing_keys,
    }
    if is_valid:
        result = CVEResult(**data)
        assert result.status == status
    else:
        with pytest.raises(ValidationError):
            CVEResult(**data)
