import yaml

from src.triage import extract_facts_profile


def test_extract_facts_profile_filters_unwanted_keys_and_components():
    dummy_yaml = """
    # このコメントは除去されるべき
    owner: sec-ops-team
    inventory:
      os: Amazon Linux 2023
      packages:
        httpd: 2.4.65

    components:
      httpd:
        owner: web-support@xxxinc.jp
        usage_context: "顧客向けポータルサイトをホストし、事業継続に不可欠な本番環境"
        criticality: low
        current_configurations:
          ssi_enabled: true
          mod_cgid_enabled: true
          mod_cgi_enabled: false
          mod_userdir_enabled: false
          suexec_enabled: false
        operational_constraints:
          - "Do not touch"
    """

    filtered_yaml_str = extract_facts_profile(dummy_yaml)
    parsed = yaml.safe_load(filtered_yaml_str)

    # 1. 必要な情報が残っていること
    assert "inventory" in parsed
    assert parsed["inventory"]["os"] == "Amazon Linux 2023"
    assert (
        parsed["components"]["httpd"]["current_configurations"]["mod_cgi_enabled"]
        is False
    )

    # 2. 除外キーが含まれないこと
    assert "owner" not in parsed
    assert "usage_context" not in parsed
    assert "criticality" not in parsed
    assert "operational_constraints" not in parsed

    # 3. プロンプト文字列中にコメントや除外キーの値が存在しないこと
    assert "sec-ops-team" not in filtered_yaml_str
    assert "Do not touch" not in filtered_yaml_str
    assert "# このコメントは除去されるべき" not in filtered_yaml_str
