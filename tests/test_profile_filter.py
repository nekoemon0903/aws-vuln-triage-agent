from pathlib import Path

import pytest
import yaml

from src.triage import (
    ALLOWED_TOP_LEVEL_KEYS,
    extract_facts_profile,
)


def test_extract_facts_profile_filters_unwanted_keys_and_components():
    """正常系プロファイルからのフィルタリング処理の検証"""
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


def test_extract_facts_profile_inventory_passthrough():
    """inventory キー配下がそのまま透過的に保持されること"""
    yaml_input = """
    inventory:
      os: "Amazon Linux 2023"
      arch: "x86_64"
    """
    result = extract_facts_profile(yaml_input)
    parsed = yaml.safe_load(result)
    assert parsed == {"inventory": {"os": "Amazon Linux 2023", "arch": "x86_64"}}


def test_extract_facts_profile_components_wildcard_and_warn(capsys):
    """components.* 配下で current_configurations のみを抽出し、未定義キーは WARN(stderr)"""
    yaml_input = """
    components:
      web01:
        current_configurations:
          mod_cgi_enabled: true
        unexpected_extra_key: "警告対象の値"
    """
    result = extract_facts_profile(yaml_input)
    parsed = yaml.safe_load(result)
    captured = capsys.readouterr()

    # 抽出結果の検証
    assert parsed["components"]["web01"] == {
        "current_configurations": {"mod_cgi_enabled": True}
    }
    assert "unexpected_extra_key" not in result

    # stderr への WARN 出力検証
    assert "[WARN] components.web01 に未定義のキーが含まれています" in captured.err
    assert "unexpected_extra_key" in captured.err


def test_extract_facts_profile_path_driven_top_level_warn(capsys):
    """パス定義からの動的導出とトップレベル未知キーの WARN(stderr) 検知"""
    # ALLOWED_TOP_LEVEL_KEYS が ALLOWED_PROFILE_PATHS から自動導出されていることを検証
    assert "inventory" in ALLOWED_TOP_LEVEL_KEYS
    assert "components" in ALLOWED_TOP_LEVEL_KEYS

    yaml_input = """
    unknown_top_level_section:
      some_key: "value"
    """
    result = extract_facts_profile(yaml_input)
    captured = capsys.readouterr()

    assert "unknown_top_level_section" not in result
    assert "[WARN] Profileに未定義の未知のキーが含まれています" in captured.err
    assert "unknown_top_level_section" in captured.err


def test_extract_facts_profile_edge_cases():
    """抽出結果が全滅する場合、ValueErrorを送出すること"""
    yaml_input = """
    inventory:
      os: "Amazon Linux 2023"
    components:
      valkey:
        other_unrelated_key: "value"
    """
    with pytest.raises(ValueError):
        extract_facts_profile(yaml_input)


@pytest.mark.parametrize(
    "invalid_input",
    [
        "just a scalar string",
        "- item1\n- item2",  # リスト構造
        "12345",
        "true",
    ],
)
def test_extract_facts_profile_non_dict_input(invalid_input):
    """isinstance(data, dict)を満たさない入力の場合、例外を出さず空データ({})を返すこと"""
    result = extract_facts_profile(invalid_input)
    parsed = yaml.safe_load(result)
    assert parsed == {}


def test_extract_facts_profile_missing_current_configurations_warn(capsys):
    """current_configurationsを持たないコンポーネントがあればWARNを出力し、正常なコンポーネントは残る"""
    yaml_input = """
    components:
      httpd:
        current_configurations:
          mod_cgi_enabled: true
      valkey:
        owner: "sec-ops-team"
        criticality: "high"
    """
    result = extract_facts_profile(yaml_input)
    parsed = yaml.safe_load(result)
    captured = capsys.readouterr()

    # httpdは残っていること
    assert "httpd" in parsed["components"]
    # stderrにvalkeyに対するWARNが出力されていること
    assert "[WARN]" in captured.err
    assert "valkey" in captured.err


@pytest.mark.parametrize(
    "empty_val",
    [
        "php: {}",  # 空辞書
        "php:",  # Noneにパースされるケース
    ],
)
def test_extract_facts_profile_empty_component_warn(empty_val, capsys):
    """コンポーネントの中身が{}やNoneの場合でもクラッシュせずWARNを出力する"""
    yaml_input = f"""
    components:
      httpd:
        current_configurations:
          mod_cgi_enabled: true
      {empty_val}
    """
    result = extract_facts_profile(yaml_input)
    parsed = yaml.safe_load(result)
    captured = capsys.readouterr()

    assert "httpd" in parsed["components"]
    assert "[WARN]" in captured.err
    assert "php" in captured.err


# --- current_configurations 誤記検出テスト ---


def test_extract_facts_profile_unknown_config_key_raises_error():
    """
    検証内容: 登録済みコンポーネントの current_configurations に誤記(未知のキー)が含まれる場合、
             LLMへのサイレントな通過を防ぐため ValueError を送出し、エラーにコンポーネント名とキー名が含まれること
    """
    yaml_input = """
    components:
      httpd:
        owner: "web-admin@example.com"
        current_configurations:
          installed: true
          mod_userdir_enable: true # 誤記(正: mod_userdir_enabled)
    """

    with pytest.raises(ValueError) as exc_info:
        extract_facts_profile(yaml_input)

    err_msg = str(exc_info.value)
    # コンポーネント名と誤記キー名の両方が含まれていることをアサート
    assert "httpd" in err_msg
    assert "mod_userdir_enable" in err_msg


def test_extract_facts_profile_valid_config_keys_passes():
    """
    検証内容: 登録済みコンポーネントの current_configurations が許可キーのみで構成されている場合、
             エラーなく正常に抽出・処理されること(正常系)
    """
    yaml_input = """
    components:
      httpd:
        current_configurations:
          installed: true
          ssi_enabled: true
          mod_cgi_enabled: false
      valkey:
        current_configurations:
          installed: true
          cluster_enabled: true
    """

    result = extract_facts_profile(yaml_input)
    assert result is not None
    assert "mod_cgi_enabled" in result
    assert "cluster_enabled" in result


def test_extract_facts_profile_unregistered_component_warns_and_passes(capsys):
    """
    検証内容: ALLOWED_CONFIG_KEYSに登録されていない未知のコンポーネントの場合、
             処理は中断せず通過するが、タイポ等に気づけるよう stderr に WARN を出力すること
    """
    yaml_input = """
    components:
      htttpd:  # 未登録・誤記コンポーネント名
        current_configurations:
          some_config: true
      valkey:
        current_configurations:
          installed: true
          cluster_enabled: true
    """

    result = extract_facts_profile(yaml_input)
    captured = capsys.readouterr()

    # 処理は中断せず valkey などの設定が抽出されること
    assert result is not None
    assert "cluster_enabled" in result

    # 警告が stderr に出力されていること(stdoutではなくstderrを厳密に検証)
    assert "[WARN]" in captured.err
    assert "htttpd" in captured.err


def test_all_real_profiles_are_valid():
    """
    検証内容: リポジトリ内の全ての実profile(stack-profile*.yaml)が一覧漏れ(誤検知)なく正常にバリデーションを通過すること
    """
    profile_files = list(Path(".").glob("**/stack-profile*.yaml"))
    assert len(profile_files) > 0, "実profileファイルが見つかりません"

    for profile_path in profile_files:
        content = profile_path.read_text(encoding="utf-8")
        # 既存profileでValueErrorが発生しないことを確認(誤検知の防止)
        extract_facts_profile(content)
