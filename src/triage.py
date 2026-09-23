import argparse
import sys
from enum import Enum
from pathlib import Path

import yaml
from anthropic import Anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field, model_validator

# .envファイルから環境変数を読み込む
load_dotenv()

# === スキーマ・定数定義 ===

# LLMに渡すことを許可する Profile のパス定義 (Single Source of Truth)
ALLOWED_PROFILE_PATHS = [
    "inventory",
    "components.*.current_configurations",
]

# 定義からトップレベルの許可キー集合を自動導出 (二重管理を解消)
ALLOWED_TOP_LEVEL_KEYS = {p.split(".")[0] for p in ALLOWED_PROFILE_PATHS}

KNOWN_IGNORED_PROFILE_KEYS = {
    "owner",
    "usage_context",
    "criticality",
    "operational_constraints",
}

# === スキーマ定義 ===


class Status(str, Enum):
    NEED_ACTION = "要対応"
    NEED_CHECK = "要確認"
    NOT_NEEDED = "対応不要"


class CVEResult(BaseModel):
    cve_id: str = Field(description="pureなCVE番号(例: CVE-2025-1318)")
    status: Status = Field(description="トリアージステータス")
    reason: str = Field(
        description="構成情報と発動条件を照らし合わせた判定根拠。missing_config_keysに挙げた項目が必要な理由も含める"
    )
    missing_config_keys: list[str] = Field(
        default_factory=list,
        description=(
            "statusが'要確認'の場合に、判定確定に必要な不足構成項目名を全て挙げたリスト。"
            "システム構成情報のキーとしてそのまま使えるsnake_case表記で出力すること(例: ['mod_cgi_enabled', 'allow_override_fileinfo'])。"
            "statusが'要対応'または'対応不要'の場合は空配列 [] とすること。"
        ),
    )

    @model_validator(mode="after")
    def validate_status_and_missing_keys(self) -> "CVEResult":
        has_keys = len(self.missing_config_keys) > 0

        # パターン1: 要確認なのにキーが空[]
        if self.status == Status.NEED_CHECK and not has_keys:
            raise ValueError(
                "statusが'要確認'の場合、missing_config_keysに不足キーを1つ以上指定する必要があります。"
            )

        # パターン2・3: 対応不要 / 要対応 なのにキーが入っている
        if self.status in {Status.NEED_ACTION, Status.NOT_NEEDED} and has_keys:
            raise ValueError(
                f"statusが'{self.status.value}'の場合、missing_config_keysは空リスト [] である必要があります。"
            )

        return self


class LLMTriageOutput(BaseModel):
    """LLMからの直接レスポンス構造(overall_triage_resultは含めない)"""

    notes: str = Field(
        description="提示されたシステム構成情報や技術的事実に関する補足・注意事項"
    )
    cve_results: list[CVEResult]


class FinalTriageReport(BaseModel):
    """コード側でoverall_triage_resultを付与した最終レポート構造"""

    overall_triage_result: Status
    notes: str
    cve_results: list[CVEResult]


# === プロンプト生成 ===


def generate_prompt(stack_profile_path: Path, alas_text_path: Path) -> str:
    with open(stack_profile_path, "r", encoding="utf-8") as f:
        raw_profile_str = f.read()

    # ホワイトリスト抽出へ置き換え
    stack_profile = extract_facts_profile(raw_profile_str)

    with open(alas_text_path, "r", encoding="utf-8") as f:
        alas_text = f.read()

    prompt = f"""あなたはセキュリティ運用の専門家です。
    以下の「システム構成情報」と「脆弱性情報(ALAS)」を突き合わせ、CVE単位でのトリアージ判定を行ってください。

    【システム構成情報】
    {stack_profile}

    【脆弱性情報(ALAS)】
    {alas_text}

    【判定ルール】
    1. 脆弱性の発動条件と構成情報を照らし合わせ、CVE単位で判定してください。
    2. cve_idフィールドにはpureなCVE番号(例: CVE-2025-66200)のみを入れ、注釈や補足テキストは一切含めないでください。
    3. 必要条件(対象バージョンやモジュール)が合致していても、追加の発動条件(設定やサブモジュール)の有無が構成情報から読み取れない場合は「要確認」を選択してください。
    4. 「要確認」を選択できるのは、システム構成情報に不足している項目名を具体的に特定できる場合のみです。特定できない場合は既存情報のみで「要対応」または「対応不要」と判定してください。
    """
    return prompt


# === ステータス集計ロジック ===


def derive_overall_status(cve_results: list[CVEResult]) -> Status:
    """cve_resultsのステータス集合からoverall_triage_resultを計算

    優先度: 要対応 > 要確認 > 対応不要
    """
    statuses = {item.status for item in cve_results}
    if Status.NEED_ACTION in statuses:
        return Status.NEED_ACTION
    if Status.NEED_CHECK in statuses:
        return Status.NEED_CHECK
    return Status.NOT_NEEDED


# === CLI引数パース ===


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run security triage for given profile."
    )
    parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="Path to the stack profile YAML file (Required).",
    )
    parser.add_argument(
        "--alas",
        required=True,
        type=Path,
        help="Path to the ALAS text file (Required).",
    )
    return parser.parse_args()


# === ホワイトリスト抽出 ===


def extract_facts_profile(raw_yaml_str: str) -> str:
    """ProfileのYAML文字列から ALLOWED_PROFILE_PATHS に定義された情報のみを動的に抽出し、
    未知のキーが存在した場合は [WARN] を stderr に出力する。
    """
    data = yaml.safe_load(raw_yaml_str) or {}
    if not isinstance(data, dict):
        return yaml.safe_dump({}, allow_unicode=True)

    # 1. トップレベルの未知キーチェック
    top_level_keys = set(data.keys())
    expected_top_keys = ALLOWED_TOP_LEVEL_KEYS | KNOWN_IGNORED_PROFILE_KEYS
    unknown_top_keys = top_level_keys - expected_top_keys
    if unknown_top_keys:
        print(
            f"[WARN] Profileに未定義の未知のキーが含まれています: {unknown_top_keys}",
            file=sys.stderr,
        )

    # 2. パス定義(ALLOWED_PROFILE_PATHS)に基づく動的抽出処理
    filtered_data = {}

    for path in ALLOWED_PROFILE_PATHS:
        parts = path.split(".")

        # パターンA: 1段のパス (例: "inventory")
        if len(parts) == 1:
            key = parts[0]
            if key in data:
                filtered_data[key] = data[key]
            continue

        # パターンB: 3段・ワイルドカード挟み (例: "components.*.current_configurations")
        if len(parts) == 3 and parts[1] == "*":
            top_key, _, target_subkey = parts
            components_data = data.get(top_key)
            if not isinstance(components_data, dict):
                continue

            filtered_sub = {}
            for comp_name, comp_val in components_data.items():
                if not isinstance(comp_val, dict):
                    continue

                # ワイルドカード階層配下の未知キー検証
                comp_subkeys = set(comp_val.keys())
                expected_subkeys = {target_subkey} | KNOWN_IGNORED_PROFILE_KEYS
                unknown_subkeys = comp_subkeys - expected_subkeys
                if unknown_subkeys:
                    print(
                        f"[WARN] {top_key}.{comp_name} に未定義のキーが含まれています: {unknown_subkeys}",
                        file=sys.stderr,
                    )

                # 対象キーの抽出
                if target_subkey in comp_val:
                    filtered_sub[comp_name] = {target_subkey: comp_val[target_subkey]}

            if filtered_sub:
                filtered_data[top_key] = filtered_sub

    # 再シリアライズ
    return yaml.safe_dump(filtered_data, allow_unicode=True, sort_keys=False)


# === メイン処理 ===


def main():
    args = parse_args()

    errors = []

    if not args.profile.exists():
        errors.append(f"プロファイルファイルが見つかりません: {args.profile}")

    if not args.alas.exists():
        errors.append(f"ALASファイルが見つかりません: {args.alas}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Using profile: {args.profile}")
    print(f"[INFO] Using ALAS file: {args.alas}")

    prompt = generate_prompt(args.profile, args.alas)

    print("LLM APIを呼び出しています (client.messages.parse)...")
    client = Anthropic()

    try:
        # Structured Outputs (client.messages.parse)を使用
        response = client.messages.parse(
            model="claude-sonnet-5",
            max_tokens=16000,
            messages=[{"role": "user", "content": prompt}],
            output_format=LLMTriageOutput,
        )

        # 型保証された Pydantic オブジェクトを取得
        llm_output: LLMTriageOutput = response.parsed_output

        # overall_triage_result をコード側で集計計算
        overall_status = derive_overall_status(llm_output.cve_results)

        # 最終レポートの作成
        final_report = FinalTriageReport(
            overall_triage_result=overall_status,
            notes=llm_output.notes,
            cve_results=llm_output.cve_results,
        )

        print("=== パース・検証済みトリアージ結果 ===")
        print(final_report.model_dump_json(indent=2))

    # リトライ未実装のため ValidationError も握り潰される(2026-09-02時点)
    except Exception as e:  # noqa: BLE001
        print(f"エラーが発生しました: {e}")


if __name__ == "__main__":
    main()
