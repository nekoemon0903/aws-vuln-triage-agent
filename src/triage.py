import os
from enum import Enum
from typing import List, Optional
from anthropic import Anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# .envファイルから環境変数を読み込む
load_dotenv()

# === 1. スキーマ定義 ===

class Status(str, Enum):
    NEED_ACTION = "要対応"
    NEED_CHECK = "要確認"
    NOT_NEEDED = "対応不要"

class UrgencyLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"

class CVEResult(BaseModel):
    cve_id: str = Field(description="pureなCVE番号(例: CVE-2025-1318)")
    status: Status = Field(description="トリアージステータス")
    urgency_level: Optional[UrgencyLevel] = Field(
        default=None,
        description="statusが'要対応'の場合のみ設定(Critical/High/Medium)。要確認・対応不要の場合はnull",
    )
    reason: str = Field(description="【最優先】構成情報と発動条件を照らし合わせた判定根拠")

class LLMOutputSummary(BaseModel):
    notes: str = Field(description="運用上の制約や人間による確認が必要な事項(例: SGの確認)")

class LLMTriageOutput(BaseModel):
    """LLMからの直接レスポンス構造(overall_triage_resultは含めない)"""
    summary: LLMOutputSummary
    cve_results: List[CVEResult]

class FinalTriageReport(BaseModel):
    """コード側でoverall_triage_resultを付与した最終レポート構造"""
    overall_triage_result: Status
    notes: str
    cve_results: List[CVEResult]


# === 2. プロンプト生成 ===

def generate_prompt(stack_profile_path: str, alas_text_path: str) -> str:
    with open(stack_profile_path, 'r', encoding='utf-8') as f:
        stack_profile = f.read()
    with open(alas_text_path, 'r', encoding='utf-8') as f:
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
    4. **【厳格制約】「要確認」を選択できるのは、stack-profile.yamlに不足している具体的な構成項目名(例: mod_cgiなど、キー候補となりうる名称)を理由内に特定して明示できる場合のみです。具体的な項目名を特定できない場合は必ず「要確認」を選ばず、既存情報のみで「要対応」または「対応不要」に決定してください。**
    5. urgency_levelはstatusが「要対応」の場合のみ設定し、「要確認」「対応不要」の場合は null としてください。
       判定は「攻撃の容易さ(認証有無・アクセス経路)」と「影響範囲」を軸に行います。
       - Critical: 外部/ネットワーク経由で未認証攻撃が可能、かつシステム全体に壊滅的影響を与える（例: 認証不要のRCE）
       - High: 攻撃に認証や内部アクセスを要するが、権限昇格や大規模なサービス停止・データ奪取につながる(例: Privilege Escalation)
       - Medium: 攻撃に特殊なローカル条件や前提が必要で、影響範囲が局所的・限定的(例: 局所的な情報漏洩、条件付きDoS)
    """
    return prompt


# === 3. コード側でのステータス畳み込みロジック ===

def derive_overall_status(cve_results: List[CVEResult]) -> Status:
    """cve_resultsのステータス集合からoverall_triage_resultを計算
    
    優先度: 要対応 > 要確認 > 対応不要
    """
    statuses = {item.status for item in cve_results}
    if Status.NEED_ACTION in statuses:
        return Status.NEED_ACTION
    if Status.NEED_CHECK in statuses:
        return Status.NEED_CHECK
    return Status.NOT_NEEDED


# === 4. メイン処理 ===

def main():
    stack_yaml_path = "stack-profile.yaml"
    alas_text_path = "ALAS2023-2025-1318.txt"

    if not os.path.exists(stack_yaml_path) or not os.path.exists(alas_text_path):
        print(f"エラー: 入力ファイルが見つかりません ({stack_yaml_path} または {alas_text_path})")
        return

    prompt = generate_prompt(stack_yaml_path, alas_text_path)

    print("LLM APIを呼び出しています (client.messages.parse)...")
    client = Anthropic()

    try:
        # Structured Outputs (client.messages.parse)を使用
        response = client.messages.parse(
            model="claude-sonnet-5",
            max_tokens=16000,
            messages=[
                {"role": "user", "content": prompt}
            ],
            output_format=LLMTriageOutput,
        )

        # 型保証された Pydantic オブジェクトを取得
        llm_output: LLMTriageOutput = response.parsed_output

        # overall_triage_result をコード側で集計計算
        overall_status = derive_overall_status(llm_output.cve_results)

        # 最終レポートの作成
        final_report = FinalTriageReport(
            overall_triage_result=overall_status,
            notes=llm_output.summary.notes,
            cve_results=llm_output.cve_results,
        )

        print("=== パース・検証済みトリアージ結果 ===")
        print(final_report.model_dump_json(indent=2))

    except Exception as e:
        print(f"エラーが発生しました: {e}")



if __name__ == "__main__":
    main()