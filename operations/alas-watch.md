
# ALAS Watch 起点記録

> このディレクトリは公開対象。組織固有の情報（実環境の構成・ホスト名・担当者名）は書かない。
> 実行ログは `archive/` (Git管理外)に置く。

- [取得元URL](https://alas.aws.amazon.com/alas2023.html)
- **起点日のadvisory ID**: `ALAS2023-2026-3091`
- **運用ルール**: 起点日のIDより後に出たものを新着として扱う
- **監視対象**: **ALAS2023系** であり **LIVEPATCH系は対象外**

- **初弾の実行観測 (2026-09-21)**:
  - 起点 ID: `ALAS2023-2026-3091` (valkey 関連の 4 CVE)
  - Profile 識別子: `stack-profile.yaml (76abad90b67b)`
  - 判定結果: 全4件「要確認」（profile 未登録コンポーネントのため）
  - 参照 RUN: `2026-09-21 09:15:56` (Commit: `c2652c1`)
