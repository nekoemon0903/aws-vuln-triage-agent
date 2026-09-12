#!/usr/bin/env bash
set -euo pipefail

echo "=== トリアージ実行インタラクティブシェル ==="

# 1. Profile の入力
read -r -p "Profile パス [デフォルト: stack-profile.vulnerable.yaml]: " INPUT_PROFILE
PROFILE="${INPUT_PROFILE:-stack-profile.vulnerable.yaml}"

# 2. ALAS の入力
read -r -p "ALAS パス    [デフォルト: ALAS2023-2025-1318.txt]: " INPUT_ALAS
ALAS="${INPUT_ALAS:-ALAS2023-2025-1318.txt}"

# 3. 実行メモの入力
read -r -p "実行メモ     [デフォルト: （メモなし）]: " INPUT_MEMO
MEMO="${INPUT_MEMO:-（メモなし）}"

# 各種メタ情報の取得
GIT_STATUS="$(git rev-parse --short HEAD 2>/dev/null || echo 'not-a-repo')$(git diff --quiet 2>/dev/null || echo ' (dirty)')"
PROFILE_HASH="$(shasum -a 256 "$PROFILE" | cut -c1-12)"
ALAS_HASH="$(shasum -a 256 "$ALAS" | cut -c1-12)"

# archive ディレクトリの作成
mkdir -p archive

# 本日の日付を付けたログファイル名
LOG_FILE="archive/runs_$(date +%Y%m%d).log"

# ヘッダー情報とプロファイルスナップショットの出力・追記
{
  echo ""
  echo "========================================"
  echo "[RUN] $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  MEMO   : $MEMO"
  echo "  Commit : $GIT_STATUS"
  echo "  Profile: $PROFILE ($PROFILE_HASH)"
  echo "  ALAS   : $ALAS ($ALAS_HASH)"
  echo "----------------------------------------"
  echo "[SNAPSHOT: Profile Content]"
  cat "$PROFILE"
  echo "----------------------------------------"
} | tee -a "$LOG_FILE"

# 処理実行 & 標準エラー（2）も含めて追記
uv run python src/triage.py --profile "$PROFILE" --alas "$ALAS" 2>&1 | tee -a "$LOG_FILE"
