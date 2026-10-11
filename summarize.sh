#!/usr/bin/env bash
cd "$(dirname "$0")"
PYTHONPATH=. uv run python -m src.eval_summary "$@"
