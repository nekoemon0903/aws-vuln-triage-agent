import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import anthropic
from pydantic import BaseModel, ValidationError

from src.cases import EvalCase, load_and_validate_cases
from src.triage import triage_advisory


def run_eval(
    cases_path: Path,
    llm_func: Callable[[EvalCase], Any],
    output_dir: Path,
    repeat_count: int = 5,
    base_dir: Path = Path("."),
) -> list[dict[str, Any]]:
    """ケースを読み込み、指定回数実行して逐次保存するランナー。"""
    cases = load_and_validate_cases(cases_path, base_dir=base_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []

    for case in cases:
        for run_index in range(1, repeat_count + 1):
            record: dict[str, Any] = {
                "case_id": case.id,
                "run_index": run_index,
            }

            try:
                llm_output = llm_func(case)
                record["status"] = "SUCCESS"
                # FinalTriageReport などの Pydantic モデルを JSON 変換可能な dict にシリアライズ
                if isinstance(llm_output, BaseModel):
                    record["detail"] = llm_output.model_dump(mode="json")
                elif isinstance(llm_output, dict):
                    record["detail"] = llm_output
                else:
                    record["detail"] = str(llm_output)
            except anthropic.APIError as e:
                record["status"] = "API_ERROR"
                record["detail"] = str(e)
            except ValidationError as e:
                record["status"] = "VALIDATION_ERROR"
                record["detail"] = str(e)

            results.append(record)
            save_path = output_dir / f"{case.id}_run_{run_index}.json"
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)

    return results


def create_triage_adapter(client: anthropic.Anthropic, base_dir: Path = Path(".")):
    """EvalCase から profile / ALAS ファイルを読み込み triage_advisory へ渡す橋渡し関数"""

    def adapter(case: EvalCase) -> Any:
        alas_text = (base_dir / case.alas_path).read_text(encoding="utf-8")
        profile_text = (base_dir / case.profile_path).read_text(encoding="utf-8")
        return triage_advisory(
            profile_yaml=profile_text, alas_text=alas_text, client=client
        )

    return adapter


def main():
    """実行用エントリポイント"""
    client = anthropic.Anthropic()
    adapter = create_triage_adapter(client)

    # 実行のたびに日時つきディレクトリを作成して上書き防止
    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("evals/results") / timestamp

    print(f"Eval開始: 出力先 -> {output_dir}")
    results = run_eval(
        cases_path=Path("evals/cases.yaml"),
        llm_func=adapter,
        output_dir=output_dir,
        repeat_count=5,
    )
    print(f"Eval完了: 全 {len(results)} 件の結果を保存しました。")


if __name__ == "__main__":
    main()
