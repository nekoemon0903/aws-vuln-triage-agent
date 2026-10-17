import argparse
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import anthropic
from pydantic import BaseModel, ValidationError

from src.cases import EvalCase, load_and_validate_cases
from src.triage import triage_advisory


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """CLI引数をパースする"""
    parser = argparse.ArgumentParser(description="Evalランナー")
    parser.add_argument(
        "--case-id",
        dest="case_ids",
        nargs="+",
        help="実行するケースIDを指定（複数指定可）",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        default=False,
        help="関門対象（expected.status が '対応不要' 以外）のケースを実行",
    )
    return parser.parse_args(argv)


def filter_cases(
    cases: list[EvalCase],
    case_ids: list[str] | None = None,
    gate: bool = False,
) -> list[EvalCase]:
    """ケース一覧から指定されたIDおよび関門対象のケースを抽出する（和集合・順序保持）"""
    if not case_ids and not gate:
        return list(cases)

    all_ids = {c.id for c in cases}
    if case_ids:
        missing_ids = [cid for cid in case_ids if cid not in all_ids]
        if missing_ids:
            raise ValueError(
                f"指定されたケースIDが見つかりません: {', '.join(missing_ids)}"
            )

    target_id_set = set(case_ids) if case_ids else set()

    filtered: list[EvalCase] = []
    for c in cases:
        is_selected_id = c.id in target_id_set
        # README 6.1: 正解が「対応不要」以外（要対応・要確認）を関門とする
        is_gate_target = gate and c.expected.status != "対応不要"
        if is_selected_id or is_gate_target:
            filtered.append(c)

    return filtered


def run_eval(
    cases: list[EvalCase] | None = None,
    llm_func: Callable[[EvalCase], Any] | None = None,
    output_dir: Path = Path("."),
    repeat_count: int = 5,
    base_dir: Path = Path("."),
    cases_path: Path | None = None,
) -> list[dict[str, Any]]:
    """ケースを実行して逐次保存するランナー（cases または cases_path を受け取り可能）"""
    if cases is not None:
        eval_cases = cases
    elif cases_path is not None:
        eval_cases = load_and_validate_cases(cases_path, base_dir=base_dir)
    else:
        raise ValueError("cases または cases_path のいずれかを指定してください。")

    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

    for case in eval_cases:
        for run_index in range(1, repeat_count + 1):
            record: dict[str, Any] = {
                "case_id": case.id,
                "run_index": run_index,
            }

            try:
                llm_output = llm_func(case)
                record["status"] = "SUCCESS"
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


def main(argv: list[str] | None = None):
    """実行用エントリポイント"""
    args = parse_args(argv)

    all_cases = load_and_validate_cases(Path("evals/cases.yaml"))
    target_cases = filter_cases(all_cases, case_ids=args.case_ids, gate=args.gate)

    client = anthropic.Anthropic()
    adapter = create_triage_adapter(client)

    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("evals/results") / timestamp

    print(f"Eval開始: 対象 {len(target_cases)} 件, 出力先 -> {output_dir}")
    results = run_eval(
        cases=target_cases,
        llm_func=adapter,
        output_dir=output_dir,
        repeat_count=5,
    )
    print(f"Eval完了: 全 {len(results)} 件の結果を保存しました。")


if __name__ == "__main__":
    main()
