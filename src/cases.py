from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.triage import Status


class ExpectedResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Status
    missing_config_keys: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_missing_keys(self) -> "ExpectedResult":
        if self.status == Status.NEED_CHECK and not self.missing_config_keys:
            raise ValueError("statusが'要確認'の場合、missing_config_keysは必須です")
        return self


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    cell: int = Field(ge=1, le=6)
    cve_id: str
    description: str
    profile_path: str
    alas_path: str
    expected: ExpectedResult


def load_and_validate_cases(
    yaml_path: Path, base_dir: Path = Path(".")
) -> list[EvalCase]:
    with open(yaml_path, encoding="utf-8") as f:
        raw_cases = yaml.safe_load(f)

    seen_ids = set()
    cases = []
    for raw in raw_cases:
        case = EvalCase(**raw)
        if case.id in seen_ids:
            raise ValueError(f"IDが重複しています: {case.id}")
        seen_ids.add(case.id)

        alas_file = base_dir / case.alas_path
        if not alas_file.exists():
            raise FileNotFoundError(
                f"指定されたALASファイルが見つかりません: {case.alas_path}"
            )

        alas_text = alas_file.read_text(encoding="utf-8")
        if case.cve_id not in alas_text:
            raise ValueError(
                f"cve_id {case.cve_id}はALAS({case.alas_path})内に存在しません"
            )

        cases.append(case)
    return cases
