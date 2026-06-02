from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def ensure_run_dir(run_dir: str | Path) -> Path:
    path = Path(run_dir)
    (path / "artifacts").mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: str | Path, data: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")

