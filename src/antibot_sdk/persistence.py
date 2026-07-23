"""Durable, atomic persistence for structured solver results."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any


def persist_json(value: Any, output_path: str | Path | None) -> Path | None:
    """Write a JSON value atomically and return its resolved destination."""

    if output_path is None or not str(output_path).strip():
        return None
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        pending.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        pending.replace(path)
    finally:
        try:
            pending.unlink(missing_ok=True)
        except OSError:
            pass
    return path


def persist_result(result: Any, output_path: str | Path | None) -> Path | None:
    """Persist a dataclass result and expose the path in its artifacts."""

    if output_path is None or not str(output_path).strip():
        return None
    path = Path(output_path).expanduser().resolve()
    artifacts = getattr(result, "artifacts", None)
    if isinstance(artifacts, dict):
        artifacts["output_json"] = str(path)
    to_dict = getattr(result, "to_dict", None)
    value = to_dict() if callable(to_dict) else result
    return persist_json(value, path)


__all__ = ["persist_json", "persist_result"]
