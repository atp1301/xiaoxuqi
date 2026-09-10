"""Atomic, versioned persistence for resumable harness runs."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .models import RunState

SCHEMA_VERSION = 1


def write_checkpoint(
    state: RunState,
    path: str | Path,
    plan: list[dict[str, Any]],
    step_statuses: list[dict[str, Any]],
    next_step_index: int,
) -> str:
    """Write a complete checkpoint atomically and return its absolute path."""
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    state.checkpoint_path = str(destination)
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "checkpoint_path": str(destination),
        "next_step_index": next_step_index,
        "plan": plan,
        "step_statuses": step_statuses,
        "state": state.to_dict(),
    }
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(envelope, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return str(destination)


def load_checkpoint(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    with source.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported or invalid checkpoint schema in {source}")
    if not isinstance(payload.get("state"), dict):
        raise ValueError(f"checkpoint state is missing in {source}")
    payload["checkpoint_path"] = str(source)
    return payload
