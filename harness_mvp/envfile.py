"""Minimal ``.env`` reader for local development.

The repository keeps model credentials in an untracked ``.env`` file.  Nothing
loaded it, so ``HARNESS_LLM_*`` never reached the process environment unless the
operator exported it by hand.  This module closes that gap without adding a
dependency.

Two rules keep it safe:

* the real environment always wins, so an exported variable is never silently
  replaced by a file value;
* values never leave this module — callers receive the *names* that were
  applied, which is enough to log progress without materialising a secret.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MAX_ENV_FILE_BYTES = 64 * 1024
_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def default_env_path() -> Path:
    """Return the ``.env`` location, overridable for tests via ``HARNESS_ENV_FILE``."""
    override = os.environ.get("HARNESS_ENV_FILE", "").strip()
    return Path(override).expanduser() if override else _PROJECT_ROOT / ".env"


def _parse_line(line: str) -> tuple[str, str] | None:
    """Split one ``KEY=VALUE`` line, or return ``None`` when it carries no pair."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export "):].lstrip()
    key, _, value = stripped.partition("=")
    key = key.strip()
    if not _KEY_PATTERN.match(key):
        return None
    value = value.strip()
    # Strip one layer of matching quotes; leave inner characters untouched.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def load_env_file(path: str | os.PathLike[str] | None = None) -> list[str]:
    """Apply ``KEY=VALUE`` pairs from ``path`` to ``os.environ``.

    Returns the names that were actually applied — never the values.  A missing
    or unreadable file is a no-op rather than an error, because the project runs
    without a ``.env`` and must not fail when one is absent.
    """
    candidate = Path(path) if path is not None else default_env_path()
    try:
        if not candidate.is_file():
            return []
        raw = candidate.read_bytes()[:_MAX_ENV_FILE_BYTES]
    except OSError:
        return []
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        text = raw.decode("utf-8", errors="replace")

    applied: list[str] = []
    for line in text.splitlines():
        parsed = _parse_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key in os.environ:
            continue
        os.environ[key] = value
        applied.append(key)
    if applied and os.environ.get("HARNESS_ENV_VERBOSE") == "1":
        print(f"envfile: applied {len(applied)} variable name(s): {', '.join(applied)}")
    return applied


__all__ = ["load_env_file", "default_env_path"]
