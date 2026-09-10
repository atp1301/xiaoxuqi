"""Read-only readiness checks for the course's three required lab families."""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.request import urlopen


@dataclass(frozen=True)
class LabCheck:
    lab_id: str
    requirement: str
    status: str
    evidence: str
    next_action: str


def _docker_check() -> LabCheck:
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=4, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return LabCheck("docker", "container runtime", "blocked", str(exc), "Start Docker Desktop")
    if result.returncode != 0 or not result.stdout.strip():
        return LabCheck("docker", "container runtime", "blocked", result.stderr.strip() or "Docker server unavailable", "Start Docker Desktop")
    return LabCheck("docker", "container runtime", "ready", f"server {result.stdout.strip()}", "")


def _loopback_check(lab_id: str, requirement: str, url: str, ready_action: str, start_action: str) -> LabCheck:
    try:
        with urlopen(url, timeout=1.5) as response:
            body = response.read(256).decode("utf-8", errors="replace")
            if response.status == 200:
                return LabCheck(lab_id, requirement, "ready", f"{url} -> 200 {body}", ready_action)
            return LabCheck(lab_id, requirement, "not_ready", f"{url} -> {response.status}", start_action)
    except Exception as exc:  # urllib has platform-specific error subclasses
        return LabCheck(lab_id, requirement, "not_ready", str(exc), start_action)


def _http_check() -> LabCheck:
    return _loopback_check(
        "local-web",
        "local SQLite training lab",
        "http://127.0.0.1:18088/health",
        "Run local-web scenario",
        "Start lab/docker-compose.yml",
    )


def _complex_web_check() -> LabCheck:
    return _loopback_check(
        "complex-web",
        "complex Web/network lab",
        "http://127.0.0.1:18089/health",
        "Run complex-web scenario",
        "Start lab/complex_web via compose or python -m lab.complex_web",
    )


def _path_check(lab_id: str, requirement: str, env_name: str, expected: tuple[str, ...], next_action: str) -> LabCheck:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return LabCheck(lab_id, requirement, "not_configured", f"{env_name} is not set", next_action)
    try:
        root = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return LabCheck(lab_id, requirement, "not_ready", f"{env_name} path cannot be resolved: {exc}", next_action)
    if not root.is_dir():
        return LabCheck(lab_id, requirement, "not_ready", f"{env_name}={root} is not a directory", next_action)
    missing: list[str] = []
    unreadable: list[str] = []
    for item in expected:
        path = root / item
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file():
                missing.append(item)
                continue
            with resolved.open("rb") as stream:
                stream.read(1)
        except (OSError, RuntimeError, ValueError):
            unreadable.append(item)
    if missing:
        return LabCheck(lab_id, requirement, "not_ready", f"missing: {', '.join(missing)}", next_action)
    if unreadable:
        return LabCheck(lab_id, requirement, "not_ready", f"unreadable: {', '.join(unreadable)}", next_action)
    return LabCheck(lab_id, requirement, "catalog_ready", f"root={root}; required metadata readable", "Run the authorized lab validation")


def check_labs() -> list[LabCheck]:
    """Perform non-invasive checks; never starts a lab or executes a payload."""
    return [
        _docker_check(),
        _http_check(),
        _complex_web_check(),
        _path_check("goad", "Windows domain lab", "GOAD_ROOT", ("README.md",), "Set GOAD_ROOT to an isolated GOAD checkout"),
        _path_check("exploitgym", "ExploitGym two-task validation", "EXPLOITGYM_ROOT", ("README.md", "data/task_ids/v1.txt"), "Set EXPLOITGYM_ROOT on a dedicated Linux host"),
        _path_check("vulhub", "complex Web/network lab", "VULHUB_ROOT", ("README.md",), "Set VULHUB_ROOT to an authorized Vulhub checkout"),
    ]


def checks_as_json() -> str:
    return json.dumps([asdict(check) for check in check_labs()], ensure_ascii=False, indent=2)
