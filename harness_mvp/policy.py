from __future__ import annotations

import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Target


ALLOWED_HOSTS = frozenset({"demo.local", "localhost", "127.0.0.1"})
ALLOWED_ACTIONS = frozenset({
    "recon_probe", "vuln_analyze", "exploit_simulate", "exploit_validate_sqlite", "report_write",
})


class PolicyViolation(ValueError):
    """Raised when a target or tool call falls outside the lab policy."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def parse_target(value: str) -> Target:
    raw = value.strip()
    if not raw:
        raise PolicyViolation("target must not be empty")
    parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
    if parsed.username or parsed.password:
        raise PolicyViolation("target credentials are not accepted")
    if not parsed.hostname:
        raise PolicyViolation("target host is missing")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise PolicyViolation("target must contain only host and optional port")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise PolicyViolation("target port is invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise PolicyViolation("only http and https targets are supported")
    return Target(parsed.hostname.lower().rstrip("."), port, parsed.scheme)


class PolicyEngine:
    """Central policy gate used by every tool-facing operation."""

    def __init__(self, allowed_hosts: frozenset[str] = ALLOWED_HOSTS) -> None:
        self.allowed_hosts = allowed_hosts

    def check_target(self, target: Target | str) -> PolicyDecision:
        try:
            parsed = parse_target(target) if isinstance(target, str) else target
        except PolicyViolation as exc:
            return PolicyDecision(False, str(exc))
        if parsed.scheme not in {"http", "https"}:
            return PolicyDecision(False, "only http and https targets are supported")
        if parsed.host not in self.allowed_hosts:
            return PolicyDecision(False, f"host {parsed.host!r} is outside the lab scope")
        if not (1 <= parsed.port <= 65535):
            return PolicyDecision(False, "port is outside the valid range")
        return PolicyDecision(True, "target is in the allowlist")

    def require_target(self, target: Target | str) -> Target:
        parsed = parse_target(target) if isinstance(target, str) else target
        decision = self.check_target(parsed)
        if not decision.allowed:
            raise PolicyViolation(decision.reason)
        return parsed

    def require_action(self, action: str, target: Target | str) -> Target:
        if action not in ALLOWED_ACTIONS:
            raise PolicyViolation(f"action {action!r} is not permitted")
        return self.require_target(target)

    def require_command(self, command: list[str] | tuple[str, ...]) -> list[str]:
        """Allow only a fixed diagnostic command; never invoke a shell."""
        argv = list(command)
        if argv not in (["python", "--version"], ["python.exe", "--version"], ["py", "--version"]):
            rendered = shlex.join(argv)
            raise PolicyViolation(f"command is not in the diagnostic allowlist: {rendered}")
        return argv
