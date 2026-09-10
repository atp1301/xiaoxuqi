from __future__ import annotations

import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Target


ALLOWED_HOSTS = frozenset({"demo.local", "localhost", "127.0.0.1"})
# Fallback used only if the tool registry cannot be imported. Live checks
# prefer TOOL_REGISTRY so implemented/stub status stays in one place.
ALLOWED_ACTIONS = frozenset({
    "recon_probe",
    "vuln_analyze",
    "code_audit_scan",
    "env_repro_read",
    "exploit_simulate",
    "exploit_validate_sqlite",
    "exploit_validate_complex",
    "post_exploit_simulate",
    "report_write",
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
        spec = None
        try:
            from .tools import get_tool
            spec = get_tool(action)
        except Exception:
            spec = None
        if spec is None:
            if action not in ALLOWED_ACTIONS:
                raise PolicyViolation(f"action {action!r} is not permitted")
        elif spec.status == "stub":
            raise PolicyViolation(f"action {action!r} is registered as a sandbox stub and is not executable")
        elif spec.status != "implemented":
            raise PolicyViolation(f"action {action!r} is not an implemented tool")
        elif spec.required_permission != action:
            raise PolicyViolation(f"action {action!r} does not match its required permission")
        return self.require_target(target)

    def require_command(self, command: list[str] | tuple[str, ...]) -> list[str]:
        """Allow only a fixed diagnostic command; never invoke a shell."""
        argv = list(command)
        if argv not in (["python", "--version"], ["python.exe", "--version"], ["py", "--version"]):
            rendered = shlex.join(argv)
            raise PolicyViolation(f"command is not in the diagnostic allowlist: {rendered}")
        return argv
