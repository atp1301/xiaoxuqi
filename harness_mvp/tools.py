from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError, URLError

from .models import ProbeResponse, Target
from .policy import PolicyEngine
from .knowledge import KnowledgeBase, KnowledgeEntry  # compatibility re-export


@dataclass(frozen=True)
class ToolSpec:
    """One entry in the harness tool library."""

    name: str
    category: str
    description: str
    required_permission: str
    status: str = "implemented"


TOOL_REGISTRY: dict[str, ToolSpec] = {
    "recon_probe": ToolSpec("recon_probe", "recon", "Bounded GET probe of an allowlisted training path.", "recon_probe", "implemented"),
    "vuln_analyze": ToolSpec("vuln_analyze", "recon", "Deterministic finding analysis plus knowledge-base retrieval.", "vuln_analyze", "implemented"),
    "code_audit_scan": ToolSpec("code_audit_scan", "recon", "Regex sink scan of authorized lab source; demo-level taint skeleton.", "code_audit_scan", "implemented"),
    "env_repro_read": ToolSpec("env_repro_read", "recon", "Read a lab manifest and emit start/reset/cleanup reproduction steps.", "env_repro_read", "implemented"),
    "exploit_simulate": ToolSpec("exploit_simulate", "exploit", "Record a simulated proof-of-concept; send no payload.", "exploit_simulate", "implemented"),
    "exploit_validate_sqlite": ToolSpec("exploit_validate_sqlite", "exploit", "Fixed baseline/positive/negative GET differential for the SQLite lab.", "exploit_validate_sqlite", "implemented"),
    "exploit_validate_complex": ToolSpec("exploit_validate_complex", "exploit", "Fixed GET chain for complex-web identity and ground-truth flag.", "exploit_validate_complex", "implemented"),
    "post_exploit_simulate": ToolSpec("post_exploit_simulate", "post-exploit", "Record a simulated lateral-movement hop; never execute it.", "post_exploit_simulate", "implemented"),
    "report_write": ToolSpec("report_write", "post-exploit", "Write the auditable JSON/Markdown report.", "report_write", "implemented"),
    "nmap_scan": ToolSpec("nmap_scan", "recon", "Network port scan. Sandbox adapter is not wired.", "nmap_scan", "stub"),
    "dir_enum": ToolSpec("dir_enum", "recon", "Directory enumeration. Sandbox adapter is not wired.", "dir_enum", "stub"),
    "command_exec": ToolSpec("command_exec", "post-exploit", "Arbitrary command execution. Sandbox adapter is not wired.", "command_exec", "stub"),
}


def get_tool(name: str) -> ToolSpec | None:
    return TOOL_REGISTRY.get(name)


def list_tools(*, implemented_only: bool = False) -> list[ToolSpec]:
    tools = list(TOOL_REGISTRY.values())
    if implemented_only:
        tools = [item for item in tools if item.status == "implemented"]
    return tools


def implemented_tool_names() -> frozenset[str]:
    return frozenset(item.name for item in TOOL_REGISTRY.values() if item.status == "implemented")


class DemoLabAdapter:
    """Deterministic local lab adapter. It simulates responses and never attacks a host."""

    recon_paths = ("/", "/login", "/search", "/admin", "/health")
    source_name = "demo"
    ENDPOINTS: dict[str, dict[str, Any]] = {
        "/": {"status": 200, "body": "Demo Portal | public training application", "title": "Demo Portal"},
        "/login": {"status": 200, "body": "Login form; database error detail disabled=false; SQL syntax marker", "title": "Login"},
        "/search": {"status": 200, "body": "Search results reflect the q parameter without output encoding", "title": "Search"},
        "/admin": {"status": 200, "body": "Admin panel | authorization_required=false | training secret", "title": "Admin"},
        "/health": {"status": 200, "body": "ok", "title": "Health"},
    }

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine()

    def probe(self, target: Target | str, path: str = "/") -> ProbeResponse:
        parsed = self.policy.require_action("recon_probe", target)
        normalized = "/" + path.lstrip("/")
        if "?" in normalized:
            normalized = normalized.split("?", 1)[0]
        started = time.perf_counter()
        item = self.ENDPOINTS.get(normalized, {"status": 404, "body": "not found", "title": "Not Found"})
        return ProbeResponse(
            path=normalized,
            status_code=item["status"],
            headers={"Content-Type": "text/html", "X-Lab": "DemoLabAdapter"},
            body_excerpt=item["body"][:240],
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            source="demo",
            metadata={"title": item["title"], "target": parsed.address},
        )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class HttpLabAdapter:
    """Bounded adapter for an explicitly authorized local HTTP lab."""

    recon_paths = ("/", "/login", "/search", "/admin", "/health")
    source_name = "http-lab"
    ALLOWED_PATHS = frozenset({"/", "/login", "/search", "/admin", "/health"})
    SQLI_POSITIVE = "' OR 1=1 --"
    SQLI_NEGATIVE = "' AND 1=0 --"

    def __init__(self, policy: PolicyEngine | None = None, timeout: float = 2.0) -> None:
        self.policy = policy or PolicyEngine()
        self.timeout = min(max(timeout, 0.1), 3.0)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _target(self, target: Target | str) -> Target:
        parsed = self.policy.require_action("recon_probe", target)
        if parsed.scheme != "http" or parsed.host not in {"127.0.0.1", "localhost"}:
            raise RuntimeError("local HTTP lab requires an http loopback target")
        # Pin localhost to the loopback IP rather than trusting DNS or hosts edits.
        return Target("127.0.0.1", parsed.port, "http")

    def _request(self, parsed: Target, path: str, query: str = "") -> ProbeResponse:
        if path not in self.ALLOWED_PATHS:
            raise ValueError(f"path is not allowed for the local lab: {path}")
        url = f"{parsed.address}{path}{('?' + query) if query else ''}"
        request = Request(url, method="GET", headers={"User-Agent": "harness-mvp/0.1", "X-Harness-Client": "harness-mvp"})
        started = time.perf_counter()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body_bytes = response.read(16385)
                if len(body_bytes) > 16384:
                    raise RuntimeError("local lab response exceeds 16 KiB limit")
                status = response.status
                headers = dict(response.headers.items())
        except HTTPError as exc:
            with exc:
                if 300 <= exc.code < 400:
                    raise RuntimeError("redirects are forbidden for local lab requests") from exc
                body_bytes = exc.read(16385)
                status = exc.code
                headers = dict(exc.headers.items()) if exc.headers else {}
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"local lab request failed: {exc}") from exc
        if len(body_bytes) > 16384:
            raise RuntimeError("local lab response exceeds 16 KiB limit")
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        if (normalized_headers.get("x-training-lab") != "harness-mvp"
                or normalized_headers.get("x-training-lab-version") != "sqlite-sqli-v1"):
            raise RuntimeError("local lab service identity handshake failed")
        body = body_bytes.decode("utf-8", errors="replace")
        digest = hashlib.sha256(body_bytes).hexdigest()
        metadata = {"target": parsed.address, "request_url": url, "method": "GET",
                    "evidence_bytes": len(body_bytes), "body_sha256": digest,
                    "body": body, "evidence_scope": "fictional-local-training-data"}
        if query:
            metadata["query"] = query
        return ProbeResponse(path=path, status_code=status, headers=headers, body_excerpt=body[:240], latency_ms=round((time.perf_counter() - started) * 1000, 3), source="http-lab", metadata=metadata)

    def probe(self, target: Target | str, path: str = "/") -> ProbeResponse:
        parsed = self._target(target)
        normalized = "/" + path.lstrip("/")
        if "?" in normalized or "#" in normalized:
            raise ValueError("HTTP lab probe accepts a path without query strings or fragments")
        query = urlencode({"q": "course"}) if normalized == "/search" else ""
        return self._request(parsed, normalized, query)

    def validate_sqlite_sqli(self, target: Target | str) -> dict[str, ProbeResponse]:
        """Check identity before sending the fixed course inputs; no custom payload."""
        self.policy.require_action("exploit_validate_sqlite", target)
        parsed = self._target(target)
        handshake = self._request(parsed, "/health")
        if handshake.status_code != 200:
            raise RuntimeError("local lab health handshake did not return 200")
        return {
            "baseline": self._request(parsed, "/search", urlencode({"q": "course"})),
            "positive": self._request(parsed, "/search", urlencode({"q": self.SQLI_POSITIVE})),
            "negative": self._request(parsed, "/search", urlencode({"q": self.SQLI_NEGATIVE})),
        }


def http_probe(policy: PolicyEngine, target: Target | str, path: str = "/", timeout: float = 2.0) -> ProbeResponse:
    """Perform a bounded GET for an explicitly allowed local target."""
    return HttpLabAdapter(policy, timeout=timeout).probe(target, path)


class SafeCommandRunner:
    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine()

    def run(self, command: list[str] | tuple[str, ...]) -> dict[str, Any]:
        argv = self.policy.require_command(command)
        executable = sys.executable if argv[0] in {"python", "python.exe", "py"} else argv[0]
        completed = subprocess.run([executable, *argv[1:]], shell=False, capture_output=True, text=True, timeout=2, check=False)
        return {"argv": argv, "returncode": completed.returncode, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)
