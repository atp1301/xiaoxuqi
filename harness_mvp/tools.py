from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError, URLError

from .models import ProbeResponse, Target
from .policy import PolicyEngine
from .knowledge import KnowledgeBase, KnowledgeEntry  # compatibility re-export


class DemoLabAdapter:
    """Deterministic local lab adapter. It simulates responses and never attacks a host."""

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
