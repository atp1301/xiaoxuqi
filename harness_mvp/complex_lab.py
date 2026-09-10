"""Bounded adapter for the authorized multi-node complex-web training lab."""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from lab.complex_web.constants import (
    HIDDEN_PROOF,
    LAB_NAME,
    LAB_VERSION,
    PUBLIC_PROOF,
    SESSION_TOKEN,
    SQLI_NEGATIVE,
    SQLI_POSITIVE,
)
from lab.complex_web.server import load_flag

from .models import ProbeResponse, Target
from .policy import PolicyEngine
from .tools import _NoRedirect


_TOKEN_RE = re.compile(r"operator:([A-Za-z0-9_-]+)")
_FLAG_RE = re.compile(r"FLAG\{[^}]{1,120}\}")
_COUNT_RE = re.compile(r"search results \((\d+)\)", re.IGNORECASE)


class ComplexWebAdapter:
    """Loopback-only adapter for the three-node complex-web lab."""

    recon_paths = ("/", "/login", "/search", "/admin", "/health", "/topology", "/internal/whoami", "/internal/flag")
    source_name = "complex-web"
    ALLOWED_PATHS = frozenset({
        "/",
        "/login",
        "/search",
        "/admin",
        "/health",
        "/topology",
        "/internal/whoami",
        "/internal/exec",
        "/internal/flag",
    })

    def __init__(self, policy: PolicyEngine | None = None, timeout: float = 2.0) -> None:
        self.policy = policy or PolicyEngine()
        self.timeout = min(max(timeout, 0.1), 3.0)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _target(self, target: Target | str) -> Target:
        parsed = self.policy.require_action("recon_probe", target)
        if parsed.scheme != "http" or parsed.host not in {"127.0.0.1", "localhost"}:
            raise RuntimeError("complex-web lab requires an http loopback target")
        return Target("127.0.0.1", parsed.port, "http")

    def _request(
        self,
        parsed: Target,
        path: str,
        query: str = "",
        headers: dict[str, str] | None = None,
        action: str = "recon_probe",
    ) -> ProbeResponse:
        if path not in self.ALLOWED_PATHS:
            raise ValueError(f"path is not allowed for the complex-web lab: {path}")
        self.policy.require_action(action, parsed)
        url = f"{parsed.address}{path}{('?' + query) if query else ''}"
        request_headers = {"User-Agent": "harness-mvp/0.1", "X-Harness-Client": "harness-mvp"}
        request_headers.update(headers or {})
        request = Request(url, method="GET", headers=request_headers)
        started = time.perf_counter()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body_bytes = response.read(16385)
                status = response.status
                response_headers = dict(response.headers.items())
        except HTTPError as exc:
            with exc:
                if 300 <= exc.code < 400:
                    raise RuntimeError("redirects are forbidden for complex-web lab requests") from exc
                body_bytes = exc.read(16385)
                status = exc.code
                response_headers = dict(exc.headers.items()) if exc.headers else {}
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"complex-web lab request failed: {exc}") from exc
        if len(body_bytes) > 16384:
            raise RuntimeError("complex-web lab response exceeds 16 KiB limit")
        normalized = {key.lower(): value for key, value in response_headers.items()}
        if normalized.get("x-training-lab") != LAB_NAME or normalized.get("x-training-lab-version") != LAB_VERSION:
            raise RuntimeError("complex-web lab service identity handshake failed")
        body = body_bytes.decode("utf-8", errors="replace")
        digest = hashlib.sha256(body_bytes).hexdigest()
        metadata = {
            "target": parsed.address,
            "request_url": url,
            "method": "GET",
            "request_headers": {key: value for key, value in request_headers.items() if key.lower() != "user-agent"},
            "evidence_bytes": len(body_bytes),
            "body_sha256": digest,
            "body": body,
            "evidence_scope": "authorized-local-complex-web",
            "upstream": normalized.get("x-lab-upstream"),
            "node": normalized.get("x-lab-node"),
        }
        if query:
            metadata["query"] = query
        return ProbeResponse(
            path=path,
            status_code=status,
            headers=response_headers,
            body_excerpt=body[:240],
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            source="complex-web",
            metadata=metadata,
        )

    def probe(self, target: Target | str, path: str = "/") -> ProbeResponse:
        parsed = self._target(target)
        normalized = "/" + path.lstrip("/")
        if "?" in normalized or "#" in normalized:
            raise ValueError("complex-web probe accepts a path without query strings or fragments")
        query = urlencode({"q": "course"}) if normalized == "/search" else ""
        return self._request(parsed, normalized, query)

    def validate_sqli(self, target: Target | str) -> dict[str, ProbeResponse]:
        self.policy.require_action("exploit_validate_complex", target)
        parsed = self._target(target)
        handshake = self._request(parsed, "/health")
        if handshake.status_code != 200:
            raise RuntimeError("complex-web health handshake did not return 200")
        return {
            "baseline": self._request(parsed, "/search", urlencode({"q": "course"})),
            "positive": self._request(parsed, "/search", urlencode({"q": SQLI_POSITIVE})),
            "negative": self._request(parsed, "/search", urlencode({"q": SQLI_NEGATIVE})),
        }

    def validate_chain(self, target: Target | str) -> dict[str, Any]:
        """Discover/verify/identity/flag using only fixed classroom GET probes."""
        self.policy.require_action("exploit_validate_complex", target)
        parsed = self._target(target)
        sqli = self.validate_sqli(parsed)
        differential = sqli_differential(sqli)
        token = extract_session_token(sqli["positive"].metadata.get("body", sqli["positive"].body_excerpt))
        whoami = self._request(
            parsed,
            "/internal/whoami",
            headers={"X-Lab-Session": token or "missing"},
            action="exploit_validate_complex",
        )
        shell = self._request(
            parsed,
            "/internal/exec",
            query=urlencode({"cmd": "id"}),
            headers={"X-Lab-Session": token or "missing"},
            action="exploit_validate_complex",
        )
        flag_response = self._request(
            parsed,
            "/internal/flag",
            headers={"X-Lab-Session": token or "missing"},
            action="exploit_validate_complex",
        )
        observed_flag = extract_flag(flag_response.metadata.get("body", flag_response.body_excerpt))
        expected_flag = load_flag()
        identity_body = (whoami.metadata.get("body") or whoami.body_excerpt) + " " + (shell.metadata.get("body") or shell.body_excerpt)
        shell_ok = whoami.status_code == 200 and shell.status_code == 200 and "uid=65532(labuser)" in identity_body
        flag_ok = bool(observed_flag) and observed_flag == expected_flag and flag_response.status_code == 200
        verified = bool(differential["verified"] and token == SESSION_TOKEN and shell_ok and flag_ok)
        raw_http = [
            _evidence("sqli-baseline", sqli["baseline"]),
            _evidence("sqli-positive", sqli["positive"]),
            _evidence("sqli-negative", sqli["negative"]),
            _evidence("shell-whoami", whoami),
            _evidence("shell-exec-id", shell),
            _evidence("read-flag", flag_response),
        ]
        return {
            "verified": verified,
            "status": "verified" if verified else "failed",
            "differential": differential,
            "session_token_seen": token == SESSION_TOKEN,
            "shell_identity": "uid=65532(labuser)" if shell_ok else "",
            "shell_obtained": shell_ok,
            "flag": observed_flag,
            "flag_expected": expected_flag,
            "flag_match": flag_ok,
            "flag_sha256": hashlib.sha256((observed_flag or "").encode()).hexdigest() if observed_flag else "",
            "raw_http": raw_http,
            "probes": {
                "whoami": _summary(whoami),
                "exec": _summary(shell),
                "flag": _summary(flag_response),
            },
        }


def extract_session_token(body: str) -> str | None:
    match = _TOKEN_RE.search(body or "")
    return match.group(1) if match else None


def extract_flag(body: str) -> str:
    match = _FLAG_RE.search(body or "")
    return match.group(0) if match else ""


def search_result_count(body: str) -> int | None:
    match = _COUNT_RE.search((body or "").lower())
    return int(match.group(1)) if match else None


def sqli_differential(validation: dict[str, ProbeResponse]) -> dict[str, Any]:
    baseline = validation["baseline"]
    positive = validation["positive"]
    negative = validation["negative"]
    base_body = (baseline.metadata.get("body") or baseline.body_excerpt).lower()
    pos_body = (positive.metadata.get("body") or positive.body_excerpt).lower()
    neg_body = (negative.metadata.get("body") or negative.body_excerpt).lower()
    base_count = search_result_count(base_body)
    pos_count = search_result_count(pos_body)
    neg_count = search_result_count(neg_body)
    verified = (
        base_count == 1
        and PUBLIC_PROOF in base_body
        and pos_count is not None
        and pos_count > base_count
        and HIDDEN_PROOF in pos_body
        and SESSION_TOKEN in pos_body
        and neg_count == 0
        and SESSION_TOKEN not in base_body
        and "flag{" not in base_body
    )
    return {
        "verified": verified,
        "baseline_count": base_count,
        "positive_count": pos_count,
        "negative_count": neg_count,
        "proof_seen": HIDDEN_PROOF in pos_body,
        "public_seen": PUBLIC_PROOF in base_body,
        "token_seen": SESSION_TOKEN in pos_body,
        "positive_sha256": positive.metadata.get("body_sha256"),
        "negative_sha256": negative.metadata.get("body_sha256"),
        "baseline_sha256": baseline.metadata.get("body_sha256"),
    }


def _summary(response: ProbeResponse) -> dict[str, Any]:
    return {
        "path": response.path,
        "status_code": response.status_code,
        "body_excerpt": response.body_excerpt,
        "body_sha256": response.metadata.get("body_sha256"),
        "request_url": response.metadata.get("request_url"),
    }


def _evidence(step: str, response: ProbeResponse) -> dict[str, Any]:
    return {
        "step": step,
        "request": {
            "method": "GET",
            "url": response.metadata.get("request_url"),
            "headers": response.metadata.get("request_headers"),
        },
        "response": {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.metadata.get("body"),
            "sha256": response.metadata.get("body_sha256"),
        },
    }


__all__ = ["ComplexWebAdapter", "extract_flag", "extract_session_token", "sqli_differential"]
