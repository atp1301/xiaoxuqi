"""Small OpenAI-compatible client used only for bounded advisory decisions.

The API key is read from the process environment and is never written to
reports or logs. No third-party SDK is required.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .interpretation import (
    BRIEF_VERSION,
    PROMPT_VERSION,
    band_for,
    evidence_digest,
    validate_interpretation,
    validate_risk_brief,
)


_INTERPRETATION_SYSTEM = (
    "You are a bounded risk grader inside an authorized security-assessment harness. "
    "The differential probe results you are given were produced by fixed HTTP requests and "
    "their SHA-256 digests are real; they are the only source of truth. "
    "You must not invent findings, endpoints, payloads, credentials, or exploit results, and "
    "you must not add, remove, rename or re-describe any finding. Every finding you receive "
    "already exists. You only grade what is in front of you. "
    "Your text is published next to machine-verified evidence and is labelled as interpretation, "
    "so write plainly and state uncertainty rather than asserting more than the evidence shows."
)


# A single advisory call to a reasoning model measured 61.5 s on the reference
# endpoint, so the previous 60 s default failed on a *successful* call.  The
# ceiling bounds a hung run at two calls without ever clipping a healthy one.
DEFAULT_TIMEOUT_SECONDS = 180.0
MIN_TIMEOUT_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_RESPONSE_BYTES = 65_536
MAX_BRIEF_RESPONSE_BYTES = 262_144


@dataclass(frozen=True)
class ModelConfig:
    api_key: str = field(default="", repr=False)
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    provider: str = "openai-compatible"

    @classmethod
    def from_env(cls) -> "ModelConfig":
        return cls(
            api_key=os.getenv("HARNESS_LLM_API_KEY", "").strip(),
            base_url=os.getenv("HARNESS_LLM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/"),
            model=os.getenv("HARNESS_LLM_MODEL", "gpt-4o-mini").strip(),
            provider=os.getenv("HARNESS_LLM_PROVIDER", "openai-compatible").strip(),
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)


class LLMClient:
    def __init__(self, config: ModelConfig | None = None, timeout: float | None = None) -> None:
        self.config = config or ModelConfig.from_env()
        configured_timeout = timeout if timeout is not None else float(
            os.getenv("HARNESS_LLM_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS))
        )
        self.timeout = min(max(configured_timeout, MIN_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS)

    def _chat_json(
        self,
        prompt: dict[str, object],
        *,
        system: str,
        max_bytes: int = MAX_RESPONSE_BYTES,
        invalid_message: str = "LLM returned an invalid advisory JSON response",
    ) -> tuple[dict[str, object], str]:
        """POST one JSON-mode chat completion and return ``(parsed, raw_text)``.

        Transport and decoding failures raise ``RuntimeError`` so callers can
        decide whether to degrade or propagate.  The raw text is returned so the
        caller can hash it for the audit trail without storing the payload.
        """
        if not self.config.configured:
            raise RuntimeError("LLM is not configured; set HARNESS_LLM_API_KEY")
        body = json.dumps({
            "model": self.config.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
        }).encode("utf-8")
        request = Request(
            f"{self.config.base_url}/chat/completions", data=body, method="POST",
            headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json", "User-Agent": "harness-mvp/0.1"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read(max_bytes).decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM request failed with HTTP {exc.code}: {detail[:300]}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc
        try:
            content = payload["choices"][0]["message"]["content"]
            result = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(invalid_message) from exc
        if not isinstance(result, dict):
            raise RuntimeError(invalid_message)
        return result, content if isinstance(content, str) else json.dumps(result, ensure_ascii=False)

    def advisory(self, target: str, observations: list[dict[str, object]]) -> dict[str, object]:
        prompt = {
            "target": target,
            "observations": observations,
            "instruction": "Analyze only the supplied observations. Return JSON with keys risk_summary, recommended_next_step, confidence. Do not invent endpoints, credentials, payloads, or exploit results.",
        }
        result, _ = self._chat_json(
            prompt,
            system="You are a cautious security assessment analyst. Evidence first; no exploit execution.",
        )
        return result

    def interpret_findings(
        self,
        target: str,
        scenario: str,
        briefs: list[dict[str, object]],
    ) -> dict[str, object]:
        """Ask the model to grade findings whose evidence already exists.

        The bands are derived from the same briefs that are sent, so the
        interval a severity is checked against is a function of the measured
        differential and nothing else. Returns validated output only; the raw
        response is reduced to a digest for the audit trail.
        """
        bands = {
            str(brief["finding_id"]): band_for(
                measured=brief.get("measured") is not None,
                verified=brief.get("measured_verified"),
            )
            for brief in briefs
            if isinstance(brief.get("finding_id"), str) and brief["finding_id"]
        }
        prompt = {
            "target": target,
            "scenario": scenario,
            "prompt_version": PROMPT_VERSION,
            "findings": briefs,
            "instruction": (
                "Grade each supplied finding. Return JSON with a single key, interpretations, "
                "whose value is a list of objects with exactly these keys: finding_id, severity, "
                "confidence, narrative. Use each finding_id at most once and only ids that were "
                "supplied. severity is one of info, low, medium, high, critical. confidence is a "
                "number in [0, 1]. narrative is one paragraph of at most 600 characters with no "
                "headings, links, or code fences. Return no other keys."
            ),
        }
        result, raw = self._chat_json(
            prompt,
            system=_INTERPRETATION_SYSTEM,
            max_bytes=MAX_BRIEF_RESPONSE_BYTES,
            invalid_message="LLM returned an invalid interpretation JSON response",
        )
        accepted, rejected = validate_interpretation(result, bands)
        return {
            "interpretations": accepted,
            "rejected": rejected,
            "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "evidence_sha256": evidence_digest(briefs),
        }

    def risk_brief(self, target: str, scenario: str, evidence: dict[str, object]) -> dict[str, object]:
        """Ask the model for the report-stage risk brief over verified evidence."""
        prompt = {
            "target": target,
            "scenario": scenario,
            "prompt_version": BRIEF_VERSION,
            "evidence": evidence,
            "instruction": (
                "Write the assessment brief from the supplied evidence only. Return JSON with keys "
                "overall_risk (one of info, low, medium, high, critical), executive_summary (one "
                "paragraph, at most 1500 characters), prioritized_actions (at most 5 strings, each "
                "at most 240 characters) and limitations (at most 5 strings, each at most 240 "
                "characters). No headings, links, or code fences. Return no other keys."
            ),
        }
        result, raw = self._chat_json(
            prompt,
            system=_INTERPRETATION_SYSTEM,
            max_bytes=MAX_BRIEF_RESPONSE_BYTES,
            invalid_message="LLM returned an invalid risk brief JSON response",
        )
        brief, rejected = validate_risk_brief(result)
        return {
            "content": brief,
            "rejected": rejected,
            "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "evidence_sha256": evidence_digest(evidence),
        }
