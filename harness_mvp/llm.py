"""Small OpenAI-compatible client used only for bounded advisory decisions.

The API key is read from the process environment and is never written to
reports or logs. No third-party SDK is required.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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
        configured_timeout = timeout if timeout is not None else float(os.getenv("HARNESS_LLM_TIMEOUT", "60"))
        self.timeout = min(max(configured_timeout, 3.0), 120.0)

    def advisory(self, target: str, observations: list[dict[str, object]]) -> dict[str, object]:
        if not self.config.configured:
            raise RuntimeError("LLM is not configured; set HARNESS_LLM_API_KEY")
        prompt = {
            "target": target,
            "observations": observations,
            "instruction": "Analyze only the supplied observations. Return JSON with keys risk_summary, recommended_next_step, confidence. Do not invent endpoints, credentials, payloads, or exploit results.",
        }
        body = json.dumps({
            "model": self.config.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "You are a cautious security assessment analyst. Evidence first; no exploit execution."},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
        }).encode("utf-8")
        request = Request(
            f"{self.config.base_url}/chat/completions", data=body, method="POST",
            headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json", "User-Agent": "harness-mvp/0.1"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read(65536).decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM request failed with HTTP {exc.code}: {detail[:300]}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc
        try:
            content = payload["choices"][0]["message"]["content"]
            result = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("LLM returned an invalid advisory JSON response") from exc
        if not isinstance(result, dict):
            raise RuntimeError("LLM advisory must be a JSON object")
        return result
