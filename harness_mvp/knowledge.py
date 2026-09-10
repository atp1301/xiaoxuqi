"""Small, dependency-free security knowledge base with explainable search.

The bundled references are teaching material.  They describe general CWE
patterns and remediation guidance; they are not evidence that a local lab is
affected, and no lab-specific CVE is asserted here.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class KnowledgeEntry:
    """A knowledge item, retaining the original four-field API."""

    entry_id: str
    title: str
    text: str
    tags: tuple[str, ...] = ()
    cwe: str = ""
    remediation: str = ""
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.tags, tuple):
            object.__setattr__(self, "tags", tuple(self.tags))


def _tokens(value: str) -> list[str]:
    """Tokenize words, CWE identifiers, and non-ASCII text without a package."""
    normalized = re.sub(
        r"\bcwe[-_\s]*([0-9]+)\b",
        lambda match: "cwe-" + (match.group(1).lstrip("0") or "0"),
        value.lower(),
    )
    return re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*|[\u4e00-\u9fff]", normalized)


_CWE = "https://cwe.mitre.org/data/definitions/"
DEFAULT_ENTRIES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("CWE-089", "SQL injection", "Untrusted input changes the structure of a SQL query.", ("sqli", "database", "input"), "CWE-89", "Use parameterized queries or prepared statements; validate input and use least-privilege database accounts.", _CWE + "89.html"),
    KnowledgeEntry("CWE-079", "Cross-site scripting", "Reflected or stored input is interpreted as browser script.", ("xss", "output", "browser"), "CWE-79", "Context-encode output, sanitize rich text deliberately, and deploy a restrictive Content Security Policy.", _CWE + "79.html"),
    KnowledgeEntry("CWE-862", "Missing authorization", "A protected function does not verify that the caller is allowed to use it.", ("authorization", "access-control", "admin"), "CWE-862", "Enforce server-side authorization on every protected route and deny by default.", _CWE + "862.html"),
    KnowledgeEntry("CWE-306", "Missing authentication", "A sensitive function can be reached without proving the caller identity.", ("authentication", "login", "identity"), "CWE-306", "Require authentication before sensitive operations and centralize session checks.", _CWE + "306.html"),
    KnowledgeEntry("CWE-022", "Path traversal", "Path input can escape an intended directory through traversal sequences.", ("file", "path", "filesystem"), "CWE-22", "Resolve paths against an allowed directory, reject escapes, and use an allowlist of files.", _CWE + "22.html"),
    KnowledgeEntry("CWE-078", "OS command injection", "Untrusted data is concatenated into an operating-system command.", ("command", "shell", "injection"), "CWE-78", "Avoid shell evaluation, pass argument arrays to a process API, and allowlist values.", _CWE + "78.html"),
    KnowledgeEntry("CWE-918", "Server-side request forgery", "A server fetches attacker-influenced destinations and may reach internal services.", ("ssrf", "network", "request"), "CWE-918", "Use destination allowlists, block private ranges after DNS resolution, and restrict egress.", _CWE + "918.html"),
    KnowledgeEntry("CWE-119", "Out-of-bounds memory access", "A buffer operation reads or writes beyond the allocated object.", ("memory", "buffer", "bounds"), "CWE-119", "Use memory-safe APIs, validate lengths, and enable compiler and runtime protections.", _CWE + "119.html"),
    KnowledgeEntry("CWE-798", "Hard-coded credentials", "Passwords, tokens, or keys embedded in source can be recovered by users or attackers.", ("secret", "credential", "key"), "CWE-798", "Load secrets from a managed secret store or protected environment and rotate exposed values.", _CWE + "798.html"),
    KnowledgeEntry("CWE-311", "Missing encryption of sensitive data", "Sensitive data is stored or transmitted without appropriate cryptographic protection.", ("encryption", "privacy", "transport"), "CWE-311", "Encrypt sensitive data in transit and at rest, manage keys separately, and minimize retention.", _CWE + "311.html"),
    KnowledgeEntry("CWE-400", "Uncontrolled resource consumption", "An input can make the service consume excessive CPU, memory, connections, or storage.", ("dos", "rate-limit", "availability"), "CWE-400", "Apply bounded input sizes, timeouts, quotas, concurrency limits, and rate limiting.", _CWE + "400.html"),
    KnowledgeEntry("CWE-352", "Cross-site request forgery", "A browser can be induced to submit a state-changing request using a victim session.", ("csrf", "session", "browser"), "CWE-352", "Use anti-CSRF tokens or appropriate SameSite cookies and verify origin where practical.", _CWE + "352.html"),
)


class KnowledgeBase:
    """In-memory TF-IDF index with deterministic cosine-similarity search."""

    def __init__(self, entries: Iterable[KnowledgeEntry] | None = None) -> None:
        self.entries = tuple(entries) if entries is not None else DEFAULT_ENTRIES
        self._documents = [self._document(entry) for entry in self.entries]
        self._idf = self._build_idf(self._documents)

    @staticmethod
    def _document(entry: KnowledgeEntry) -> list[str]:
        # Repeat the title to make labels useful while retaining a plain
        # token-based model that can be inspected and explained easily.
        return _tokens(" ".join((entry.title, entry.title, entry.text, entry.cwe, " ".join(entry.tags), entry.remediation)))

    @staticmethod
    def _build_idf(documents: list[list[str]]) -> dict[str, float]:
        count = len(documents)
        if not count:
            return {}
        df: dict[str, int] = {}
        for document in documents:
            for token in set(document):
                df[token] = df.get(token, 0) + 1
        return {token: math.log((count + 1) / (frequency + 1)) + 1.0 for token, frequency in df.items()}

    def _vector(self, tokens: Iterable[str]) -> dict[str, float]:
        token_list = list(tokens)
        counts: dict[str, int] = {}
        for token in token_list:
            counts[token] = counts.get(token, 0) + 1
        length = len(token_list)
        if not length:
            return {}
        return {token: (frequency / length) * self._idf.get(token, 0.0) for token, frequency in counts.items()}

    @staticmethod
    def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
        denominator = math.sqrt(sum(value * value for value in left.values())) * math.sqrt(sum(value * value for value in right.values()))
        return sum(left.get(token, 0.0) * value for token, value in right.items()) / denominator if denominator else 0.0

    def search(self, query: str, limit: int = 3) -> list[KnowledgeEntry]:
        """Rank lexical relevance; score is cosine similarity, not confidence.

        Each returned copy includes the matched terms and score explanation.
        Unrelated queries produce no result instead of a zero-score fallback.
        """
        if limit <= 0 or not isinstance(query, str):
            return []
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        query_vector = self._vector(query_tokens)
        ranked = [(self._cosine(query_vector, self._vector(document)), index, entry) for index, (document, entry) in enumerate(zip(self._documents, self.entries))]
        ranked.sort(key=lambda item: (-item[0], item[1]))
        results: list[KnowledgeEntry] = []
        for score, index, entry in ranked[:limit]:
            if score <= 0.0:
                continue
            rounded_score = round(score, 6)
            results.append(replace(entry, score=rounded_score, metadata={
                **entry.metadata,
                "cwe": entry.cwe,
                "source": entry.source,
                "remediation": entry.remediation,
                "retrieval": {
                    "method": "tf-idf-cosine",
                    "score": rounded_score,
                    "score_meaning": "Lexical cosine similarity in [0, 1]; not vulnerability confidence or proof.",
                    "matched_terms": sorted(set(query_tokens).intersection(self._documents[index])),
                },
            }))
        return results


__all__ = ["DEFAULT_ENTRIES", "KnowledgeBase", "KnowledgeEntry"]
