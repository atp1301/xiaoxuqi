from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
import re
from pathlib import Path
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
    category: str = "cve"
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
_CVE = "https://www.cve.org/CVERecord?id="
_ATTACK = "https://attack.mitre.org/techniques/"
KNOWLEDGE_CATEGORIES = ("cve", "ttp", "payload", "case")

_CWE_ENTRIES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("CWE-089", "SQL injection", "Untrusted input changes the structure of a SQL query.", ("sqli", "database", "input"), "CWE-89", "Use parameterized queries or prepared statements; validate input and use least-privilege database accounts.", _CWE + "89.html", "cve"),
    KnowledgeEntry("CWE-079", "Cross-site scripting", "Reflected or stored input is interpreted as browser script.", ("xss", "output", "browser"), "CWE-79", "Context-encode output, sanitize rich text deliberately, and deploy a restrictive Content Security Policy.", _CWE + "79.html", "cve"),
    KnowledgeEntry("CWE-862", "Missing authorization", "A protected function does not verify that the caller is allowed to use it.", ("authorization", "access-control", "admin"), "CWE-862", "Enforce server-side authorization on every protected route and deny by default.", _CWE + "862.html", "cve"),
    KnowledgeEntry("CWE-306", "Missing authentication", "A sensitive function can be reached without proving the caller identity.", ("authentication", "login", "identity"), "CWE-306", "Require authentication before sensitive operations and centralize session checks.", _CWE + "306.html", "cve"),
    KnowledgeEntry("CWE-022", "Path traversal", "Path input can escape an intended directory through traversal sequences.", ("file", "path", "filesystem"), "CWE-22", "Resolve paths against an allowed directory, reject escapes, and use an allowlist of files.", _CWE + "22.html", "cve"),
    KnowledgeEntry("CWE-078", "OS command injection", "Untrusted data is concatenated into an operating-system command.", ("command", "shell", "injection"), "CWE-78", "Avoid shell evaluation, pass argument arrays to a process API, and allowlist values.", _CWE + "78.html", "cve"),
    KnowledgeEntry("CWE-918", "Server-side request forgery", "A server fetches attacker-influenced destinations and may reach internal services.", ("ssrf", "network", "request"), "CWE-918", "Use destination allowlists, block private ranges after DNS resolution, and restrict egress.", _CWE + "918.html", "cve"),
    KnowledgeEntry("CWE-119", "Out-of-bounds memory access", "A buffer operation reads or writes beyond the allocated object.", ("memory", "buffer", "bounds"), "CWE-119", "Use memory-safe APIs, validate lengths, and enable compiler and runtime protections.", _CWE + "119.html", "cve"),
    KnowledgeEntry("CWE-798", "Hard-coded credentials", "Passwords, tokens, or keys embedded in source can be recovered by users or attackers.", ("secret", "credential", "key"), "CWE-798", "Load secrets from a managed secret store or protected environment and rotate exposed values.", _CWE + "798.html", "cve"),
    KnowledgeEntry("CWE-311", "Missing encryption of sensitive data", "Sensitive data is stored or transmitted without appropriate cryptographic protection.", ("encryption", "privacy", "transport"), "CWE-311", "Encrypt sensitive data in transit and at rest, manage keys separately, and minimize retention.", _CWE + "311.html", "cve"),
    KnowledgeEntry("CWE-400", "Uncontrolled resource consumption", "An input can make the service consume excessive CPU, memory, connections, or storage.", ("dos", "rate-limit", "availability"), "CWE-400", "Apply bounded input sizes, timeouts, quotas, concurrency limits, and rate limiting.", _CWE + "400.html", "cve"),
    KnowledgeEntry("CWE-352", "Cross-site request forgery", "A browser can be induced to submit a state-changing request using a victim session.", ("csrf", "session", "browser"), "CWE-352", "Use anti-CSRF tokens or appropriate SameSite cookies and verify origin where practical.", _CWE + "352.html", "cve"),
)

_CVE_DETAIL_ENTRIES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("CVE-2021-44228", "Log4j JNDI lookup", "Public CVE teaching record for untrusted JNDI lookups in logging libraries. Not evidence that a local lab is affected.", ("cve", "jndi", "log4j", "rce"), "CWE-917", "Upgrade the logging library, disable JNDI lookups, and restrict outbound LDAP/RMI.", _CVE + "CVE-2021-44228", "cve"),
    KnowledgeEntry("CVE-2014-0160", "Heartbleed buffer over-read", "Public CVE teaching record for TLS heartbeat over-reads that can leak process memory. Not a lab finding.", ("cve", "tls", "heartbeat", "memory"), "CWE-119", "Patch OpenSSL, rotate exposed keys, and disable vulnerable heartbeat handling.", _CVE + "CVE-2014-0160", "cve"),
    KnowledgeEntry("CVE-2017-0144", "SMBv1 remote code execution", "Public CVE teaching record for the MS17-010 SMBv1 family used in EternalBlue discussions. Not a lab finding.", ("cve", "smb", "windows", "worm"), "CWE-119", "Disable SMBv1, apply the MS17-010 updates, and segment Windows administrative shares.", _CVE + "CVE-2017-0144", "cve"),
)

_TTP_ENTRIES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("T1190", "Exploit public-facing application", "ATT&CK TTP: initial access by abusing a reachable application flaw, matching the course recon-to-exploit chain.", ("attack", "ttp", "initial-access", "t1190"), "", "Patch public apps, put a WAF in front of teaching services, and keep labs loopback-only.", _ATTACK + "T1190/", "ttp"),
    KnowledgeEntry("T1059", "Command and script interpreter", "ATT&CK TTP: command execution through an interpreter. This harness only records simulated command intent and never opens a shell.", ("attack", "ttp", "execution", "t1059"), "CWE-78", "Avoid shell evaluation, pass argument arrays, and keep command tools on a diagnostic allowlist.", _ATTACK + "T1059/", "ttp"),
    KnowledgeEntry("T1021", "Remote services lateral movement", "ATT&CK TTP: moving between nodes with existing remote services. PostExploitAgent records this as simulated only.", ("attack", "ttp", "lateral-movement", "t1021"), "", "Segment internal-admin from the public edge and require a fresh session for each hop.", _ATTACK + "T1021/", "ttp"),
    KnowledgeEntry("T1005", "Data from local system", "ATT&CK TTP: reading local files such as an in-lab flag after a constrained identity check.", ("attack", "ttp", "collection", "t1005"), "", "Keep flags in the isolated lab, hash evidence, and do not copy host files.", _ATTACK + "T1005/", "ttp"),
)

_PAYLOAD_ENTRIES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("PAY-SQLITE-DIFF", "Authorized SQLite differential probe template", "Teaching payload template for the local training lab: a fixed baseline query, a fixed tautology probe, and a fixed contradiction probe. Custom payloads are rejected.", ("payload", "template", "sqlite", "differential"), "CWE-89", "Use this only against the authorized loopback lab; never send attacker-controlled SQL.", "lab/app.py", "payload"),
    KnowledgeEntry("PAY-XSS-REFLECT", "Reflected output encoding check template", "Teaching template that looks for reflected input without output encoding on /search. It is a marker check, not a browser exploit kit.", ("payload", "template", "xss", "encoding"), "CWE-79", "Context-encode reflected output and deploy a restrictive CSP.", "DemoLabAdapter /search", "payload"),
    KnowledgeEntry("PAY-AUTHZ-GET", "Missing authorization GET template", "Teaching template for an unauthenticated GET to /admin. The harness records the response; it does not brute-force credentials.", ("payload", "template", "authorization", "admin"), "CWE-862", "Require authentication and enforce server-side authorization on the route.", "DemoLabAdapter /admin", "payload"),
)

_STATIC_CASES: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry("CASE-DEMO-3FINDINGS", "Harness demo success case", "Completed demo scenario with three simulated findings: SQL syntax marker, reflected output, and missing authorization. Exploit stayed simulated; no payload left the process.", ("case", "demo", "success", "report"), "", "Keep demo evidence labeled simulated.", "out/*.md", "case"),
    KnowledgeEntry("CASE-LOCAL-SQLI", "Harness local-web success case", "Completed local-web scenario: baseline/positive/negative GET probes verified a SQLite differential on /search and stored SHA-256 hashes.", ("case", "local-web", "success", "verified"), "CWE-89", "Keep using parameterized queries in the repaired lab variant.", "out-local/*.md", "case"),
    KnowledgeEntry("CASE-COMPLEX-CHAIN", "Harness complex-web success case", "Completed complex-web chain: discover, verify, constrained shell identity uid=65532, and ground-truth flag match. Session reuse was in-lab only.", ("case", "complex-web", "success", "flag"), "CWE-89", "Keep internal-admin off the public edge.", "out-complex-web/*.md", "case"),
)


def _parse_success_case(path: Path) -> KnowledgeEntry | None:
    try:
        text = path.read_text(encoding="utf-8")[:2400]
    except OSError:
        return None
    if "Harness MVP Security Assessment" not in text:
        return None
    run_id = path.stem
    scenario_match = re.search(r"Scenario:\s+`([^`]+)`", text)
    status_match = re.search(r"Status:\s+\*\*([^*]+)\*\*", text)
    findings_match = re.search(r"Findings:\s+\*\*(\d+)\*\*", text)
    scenario = scenario_match.group(1) if scenario_match else "unknown"
    status = status_match.group(1).strip() if status_match else "unknown"
    finding_count = findings_match.group(1) if findings_match else "n/a"
    rel = path.as_posix()
    return KnowledgeEntry(
        f"CASE-FILE-{run_id}",
        f"Historical harness report {run_id}",
        f"Archived success-case report for scenario {scenario} with status {status} and {finding_count} findings. Source file {path.name}.",
        ("case", "report", "success", scenario.replace("-", "")),
        "",
        "Treat archived reports as retrieval examples, not new evidence against a live host.",
        rel,
        "case",
        {"run_id": run_id, "scenario": scenario, "status": status},
    )


def load_success_cases(workspace: Path | None = None, limit: int = 8) -> tuple[KnowledgeEntry, ...]:
    """Index a few historical Markdown reports as RAG success-case documents."""
    root = workspace or Path(__file__).resolve().parents[1]
    collected: list[KnowledgeEntry] = []
    seen: set[str] = set()
    directories = (
        "out",
        "out-local",
        "out-complex-web",
        "out-complex-web-docker",
        "out-course-upgrade",
    )
    for directory in directories:
        folder = root / directory
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.md")):
            if len(collected) >= limit:
                return tuple(collected)
            if path.stem in seen:
                continue
            entry = _parse_success_case(path)
            if entry is None:
                continue
            seen.add(path.stem)
            collected.append(entry)
    return tuple(collected)


DEFAULT_ENTRIES: tuple[KnowledgeEntry, ...] = (
    _CWE_ENTRIES
    + _CVE_DETAIL_ENTRIES
    + _TTP_ENTRIES
    + _PAYLOAD_ENTRIES
    + _STATIC_CASES
)


class KnowledgeBase:
    """In-memory TF-IDF index with deterministic cosine-similarity search."""

    def __init__(self, entries: Iterable[KnowledgeEntry] | None = None, *, include_report_cases: bool = True) -> None:
        bundled = DEFAULT_ENTRIES + (load_success_cases() if include_report_cases else ())
        self.entries = tuple(entries) if entries is not None else bundled
        self._documents = [self._document(entry) for entry in self.entries]
        self._idf = self._build_idf(self._documents)

    @staticmethod
    def _document(entry: KnowledgeEntry) -> list[str]:
        # Repeat the title to make labels useful while retaining a plain
        # token-based model that can be inspected and explained easily.
        return _tokens(" ".join((entry.title, entry.title, entry.text, entry.cwe, " ".join(entry.tags), entry.remediation, entry.category)))

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

    def search(self, query: str, limit: int = 3, category: str | None = None) -> list[KnowledgeEntry]:
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
        ranked = []
        for index, (document, entry) in enumerate(zip(self._documents, self.entries)):
            if category and entry.category != category:
                continue
            ranked.append((self._cosine(query_vector, self._vector(document)), index, entry))
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
                "category": entry.category,
                "retrieval": {
                    "method": "tf-idf-cosine",
                    "score": rounded_score,
                    "score_meaning": "Lexical cosine similarity in [0, 1]; not vulnerability confidence or proof.",
                    "matched_terms": sorted(set(query_tokens).intersection(self._documents[index])),
                },
            }))
        return results


__all__ = ["DEFAULT_ENTRIES", "KNOWLEDGE_CATEGORIES", "KnowledgeBase", "KnowledgeEntry", "load_success_cases"]
