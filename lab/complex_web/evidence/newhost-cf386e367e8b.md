# Harness MVP Security Assessment

- Run: `cf386e367e8b`
- Target: `http://127.0.0.1:18089`
- Scenario: `complex-web`
- Status: **completed**
- Findings: **1**

## Findings

### F-001: SQLite SQL injection with session disclosure
- Severity: **high** | Confidence: `99%`
- Endpoint: `/search` | CWE: `CWE-89` | Source: `complex-web`
- Description: Controlled differential in the authorized multi-node complex-web lab leaked an internal session token.
- Evidence: `Baseline/public, fixed positive, and fixed negative GET probes diverged; the positive branch disclosed operator:lab-session-v1.`
- Remediation: Use parameterized SQLite queries, hide non-public rows, and keep internal-admin off the public edge.

- Validation: **verified**
- Evidence hashes: positive and negative response SHA-256 values are stored in the JSON report.

## Validation Results

`verified` means the bounded local training check observed the expected differential; `simulated` means no payload was sent; complex-web also records constrained shell identity and flag match.

```json
[
  {
    "finding_id": "F-001",
    "status": "verified",
    "message": "Fixed GET probes only: SQLi differential, constrained id identity, and ground-truth flag read.",
    "shell_obtained": true,
    "flag_match": true
  }
]
```

## Attack Chain Evidence

- Chain: `discover -> verify -> constrained-shell-identity -> read-flag`
- Shell identity: `uid=65532(labuser)`
- Flag match: **True**
- Flag: `FLAG{harness-complex-web-authorized-v1}`
- Flag SHA-256: `2ef099f042467dd8b0569655972062e41c15030e00c19ed265086f9b166cc74e`

## Task Tree

- `goal` parent=`root` agent=`operator`: complete attack-chain assessment
- `recon` parent=`goal` agent=`recon`: discover attack surface
- `code_audit` parent=`goal` agent=`code_audit`: static code audit
- `env_repro` parent=`goal` agent=`env_repro`: reproduce lab environment
- `vuln` parent=`goal` agent=`vuln`: analyze observations
- `exploit` parent=`goal` agent=`exploit`: validate in lab
- `post_exploit` parent=`goal` agent=`post_exploit`: simulate post-exploit movement
- `report` parent=`goal` agent=`report`: assemble report

## Operator Memory

- Operator: 协调智能体 Operator：接收各 Agent 汇报 → 综合 → 分配任务
- Current goal: `complete attack-chain assessment`
- Last action: `report`

## Agent Results

```json
[
  {
    "agent": "recon",
    "status": "success",
    "summary": "probed 8 lab endpoints",
    "data": {
      "responses": 8
    },
    "errors": [],
    "observations": [
      "/",
      "/login",
      "/search",
      "/admin",
      "/health",
      "/topology",
      "/internal/whoami",
      "/internal/flag"
    ]
  },
  {
    "agent": "code_audit",
    "status": "success",
    "summary": "scanned 1 lab source file(s); 0 tainted sink(s)",
    "data": {
      "method": "regex-sink-scan",
      "taint_model": "demo-skeleton",
      "files": [
        "lab/complex_web/server.py"
      ],
      "sink_count": 3,
      "tainted_count": 0,
      "sinks": [
        {
          "file": "lab/complex_web/server.py",
          "line": 80,
          "sink": "execute",
          "excerpt": "connection.execute(\"CREATE TABLE records (name TEXT, proof TEXT, visible INTEGER)\")",
          "tainted": false
        },
        {
          "file": "lab/complex_web/server.py",
          "line": 91,
          "sink": "execute",
          "excerpt": "connection.execute(",
          "tainted": false
        },
        {
          "file": "lab/complex_web/server.py",
          "line": 99,
          "sink": "execute",
          "excerpt": "return list(connection.execute(statement))",
          "tainted": false
        }
      ]
    },
    "errors": [],
    "observations": [
      "execute:lab/complex_web/server.py:80",
      "execute:lab/complex_web/server.py:91",
      "execute:lab/complex_web/server.py:99"
    ]
  },
  {
    "agent": "env_repro",
    "status": "success",
    "summary": "reproduced environment plan for complex-web-v1",
    "data": {
      "environment_id": "complex-web-v1",
      "classification": "local-real-complex-web",
      "target": "http://127.0.0.1:18089",
      "source_revision": "workspace-lab/complex_web",
      "start_command": "docker compose -f lab/complex_web/docker-compose.yml up -d --build",
      "reset_command": "docker compose -f lab/complex_web/docker-compose.yml down -v && docker compose -f lab/complex_web/docker-compose.yml up -d --build",
      "cleanup_command": "docker compose -f lab/complex_web/docker-compose.yml down -v",
      "success_criteria": [
        "Recon observes the public edge and the session-gated internal identity/flag routes",
        "Vulnerability agent records SQLite SQL injection from a controlled response differential",
        "Exploit agent uses the leaked classroom session to obtain the in-lab identity (uid=65532)",
        "Exploit agent reads FLAG{harness-complex-web-authorized-v1} from internal-admin and matches ground truth",
        "Report stores original request URLs, response excerpts, SHA-256 hashes, shell identity, and flag evidence"
      ],
      "manifest": "lab/complex_web/manifest.json",
      "steps": [
        "Start: docker compose -f lab/complex_web/docker-compose.yml up -d --build",
        "Reset: docker compose -f lab/complex_web/docker-compose.yml down -v && docker compose -f lab/complex_web/docker-compose.yml up -d --build",
        "Cleanup: docker compose -f lab/complex_web/docker-compose.yml down -v"
      ]
    },
    "errors": [],
    "observations": [
      "Start: docker compose -f lab/complex_web/docker-compose.yml up -d --build",
      "Reset: docker compose -f lab/complex_web/docker-compose.yml down -v && docker compose -f lab/complex_web/docker-compose.yml up -d --build",
      "Cleanup: docker compose -f lab/complex_web/docker-compose.yml down -v"
    ]
  },
  {
    "agent": "vuln",
    "status": "success",
    "summary": "identified 1 findings",
    "data": {
      "finding_ids": [
        "F-001"
      ]
    },
    "errors": [],
    "observations": [
      "SQLite SQL injection with session disclosure"
    ]
  },
  {
    "agent": "exploit",
    "status": "success",
    "summary": "validated verified for complex-web chain",
    "data": {
      "validated": 1,
      "status": "verified",
      "shell_obtained": true,
      "flag_match": true
    },
    "errors": [],
    "observations": []
  },
  {
    "agent": "post_exploit",
    "status": "success",
    "summary": "simulated app-api to internal-admin hop",
    "data": {
      "simulated": true,
      "executed": false,
      "boundary": "post-exploit is observational only; no shell, no nmap, no extra HTTP",
      "hops": [
        {
          "from": "app-api",
          "to": "internal-admin",
          "technique": "T1021",
          "status": "simulated",
          "message": "Would reuse the in-lab session toward internal-admin. Not executed by this agent."
        }
      ]
    },
    "errors": [],
    "observations": [
      "Would reuse the in-lab session toward internal-admin. Not executed by this agent."
    ]
  },
  {
    "agent": "report",
    "status": "success",
    "summary": "assembled auditable report",
    "data": {
      "finding_count": 1
    },
    "errors": [],
    "observations": []
  }
]
```

## Checkpoint

- Path: `E:\Desktop\xxq\xiaoxuqi\out-complex-web-newhost\.checkpoints\cf386e367e8b.json`
- Resumable: **True**

## Test Evidence

```json
{
  "chain": [
    "discover",
    "verify",
    "constrained-shell-identity",
    "read-flag"
  ],
  "classification": "local-real-complex-web",
  "shell_obtained": true,
  "shell_identity": "uid=65532(labuser)",
  "flag": "FLAG{harness-complex-web-authorized-v1}",
  "flag_match": true,
  "flag_sha256": "2ef099f042467dd8b0569655972062e41c15030e00c19ed265086f9b166cc74e",
  "session_token_seen": true
}
```
