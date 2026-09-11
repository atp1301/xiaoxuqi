from __future__ import annotations

import json
import mimetypes
import os
import threading
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from .exploitgym import ExploitGymAdapter
from .knowledge import DEFAULT_ENTRIES, KnowledgeBase
from .labs import check_labs
from .models import RunState
from .orchestrator import Orchestrator
from .policy import PolicyEngine, PolicyViolation, parse_target
from .services import (
    check_system_health,
    start_local_services,
    run_goad_requirement_test,
    run_exploitgym_requirement_test,
    run_complex_web_requirement_test,
)


MAX_REQUEST_BODY = 64 * 1024
MAX_ACTIVE_RUNS = 4
MAX_KNOWLEDGE_QUERY = 200
STEP_NAMES = ("recon", "code_audit", "env_repro", "vuln", "exploit", "post_exploit", "report")
STATIC_ROOT = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": "console.html",
    "/static/console.css": "console.css",
    "/static/console.js": "console.js",
}


@dataclass
class _RunRecord:
    run_id: str
    target: str
    scenario: str
    output_dir: str
    status: str = "queued"
    state: RunState | None = None
    errors: list[str] = field(default_factory=list)
    steps: list[dict[str, str]] = field(
        default_factory=lambda: [{"name": name, "agent": name, "status": "queued"} for name in STEP_NAMES]
    )
    thread: threading.Thread | None = None


def _completed_steps(state: RunState) -> list[dict[str, str]]:
    statuses = {result.agent: result.status.value for result in state.agent_results}
    return [{"name": name, "agent": name, "status": statuses.get(name, "queued")} for name in STEP_NAMES]


def _progress_from_record(record: "_RunRecord") -> dict[str, Any]:
    steps = [dict(step) for step in record.steps]
    tree = [
        {
            "step_id": "goal",
            "parent_id": None,
            "name": "complete attack-chain assessment",
            "agent": "operator",
            "status": record.status if record.status not in {"queued"} else "pending",
            "depends_on": [],
        }
    ]
    for step in steps:
        tree.append(
            {
                "step_id": step.get("step_id") or step.get("agent"),
                "parent_id": step.get("parent_id") or "goal",
                "name": step.get("name") or step.get("agent"),
                "agent": step.get("agent"),
                "status": step.get("status"),
                "depends_on": list(step.get("depends_on") or []),
            }
        )
    completed = sum(1 for step in steps if step.get("status") in {"success", "skipped"})
    return {
        "steps": steps,
        "tree": tree,
        "completed": completed,
        "total": len(STEP_NAMES),
        "operator": "协调智能体 Operator：接收各 Agent 汇报 → 综合 → 分配任务",
    }


def build_catalog() -> dict[str, Any]:
    return {
        "product": "Harness MVP Console",
        "bind": "loopback-only",
        "capabilities": [
            {
                "title": "Demo 场景",
                "summary": "离线确定性演示，产出 3 条模拟发现与报告，不访问真实服务。",
                "status": "可用",
            },
            {
                "title": "Local Web 半真实验证",
                "summary": "对本机训练服务做 baseline/正向/负向差分，验证固定 SQLite SQLi。",
                "status": "可用",
            },
            {
                "title": "Complex Web multi-node lab",
                "summary": "Gateway + app-api + internal-admin: discover, verify, constrained identity, ground-truth flag.",
                "status": "available",
            },
            {
                "title": "Checkpoint 恢复",
                "summary": "CLI 可用 --resume 从断点继续；控制台展示运行状态与报告。",
                "status": "CLI 可用",
            },
            {
                "title": "知识库 TF-IDF",
                "summary": f"四类 RAG：CVE/CWE、ATT&CK TTP、Payload 模板、成功案例，共 {len(DEFAULT_ENTRIES)}+ 条。",
                "status": "可用",
            },
            {
                "title": "靶场只读检查",
                "summary": "检查 Docker、local-web、GOAD、ExploitGym、Vulhub 是否配置/可达。",
                "status": "只读",
            },
            {
                "title": "ExploitGym 适配器",
                "summary": "检查本地 checkout 与任务 ID 是否在清单中，不运行 benchmark。",
                "status": "只读",
            },
        ],
        "agents": [
            {"name": "operator", "label": "协调者", "summary": "接收各 Agent 汇报，综合观察后分配下一步任务。", "role": "coordinator"},
            {"name": "recon", "label": "侦察", "summary": "探测固定训练路径，记录响应摘要与哈希。"},
            {"name": "code_audit", "label": "代码审计", "summary": "对实验源码做 sink 正则扫描和演示级污点骨架。"},
            {"name": "env_repro", "label": "环境复现", "summary": "读取 lab/manifest.json 的启动/重置/清理命令。"},
            {"name": "vuln", "label": "漏洞分析", "summary": "识别 Demo 标记或 local-web 差分特征，并关联知识库。"},
            {"name": "exploit", "label": "验证", "summary": "Demo 模拟验证；local-web 用固定探针输出 verified/failed。"},
            {"name": "post_exploit", "label": "横向移动", "summary": "只记录 simulated 后渗透跳转，不执行命令。"},
            {"name": "report", "label": "报告", "summary": "生成可审计 JSON/Markdown 报告。"},
        ],
        "scenarios": [
            {"id": "demo", "target_example": "demo.local", "kind": "simulated"},
            {"id": "local-web", "target_example": "http://127.0.0.1:18088", "kind": "local-real-training"},
            {"id": "complex-web", "target_example": "http://127.0.0.1:18089", "kind": "local-real-complex-web"},
        ],
        "apis": [
            "GET /api/catalog",
            "GET /api/labs",
            "GET /api/knowledge?q=&limit=",
            "GET /api/exploitgym?task_id=",
            "GET /api/runs",
            "POST /api/runs",
            "GET /api/runs/{id}",
            "GET /api/runs/{id}/progress",
            "GET /api/runs/{id}/report",
            "GET /api/tools",
            "GET /api/services/health",
            "POST /api/services/start",
            "GET /api/tests/goad",
            "GET /api/tests/exploitgym",
            "GET /api/tests/complex-web",
            "POST /api/tests/goad",
            "POST /api/tests/exploitgym",
        ],
        "safety": [
            "只绑定 127.0.0.1 / localhost / ::1",
            "目标必须通过 PolicyEngine 白名单",
            "不接受任意攻击载荷，不读取宿主文件",
            "输出目录不能跳出 dashboard output root",
            "ExploitGym / GOAD / Vulhub 检查均为只读，不启动环境",
        ],
    }


class DashboardHandler(BaseHTTPRequestHandler):
    runs: dict[str, _RunRecord] = {}
    output_dir = Path("out")
    output_root = Path("out").resolve()
    lock = threading.RLock()
    knowledge = KnowledgeBase()

    def _send(self, status: int, body: bytes | str, content_type: str = "application/json") -> None:
        encoded = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False, default=str, indent=2))

    def _send_static(self, relative_name: str) -> None:
        candidate = (STATIC_ROOT / relative_name).resolve()
        if not candidate.is_file() or not candidate.is_relative_to(STATIC_ROOT):
            self._send_json(404, {"error": "static asset not found"})
            return
        content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        self._send(200, candidate.read_bytes(), content_type)

    @classmethod
    def _resolve_output(cls, requested: object) -> str:
        root = Path(cls.output_root).resolve()
        if requested is None or requested == "":
            return str(root)
        if not isinstance(requested, str):
            raise ValueError("output must be a relative directory path")
        value = requested.strip()
        if not value:
            return str(root)
        if value == "out" and root.name.lower() == "out":
            return str(root)
        windows = PureWindowsPath(value)
        if Path(value).is_absolute() or windows.is_absolute() or bool(windows.drive):
            raise ValueError("output must be a relative directory path")
        if any(part == ".." for part in value.replace("\\", "/").split("/")):
            raise ValueError("output must not contain '..'")
        candidate = (root / Path(value)).resolve()
        try:
            if os.path.commonpath((str(root), str(candidate))) != str(root):
                raise ValueError
        except ValueError as exc:
            raise ValueError("output is outside the dashboard output root") from exc
        return str(candidate)

    @classmethod
    def _payload(cls, record: _RunRecord) -> dict[str, Any]:
        with cls.lock:
            payload: dict[str, Any] = {
                "run_id": record.run_id,
                "status": record.status,
                "target": record.target,
                "scenario": record.scenario,
                "progress": _progress_from_record(record),
                "errors": list(record.errors),
                "report_url": f"/api/runs/{record.run_id}/report",
            }
            if record.state is None:
                return payload
            state_payload = record.state.to_dict()
            state_payload["orchestrator_run_id"] = state_payload.get("run_id")
            state_payload["run_id"] = record.run_id
            state_payload["status"] = record.status
            state_payload["progress"] = payload["progress"]
            state_payload["report_url"] = payload["report_url"]
            if record.errors:
                state_payload["errors"] = list(state_payload.get("errors", [])) + list(record.errors)
            return state_payload

    @classmethod
    def _run_summaries(cls) -> list[dict[str, Any]]:
        with cls.lock:
            return [
                {
                    "run_id": record.run_id,
                    "status": record.status,
                    "target": record.target,
                    "scenario": record.scenario,
                    "finding_count": 0 if record.state is None else len(record.state.findings),
                }
                for record in cls.runs.values()
            ]

    @classmethod
    def _active_count(cls) -> int:
        return sum(1 for record in cls.runs.values() if record.status in {"queued", "running"})

    @classmethod
    def _worker(cls, record: _RunRecord) -> None:
        def progress(state: RunState, steps: list[dict[str, Any]]) -> None:
            with cls.lock:
                record.state = state
                record.status = state.status.value
                record.steps = [
                    {
                        "name": str(item.get("name", item.get("agent", ""))),
                        "agent": str(item.get("agent", "")),
                        "step_id": str(item.get("step_id", item.get("agent", ""))),
                        "parent_id": item.get("parent_id") or "goal",
                        "depends_on": list(item.get("depends_on") or []),
                        "status": str(item.get("status", "queued")),
                    }
                    for item in steps
                ]

        with cls.lock:
            record.status = "running"
            record.steps[0]["status"] = "running"
        try:
            state = Orchestrator(mode="deterministic").run(
                record.target,
                record.scenario,
                record.output_dir,
                progress_callback=progress,
                run_id=record.run_id,
            )
            with cls.lock:
                record.state = state
                record.status = state.status.value
                record.steps = _completed_steps(state)
        except Exception as exc:
            with cls.lock:
                record.status = "failed"
                record.errors.append(str(exc))
                for step in record.steps:
                    if step["status"] == "running":
                        step["status"] = "failed"
                        break
        finally:
            with cls.lock:
                record.thread = None

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in STATIC_FILES:
            self._send_static(STATIC_FILES[path])
            return
        if path == "/api/catalog":
            self._send_json(200, build_catalog())
            return
        if path == "/api/labs":
            self._send_json(200, {"labs": [asdict(item) for item in check_labs()]})
            return
        if path == "/api/services/health":
            self._send_json(200, check_system_health())
            return
        if path == "/api/tests/goad":
            self._send_json(200, run_goad_requirement_test())
            return
        if path == "/api/tests/exploitgym":
            self._send_json(200, run_exploitgym_requirement_test())
            return
        if path == "/api/tests/complex-web":
            self._send_json(200, run_complex_web_requirement_test())
            return
        if path == "/api/knowledge":
            raw_query = (query.get("q") or [""])[0]
            if len(raw_query) > MAX_KNOWLEDGE_QUERY:
                self._send_json(400, {"error": "query is too long"})
                return
            try:
                limit = int((query.get("limit") or ["5"])[0])
            except ValueError:
                self._send_json(400, {"error": "limit must be an integer"})
                return
            limit = max(1, min(limit, 10))
            category = (query.get("category") or [None])[0]
            if category == "":
                category = None
            results = []
            for entry in self.knowledge.search(raw_query, limit=limit, category=category):
                results.append(
                    {
                        "entry_id": entry.entry_id,
                        "title": entry.title,
                        "text": entry.text,
                        "cwe": entry.cwe,
                        "category": entry.category,
                        "remediation": entry.remediation,
                        "source": entry.source,
                        "tags": list(entry.tags),
                        "score": entry.score,
                        "retrieval": entry.metadata.get("retrieval"),
                    }
                )
            self._send_json(200, {"query": raw_query, "results": results})
            return
        if path == "/api/exploitgym":
            task_id = (query.get("task_id") or ["v8:sbxbrk/398773898"])[0].strip()
            if not task_id or len(task_id) > 120:
                self._send_json(400, {"error": "task_id is invalid"})
                return
            self._send_json(200, ExploitGymAdapter().check(task_id))
            return
        if path == "/api/runs":
            self._send_json(200, {"runs": self._run_summaries()})
            return
        if path == "/api/tools":
            from .tools import list_tools
            tools = [
                {
                    "name": item.name,
                    "category": item.category,
                    "description": item.description,
                    "required_permission": item.required_permission,
                    "status": item.status,
                }
                for item in list_tools()
            ]
            self._send_json(200, {"tools": tools})
            return

        parts = path.strip("/").split("/")
        if len(parts) not in (3, 4) or parts[:2] != ["api", "runs"]:
            self._send_json(404, {"error": "route not found"})
            return
        with self.lock:
            record = self.runs.get(parts[2])
        if record is None:
            self._send_json(404, {"error": "run not found"})
            return
        if len(parts) == 3:
            self._send_json(200, self._payload(record))
            return
        if parts[3] == "progress":
            self._send_json(200, {"run_id": record.run_id, "status": record.status, **_progress_from_record(record)})
            return
        if parts[3] != "report":
            self._send_json(404, {"error": "route not found"})
            return
        with self.lock:
            state, status = record.state, record.status
        if state is None or status not in {"completed", "failed"}:
            self._send_json(202, {"error": "report not ready", "status": status})
            return
        report_path = state.report_paths.get("markdown")
        if not report_path:
            self._send_json(404, {"error": "report unavailable"})
            return
        try:
            root, candidate = Path(self.output_root).resolve(), Path(report_path).resolve()
            if os.path.commonpath((str(root), str(candidate))) != str(root) or not candidate.is_file():
                raise ValueError
            content = candidate.read_text(encoding="utf-8")
        except (OSError, ValueError):
            self._send_json(404, {"error": "report unavailable"})
            return
        self._send(200, content, "text/markdown")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlparse(self.path).path
        if path not in {"/api/runs", "/api/services/start", "/api/tests/goad", "/api/tests/exploitgym"}:
            self._send_json(404, {"error": "route not found"})
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send_json(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                self._send_json(411, {"error": "Content-Length is required"})
                return
            length = int(length_header)
            if length < 0:
                raise ValueError("Content-Length is invalid")
            if length > MAX_REQUEST_BODY:
                try:
                    self.rfile.read(min(length, 65536))
                except Exception:
                    pass
                self.close_connection = True
                self._send_json(413, {"error": "request body is too large"})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("request body is truncated")
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        if path == "/api/services/start":
            role = payload.get("role", "all")
            if not isinstance(role, str):
                role = "all"
            self._send_json(200, start_local_services(role))
            return

        if path == "/api/tests/goad":
            self._send_json(200, run_goad_requirement_test())
            return

        if path == "/api/tests/exploitgym":
            self._send_json(200, run_exploitgym_requirement_test())
            return

        try:
            target, scenario = payload.get("target", "demo.local"), payload.get("scenario", "demo")
            if not isinstance(target, str) or not isinstance(scenario, str):
                raise ValueError("target and scenario must be strings")
            if scenario not in {"demo", "local-web", "complex-web"}:
                raise ValueError("unsupported scenario")
            PolicyEngine().require_target(parse_target(target))
            output_dir = self._resolve_output(payload.get("output"))
        except (ValueError, TypeError, PolicyViolation) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        record = _RunRecord(uuid4().hex[:12], target, scenario, output_dir)
        worker = threading.Thread(
            target=self._worker,
            args=(record,),
            name=f"dashboard-run-{record.run_id}",
            daemon=True,
        )
        record.thread = worker
        with self.lock:
            if self._active_count() >= MAX_ACTIVE_RUNS:
                self._send_json(429, {"error": "too many active runs"})
                return
            self.runs[record.run_id] = record
        try:
            self._send_json(202, self._payload(record))
        finally:
            worker.start()

    def log_message(self, format: str, *args: Any) -> None:
        return


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    output_dir: str = "out",
    initial_state: RunState | None = None,
) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("dashboard must bind to a loopback host")
    DashboardHandler.output_dir = Path(output_dir)
    DashboardHandler.output_root = Path(output_dir).resolve()
    if initial_state:
        record = _RunRecord(
            initial_state.run_id,
            initial_state.target.address,
            initial_state.scenario,
            str(DashboardHandler.output_root),
            initial_state.status.value,
            initial_state,
            [],
            _completed_steps(initial_state),
        )
        with DashboardHandler.lock:
            DashboardHandler.runs[initial_state.run_id] = record
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard: http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
