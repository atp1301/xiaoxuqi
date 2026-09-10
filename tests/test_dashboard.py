import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from harness_mvp.dashboard import DashboardHandler, MAX_REQUEST_BODY


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        DashboardHandler.runs = {}
        DashboardHandler.output_root = Path(self.tmp.name).resolve()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.tmp.cleanup()

    def wait_for_run(self, run_id, timeout=30.0):
        """Poll a queued run until it reaches a terminal state.

        The budget is deliberately generous: a demo run writes ~23 fsynced
        checkpoints, and on hosts with a real-time AV file filter each write
        is rescanned, stretching a 0.6s in-process run past 4s. The wait is
        widened, but the terminal state is still asserted by the caller.
        """
        deadline = time.monotonic() + timeout
        state = {"status": "queued"}
        while time.monotonic() < deadline:
            _, state = self.request(f"/api/runs/{run_id}")
            if state["status"] in {"completed", "failed"}:
                break
            time.sleep(0.05)
        return state

    def request(self, path, payload=None, content_type="application/json"):
        data = None if payload is None else (payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        req = Request(self.base + path, data=data, headers={"Content-Type": content_type} if data is not None else {}, method="POST" if data is not None else "GET")
        try:
            with urlopen(req, timeout=5) as response:
                body = response.read().decode()
                ctype = response.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    return response.status, json.loads(body)
                return response.status, body
        except HTTPError as exc:
            body = exc.read().decode()
            exc.close()
            return exc.code, json.loads(body)

    def test_console_page_and_catalog_are_readable(self):
        status, page = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("Harness MVP 控制台", page)
        status, catalog = self.request("/api/catalog")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(catalog["capabilities"]), 4)
        self.assertEqual(len(catalog["agents"]), 8)

    def test_labs_and_knowledge_endpoints(self):
        status, labs = self.request("/api/labs")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["lab_id"] == "docker" for item in labs["labs"]))
        status, knowledge = self.request("/api/knowledge?q=SQL%20injection&limit=3")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(knowledge["results"]), 1)
        status, eg = self.request("/api/exploitgym?task_id=v8:sbxbrk/398773898")
        self.assertEqual(status, 200)
        self.assertEqual(eg["benchmark_status"], "external-benchmark-pending")

    def test_post_is_queued_then_completes_and_report_is_readable(self):
        status, queued = self.request("/api/runs", {"target": "demo.local", "scenario": "demo", "output": "out"})
        self.assertEqual(status, 202); self.assertIn(queued["status"], {"queued", "running"})
        run_id = queued["run_id"]
        state = self.wait_for_run(run_id)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(len(state["findings"]), 3)
        report_status, report = self.request(f"/api/runs/{run_id}/report")
        self.assertEqual(report_status, 200)
        self.assertIn("Harness MVP Security Assessment", report if isinstance(report, str) else "")
        list_status, listing = self.request("/api/runs")
        self.assertEqual(list_status, 200)
        self.assertTrue(any(item["run_id"] == run_id for item in listing["runs"]))

    def test_content_type_and_body_limits(self):
        self.assertEqual(self.request("/api/runs", b"{}", "text/plain")[0], 415)
        oversized = b"{" + b"x" * (MAX_REQUEST_BODY + 1) + b"}"
        self.assertEqual(self.request("/api/runs", oversized)[0], 413)

    def test_post_requires_content_length(self):
        import socket
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2) as sock:
            sock.sendall(("POST /api/runs HTTP/1.1\r\nHost: localhost\r\n"
                          "Content-Type: application/json\r\nConnection: close\r\n\r\n{}").encode())
            response = sock.recv(4096).decode("latin1")
        self.assertIn("411", response.split("\r\n", 1)[0])

    def test_output_must_stay_under_root(self):
        self.assertEqual(self.request("/api/runs", {"output": "../escape"})[0], 400)
        self.assertEqual(self.request("/api/runs", {"output": str(Path(self.tmp.name) / "absolute")})[0], 400)

    def test_progress_and_tools_endpoints(self):
        status, queued = self.request("/api/runs", {"target": "demo.local", "scenario": "demo"})
        self.assertEqual(status, 202)
        run_id = queued["run_id"]
        state = self.wait_for_run(run_id)
        self.assertEqual(state["status"], "completed")
        progress_status, progress = self.request(f"/api/runs/{run_id}/progress")
        self.assertEqual(progress_status, 200)
        self.assertEqual(progress["total"], 7)
        agents = [node["agent"] for node in progress["tree"]]
        self.assertEqual(agents[0], "operator")
        self.assertIn("code_audit", agents)
        self.assertIn("post_exploit", agents)
        tools_status, tools = self.request("/api/tools")
        self.assertEqual(tools_status, 200)
        names = {item["name"] for item in tools["tools"]}
        self.assertIn("recon_probe", names)
        self.assertIn("nmap_scan", names)
        stubs = [item for item in tools["tools"] if item["status"] == "stub"]
        self.assertGreaterEqual(len(stubs), 3)


if __name__ == "__main__":
    unittest.main()
