"""Multi-node authorized training lab used by the complex-web scenario.

Topology:
  edge-gateway  ->  app-api (records / SQLi classroom probe)
                ->  internal-admin (session-gated identity + flag)

The lab only accepts fixed classroom GET probes from the harness. It does not
expose a general command shell or arbitrary payload interface.
"""
from __future__ import annotations

import argparse
import html
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

try:
    from .constants import (
        ADMIN_URL_ENV,
        APP_URL_ENV,
        DEFAULT_FLAG,
        FLAG_ENV,
        FLAG_FILE_ENV,
        HIDDEN_NAME,
        HIDDEN_PROOF,
        LAB_NAME,
        LAB_VERSION,
        OPERATOR_NAME,
        PUBLIC_NAME,
        PUBLIC_PROOF,
        SESSION_TOKEN,
    )
except ImportError:  # running as /app/server.py inside the image
    from constants import (
        ADMIN_URL_ENV,
        APP_URL_ENV,
        DEFAULT_FLAG,
        FLAG_ENV,
        FLAG_FILE_ENV,
        HIDDEN_NAME,
        HIDDEN_PROOF,
        LAB_NAME,
        LAB_VERSION,
        OPERATOR_NAME,
        PUBLIC_NAME,
        PUBLIC_PROOF,
        SESSION_TOKEN,
    )


def load_flag() -> str:
    raw = os.environ.get(FLAG_ENV, "").strip()
    if raw:
        return raw
    configured = os.environ.get(FLAG_FILE_ENV, "").strip()
    path = Path(configured) if configured else Path(__file__).with_name("flag.txt")
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return DEFAULT_FLAG
    return text or DEFAULT_FLAG


def _html(body: str) -> bytes:
    return f"<html><title>Complex Web Lab</title><body>{body}</body></html>".encode()


def _search(query: str, fixed: bool = False) -> list[tuple[str, str]]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE records (name TEXT, proof TEXT, visible INTEGER)")
        connection.executemany(
            "INSERT INTO records VALUES (?, ?, ?)",
            [
                (PUBLIC_NAME, PUBLIC_PROOF, 1),
                (OPERATOR_NAME, SESSION_TOKEN, 0),
                (HIDDEN_NAME, HIDDEN_PROOF, 0),
            ],
        )
        if fixed:
            return list(
                connection.execute(
                    "SELECT name, proof FROM records WHERE name = ? AND visible = 1",
                    (query,),
                )
            )
        statement = (
            "SELECT name, proof FROM records WHERE name = '" + query + "' AND visible = 1"
        )
        return list(connection.execute(statement))
    finally:
        connection.close()


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return


class AppHandler(_QuietHandler):
    fixed = False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/search":
            query = params.get("q", [PUBLIC_NAME])[0]
            try:
                if len(query) > 128:
                    raise sqlite3.DataError("training input too long")
                rows = _search(query, fixed=self.fixed)
                listing = ", ".join(
                    f"{html.escape(name)}:{html.escape(proof)}" for name, proof in rows
                )
                body = f"Search results ({len(rows)}): {listing}"
                status = 200
            except sqlite3.Error:
                body, status = "search rejected", 400
        elif parsed.path == "/health":
            body, status = "ok", 200
        else:
            body, status = "app-api ready", 200
        self._write(status, body, extra={"X-Lab-Node": "app-api"})

    def _write(self, status: int, body: str, extra: dict[str, str] | None = None) -> None:
        payload = _html(body)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Training-Lab", LAB_NAME)
        self.send_header("X-Training-Lab-Version", LAB_VERSION)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


class AdminHandler(_QuietHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        session = self.headers.get("X-Lab-Session", "")
        if parsed.path == "/health":
            self._write(200, "ok", extra={"X-Lab-Node": "internal-admin"})
            return
        if session != SESSION_TOKEN:
            self._write(401, "session required", extra={"X-Lab-Node": "internal-admin"})
            return
        if parsed.path in {"/whoami", "/exec"}:
            params = parse_qs(parsed.query, keep_blank_values=True)
            if parsed.path == "/exec":
                command = params.get("cmd", [""])[0]
                if command != "id":
                    self._write(400, "command is not in the lab allowlist", extra={"X-Lab-Node": "internal-admin"})
                    return
            body = (
                "uid=65532(labuser) gid=65532(labuser) groups=65532(labuser) "
                "tty=lab-console host=internal-admin"
            )
            self._write(200, body, extra={"X-Lab-Node": "internal-admin"})
            return
        if parsed.path == "/flag":
            self._write(200, load_flag(), extra={"X-Lab-Node": "internal-admin"})
            return
        self._write(404, "not found", extra={"X-Lab-Node": "internal-admin"})

    def _write(self, status: int, body: str, extra: dict[str, str] | None = None) -> None:
        payload = _html(body)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Training-Lab", LAB_NAME)
        self.send_header("X-Training-Lab-Version", LAB_VERSION)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


class GatewayHandler(_QuietHandler):
    app_url = os.environ.get(APP_URL_ENV, "http://127.0.0.1:18090")
    admin_url = os.environ.get(ADMIN_URL_ENV, "http://127.0.0.1:18091")
    timeout = 1.5

    _LOCAL = {
        "/": (200, "Complex Web Lab | edge-gateway | authorized local assessment only"),
        "/login": (200, "Login form"),
        "/admin": (200, "Admin panel | public edge only"),
        "/health": (200, "ok"),
        "/topology": (
            200,
            "nodes=edge-gateway,app-api,internal-admin network=labnet flag_store=internal-admin",
        ),
    }

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/search":
            self._proxy(self.app_url, self.path, node="app-api")
            return
        if parsed.path in {"/internal/whoami", "/internal/exec", "/internal/flag"}:
            upstream_path = parsed.path[len("/internal"):] + (("?" + parsed.query) if parsed.query else "")
            headers = {}
            session = self.headers.get("X-Lab-Session", "")
            if session:
                headers["X-Lab-Session"] = session
            self._proxy(self.admin_url, upstream_path, node="internal-admin", extra_headers=headers)
            return
        status, body = self._LOCAL.get(parsed.path, (404, "not found"))
        self._write(status, body, extra={"X-Lab-Node": "edge-gateway"})

    def _proxy(
        self,
        base: str,
        path: str,
        node: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        url = base.rstrip("/") + path
        headers = {"User-Agent": "complex-web-gateway/1", "X-Harness-Client": "harness-mvp"}
        headers.update(extra_headers or {})
        request = Request(url, method="GET", headers=headers)
        opener = build_opener(ProxyHandler({}))
        try:
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(16385)
                status = response.status
                upstream_headers = dict(response.headers.items())
        except HTTPError as exc:
            with exc:
                body = exc.read(16385)
                status = exc.code
                upstream_headers = dict(exc.headers.items()) if exc.headers else {}
        except (URLError, TimeoutError, OSError):
            self._write(502, f"upstream {node} unavailable", extra={"X-Lab-Node": "edge-gateway"})
            return
        if len(body) > 16384:
            self._write(502, "upstream body too large", extra={"X-Lab-Node": "edge-gateway"})
            return
        extra = {
            "X-Lab-Node": "edge-gateway",
            "X-Lab-Upstream": node,
            "X-Lab-Upstream-Status": str(status),
        }
        node_header = {key.lower(): value for key, value in upstream_headers.items()}.get("x-lab-node")
        if node_header:
            extra["X-Lab-Upstream-Node"] = node_header
        self._write_bytes(status, body, extra=extra)

    def _write(self, status: int, body: str, extra: dict[str, str] | None = None) -> None:
        self._write_bytes(status, _html(body), extra=extra)

    def _write_bytes(self, status: int, payload: bytes, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Training-Lab", LAB_NAME)
        self.send_header("X-Training-Lab-Version", LAB_VERSION)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


def _serve(handler: type[BaseHTTPRequestHandler], host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.thread = thread  # type: ignore[attr-defined]
    return server


@dataclass
class ComplexWebLab:
    gateway_url: str
    app_url: str
    admin_url: str
    _servers: tuple[ThreadingHTTPServer, ...]

    def close(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for server in self._servers:
            thread = getattr(server, "thread", None)
            if thread is not None:
                thread.join(timeout=2)


def start_lab(
    host: str = "127.0.0.1",
    gateway_port: int = 0,
    app_port: int = 0,
    admin_port: int = 0,
    fixed: bool = False,
) -> ComplexWebLab:
    AppHandler.fixed = fixed
    admin = _serve(AdminHandler, host, admin_port)
    app = _serve(AppHandler, host, app_port)
    GatewayHandler.app_url = f"http://{host}:{app.server_address[1]}"
    GatewayHandler.admin_url = f"http://{host}:{admin.server_address[1]}"
    gateway = _serve(GatewayHandler, host, gateway_port)
    return ComplexWebLab(
        gateway_url=f"http://{host}:{gateway.server_address[1]}",
        app_url=f"http://{host}:{app.server_address[1]}",
        admin_url=f"http://{host}:{admin.server_address[1]}",
        _servers=(admin, app, gateway),
    )


@contextmanager
def running_lab(**kwargs: object) -> Iterator[ComplexWebLab]:
    previous_fixed = AppHandler.fixed
    previous_app = GatewayHandler.app_url
    previous_admin = GatewayHandler.admin_url
    lab = start_lab(**kwargs)  # type: ignore[arg-type]
    try:
        yield lab
    finally:
        lab.close()
        AppHandler.fixed = previous_fixed
        GatewayHandler.app_url = previous_app
        GatewayHandler.admin_url = previous_admin


def _run_single(handler: type[BaseHTTPRequestHandler], host: str, port: int, label: str) -> int:
    server = ThreadingHTTPServer((host, port), handler)
    print(f"{label} listening on http://{host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorized complex-web training lab")
    parser.add_argument("role", nargs="?", choices=["gateway", "app", "admin", "all"], default="all")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18089)
    parser.add_argument("--app-port", type=int, default=18090)
    parser.add_argument("--admin-port", type=int, default=18091)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args(argv)
    AppHandler.fixed = args.fixed
    if args.role == "app":
        return _run_single(AppHandler, args.host, args.port if args.port != 18089 else 8080, "app-api")
    if args.role == "admin":
        return _run_single(AdminHandler, args.host, args.port if args.port != 18089 else 8081, "internal-admin")
    if args.role == "gateway":
        GatewayHandler.app_url = os.environ.get(APP_URL_ENV, GatewayHandler.app_url)
        GatewayHandler.admin_url = os.environ.get(ADMIN_URL_ENV, GatewayHandler.admin_url)
        return _run_single(GatewayHandler, args.host, args.port, "edge-gateway")
    lab = start_lab(args.host, args.port, args.app_port, args.admin_port, fixed=args.fixed)
    print(f"complex web lab listening on {lab.gateway_url}")
    print(f"app-api {lab.app_url} | internal-admin {lab.admin_url}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        return 0
    finally:
        lab.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
