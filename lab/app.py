"""Tiny local SQLite training service for the authorized course lab."""
from __future__ import annotations
import argparse
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

def _search(q: str, fixed: bool = False) -> list[tuple[str, str]]:
    """Compare deliberate string concatenation with a parameterized repair.

    All records are fictional; the connection is recreated in memory per GET.
    Ordinary lookups only return public records, including for name='alice'.
    """
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE records (name TEXT, proof TEXT, visible INTEGER)")
        connection.executemany("INSERT INTO records VALUES (?, ?, ?)", [
            ("course", "public-training-record", 1),
            ("alice", "course-proof-sqli-v1", 0),
        ])
        if fixed:
            return list(connection.execute(
                "SELECT name, proof FROM records WHERE name = ? AND visible = 1", (q,)
            ))
        # Intentional CWE-89 for this loopback classroom service only.
        statement = "SELECT name, proof FROM records WHERE name = '" + q + "' AND visible = 1"
        return list(connection.execute(statement))
    finally:
        connection.close()

class Handler(BaseHTTPRequestHandler):
    fixed = False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/search":
            query = params.get("q", ["course"])[0]
            try:
                if len(query) > 128:
                    raise sqlite3.DataError("training input too long")
                rows = _search(query, fixed=self.fixed)
                body = "Search results ({}): {}".format(len(rows), ", ".join(f"{html.escape(name)}:{html.escape(proof)}" for name, proof in rows))
                status = 200
            except sqlite3.Error:
                body, status = "search rejected", 400
        else:
            routes = {"/": (200, "Training Web Lab | authorized local assessment only"), "/login": (200, "Login form"), "/admin": (200, "Admin panel"), "/health": (200, "ok")}
            status, body = routes.get(path, (404, "not found"))
        payload = f"<html><title>Local Training Lab</title><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Training-Lab", "harness-mvp")
        self.send_header("X-Training-Lab-Version", "sqlite-sqli-v1")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        return

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--fixed", action="store_true", help="use parameterized SQL for remediation comparison")
    args = parser.parse_args()
    Handler.fixed = args.fixed
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"training lab listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
