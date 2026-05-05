from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .runtime import ModelGuardRuntime


class _ModelGuardRequestHandler(BaseHTTPRequestHandler):
    runtime: ModelGuardRuntime

    def _json_response(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"
        return json.loads(body.decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json_response(self.runtime.health())
            return
        self._json_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/score/observation":
            self._json_response(self.runtime.score_observation(self._read_json()))
            return
        if self.path == "/v1/score/batch":
            payload = self._read_json()
            requests = payload.get("requests", [])
            self._json_response(self.runtime.score_batch(requests))
            return
        self._json_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def create_model_guard_server(
    bundle_dir: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8788,
) -> ThreadingHTTPServer:
    runtime = ModelGuardRuntime(bundle_dir)
    handler = type("BoundModelGuardRequestHandler", (_ModelGuardRequestHandler,), {"runtime": runtime})
    server = ThreadingHTTPServer((host, port), handler)
    return server
