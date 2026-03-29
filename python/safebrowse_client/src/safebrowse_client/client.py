from __future__ import annotations

import json
from typing import Any
from urllib import request


class SafeBrowseClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8787", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def observe(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/observe", payload)

    def action(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/action", payload)

    def artifact(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/artifact", payload)

    def tool(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/tool", payload)

    def memory(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/memory", payload)

    def replay(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return self._post("/v1/replay", {"events": events})

