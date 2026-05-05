from __future__ import annotations

import json
from typing import Any
from urllib import request


class SafeBrowseClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8787", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, path: str) -> dict[str, Any]:
        req = request.Request(f"{self.base_url}{path}", method="GET")
        with request.urlopen(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

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

    def _post_v6(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"/v6{path}", payload)

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def start_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/session/start", payload)

    def observe(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/observe", payload)

    def action(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/action/evaluate", payload)

    def artifact(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/artifact/ingest", payload)

    def artifact_extract(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/artifact/extract", payload)

    def tool(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.tool_prepare(payload)

    def tool_prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/tool/prepare", payload)

    def tool_callback_verify(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/tool/callback/verify", payload)

    def issue_approval_grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.approval_issue(payload)

    def approval_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/approval/issue", payload)

    def memory(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.memory_stage(payload)

    def memory_stage(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/memory/stage", payload)

    def memory_promote(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/memory/promote", payload)

    def memory_rollback(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/memory/rollback", payload)

    def replay(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.replay_bundle(payload)

    def replay_bundle(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post_v6("/replay/bundle", payload)

    def extract(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.artifact_extract(payload)
