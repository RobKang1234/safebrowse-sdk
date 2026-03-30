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

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def start_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/session/start", payload)

    def start_session_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/session/start", payload)

    def observe(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/observe", payload)

    def observe_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/observe", payload)

    def observe_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/observe", payload)

    def action(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/action", payload)

    def action_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/action/evaluate", payload)

    def action_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/capability/use", payload)

    def artifact(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/artifact", payload)

    def artifact_ingest_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/artifact/ingest", payload)

    def artifact_ingest_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/artifact/ingest", payload)

    def tool(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/tool", payload)

    def tool_prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v2/tool/prepare", payload)

    def tool_prepare_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/tool/prepare", payload)

    def tool_prepare_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/tool/prepare", payload)

    def tool_callback_verify(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v2/tool/callback/verify", payload)

    def tool_callback_verify_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/tool/callback/verify", payload)

    def tool_callback_verify_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/tool/callback/verify", payload)

    def issue_approval_grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/approval/grant", payload)

    def issue_approval_envelope_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/approval/issue", payload)

    def memory(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/memory", payload)

    def memory_write_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/memory/write", payload)

    def memory_write_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/memory/write", payload)

    def memory_promote_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/memory/promote", payload)

    def memory_promote_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/memory/promote", payload)

    def memory_rollback_v4(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v4/memory/rollback", payload)

    def memory_rollback_v5(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v5/memory/rollback", payload)

    def artifact_v2(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v2/artifact", payload)

    def replay(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return self._post("/v1/replay", {"events": events})

