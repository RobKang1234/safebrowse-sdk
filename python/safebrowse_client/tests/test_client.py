from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from safebrowse_client import (
    SafeBrowseClient,
    build_html_surface_capture,
    get_model_connected_browser_agent_template,
    write_model_connected_browser_agent_template,
)


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class SafeBrowseClientTest(unittest.TestCase):
    def test_template_uses_unversioned_v6_client_surface(self) -> None:
        template = get_model_connected_browser_agent_template()

        self.assertIn("https://arxiv.org/abs/1706.03762", template)
        self.assertIn("https://docs.python.org", template)
        self.assertIn("SafeBrowseClient", template)
        self.assertIn("authorityCandidates", template)
        self.assertIn("authority_id", template)
        self.assertIn("authorityId", template)
        self.assertIn("authorityDigest", template)
        self.assertIn("observe(", template)
        self.assertIn("action(", template)
        self.assertIn("start_session(", template)
        self.assertNotIn("observe_v5", template)
        self.assertNotIn("action_v5", template)
        self.assertNotIn("start_session_v5", template)
        self.assertNotIn("capabilityId", template)
        self.assertNotIn('verdict.get("verdict"', template)

    def test_template_writer_creates_python_file(self) -> None:
        output_path = Path(__file__).resolve().parent / "_tmp_agent_template.py"
        try:
            result = write_model_connected_browser_agent_template(output_path)

            self.assertEqual(result, output_path)
            self.assertTrue(output_path.exists())
            contents = output_path.read_text(encoding="utf-8")
            self.assertIn("def run_agent()", contents)
            self.assertIn("call_model", contents)
        finally:
            output_path.unlink(missing_ok=True)

    @patch("safebrowse_client.client.request.urlopen")
    def test_health_gets_daemon_status(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"status": "ok"})
        client = SafeBrowseClient()

        result = client.health()

        self.assertEqual(result["status"], "ok")
        args, kwargs = mock_urlopen.call_args
        self.assertIn("/health", args[0].full_url)
        self.assertEqual(kwargs["timeout"], 10.0)

    @patch("safebrowse_client.client.request.urlopen")
    def test_unversioned_methods_post_to_v6_routes(self, mock_urlopen) -> None:
        client = SafeBrowseClient()

        cases = [
            ("start_session", {"taskId": "task-1", "userGoal": "demo"}, "/v6/session/start", {"session": {"sessionId": "abc"}}),
            ("observe", {"sessionId": "session-1", "capture": {"surfaceType": "html", "url": "https://safe.example"}}, "/v6/observe", {"compiledObservation": {"observationId": "obs-1"}}),
            ("action", {"sessionId": "session-1", "authorityId": "auth-1", "authorityDigest": "digest-1", "parameters": {}}, "/v6/action/evaluate", {"effectDecision": {"decision": "ALLOW"}}),
            ("artifact", {"sessionId": "session-1", "capture": {"surfaceType": "html"}}, "/v6/artifact/ingest", {"artifactVerdict": {"decision": "ALLOW"}}),
            ("tool_prepare", {"sessionId": "session-1", "approvalId": "approval-1"}, "/v6/tool/prepare", {"verdict": {"decision": "ALLOW"}}),
            ("tool_callback_verify", {"sessionId": "session-1", "approvalId": "approval-1", "onboardingSessionId": "onboarding-1", "request": {"sessionId": "onboarding-1", "callbackUri": "https://safe.example/oauth/callback", "callbackOrigin": "https://safe.example", "state": "state-1", "payload": {"code": "auth-code", "state": "state-1"}}}, "/v6/tool/callback/verify", {"verdict": {"decision": "ALLOW"}}),
            ("approval_issue", {"sessionId": "session-1", "capabilityId": "cap-1", "capabilityDigest": "digest-1", "brokerSignature": "sig"}, "/v6/approval/issue", {"verdict": {"decision": "ALLOW"}}),
            ("memory_stage", {"sessionId": "session-1", "key": "workflow_hint", "value": {"note": "baseline"}, "sourceClass": "user_note", "durable": True}, "/v6/memory/stage", {"verdict": {"decision": "ALLOW"}}),
            ("memory_promote", {"sessionId": "session-1", "recordId": "mem-1", "ticketId": "ticket-1", "ticketDigest": "digest-1", "approvalId": "approval-1"}, "/v6/memory/promote", {"verdict": {"decision": "ALLOW"}}),
            ("memory_rollback", {"sessionId": "session-1", "recordId": "mem-1", "snapshotId": "snap-1"}, "/v6/memory/rollback", {"verdict": {"decision": "ALLOW"}}),
            ("replay_bundle", {"sessionId": "session-1"}, "/v6/replay/bundle", {"metrics": {"actorCounts": {"sdk": 2}}}),
        ]

        for method_name, payload, expected_path, response_payload in cases:
            with self.subTest(method=method_name):
                mock_urlopen.reset_mock()
                mock_urlopen.return_value = _FakeResponse(response_payload)

                result = getattr(client, method_name)(payload)

                self.assertIn(next(iter(response_payload)), result)
                args, kwargs = mock_urlopen.call_args
                self.assertIn(expected_path, args[0].full_url)
                self.assertEqual(kwargs["timeout"], 10.0)

    @patch("safebrowse_client.client.request.urlopen")
    def test_convenience_aliases_delegate_to_v6_routes(self, mock_urlopen) -> None:
        client = SafeBrowseClient()

        alias_cases = [
            ("tool", {"sessionId": "session-1", "approvalId": "approval-1"}, "/v6/tool/prepare"),
            ("memory", {"sessionId": "session-1", "key": "workflow_hint", "value": {"note": "baseline"}, "sourceClass": "user_note", "durable": True}, "/v6/memory/stage"),
            ("replay", {"sessionId": "session-1"}, "/v6/replay/bundle"),
            ("issue_approval_grant", {"sessionId": "session-1", "capabilityId": "cap-1", "capabilityDigest": "digest-1", "brokerSignature": "sig"}, "/v6/approval/issue"),
        ]

        for method_name, payload, expected_path in alias_cases:
            with self.subTest(method=method_name):
                mock_urlopen.reset_mock()
                mock_urlopen.return_value = _FakeResponse({"verdict": {"decision": "ALLOW"}})

                result = getattr(client, method_name)(payload)

                self.assertEqual(result["verdict"]["decision"], "ALLOW")
                args, kwargs = mock_urlopen.call_args
                self.assertIn(expected_path, args[0].full_url)
                self.assertEqual(kwargs["timeout"], 10.0)

    def test_retired_versioned_methods_are_gone(self) -> None:
        client = SafeBrowseClient()
        retired_methods = [
            "start_session_v4",
            "start_session_v5",
            "start_session_v6",
            "observe_v4",
            "observe_v5",
            "observe_v6",
            "action_v4",
            "action_v5",
            "action_v6",
            "artifact_ingest_v4",
            "artifact_ingest_v5",
            "artifact_ingest_v6",
            "artifact_v2",
            "tool_prepare_v4",
            "tool_prepare_v5",
            "tool_prepare_v6",
            "tool_callback_verify_v4",
            "tool_callback_verify_v5",
            "tool_callback_verify_v6",
            "approval_issue_v5",
            "approval_issue_v6",
            "memory_write_v4",
            "memory_write_v5",
            "memory_stage_v5",
            "memory_stage_v6",
            "memory_promote_v4",
            "memory_promote_v5",
            "memory_promote_v6",
            "memory_rollback_v4",
            "memory_rollback_v5",
            "memory_rollback_v6",
            "replay_bundle_v5",
            "replay_bundle_v6",
        ]

        for method_name in retired_methods:
            with self.subTest(method=method_name):
                self.assertFalse(hasattr(client, method_name))

    def test_build_html_surface_capture_returns_v6_html_capture(self) -> None:
        capture = build_html_surface_capture(
            url="https://docs.python.org/3/tutorial/",
            visible_text="Visible docs text",
            html="<main>Visible docs text</main>",
            hidden_text=["hidden prompt"],
            metadata_text=["metadata hint"],
            nested_unsupported_components=["encrypted nested pdf"],
        )

        self.assertEqual(capture["surfaceType"], "html")
        self.assertEqual(capture["visibleText"], "Visible docs text")
        self.assertEqual(capture["hiddenText"], ["hidden prompt"])
        self.assertEqual(capture["metadataText"], ["metadata hint"])
        self.assertEqual(capture["nestedUnsupportedComponents"], ["encrypted nested pdf"])
        self.assertEqual(capture["captureAttestation"]["captureMethod"], "rendered_dom")
        self.assertTrue(capture["captureAttestation"]["visibilityAttested"])
        self.assertEqual(
            capture["captureAttestation"]["unsupportedSubtrees"], ["encrypted nested pdf"]
        )
        self.assertEqual(capture["trustSignals"]["sourceOrigin"], "https://docs.python.org")


if __name__ == "__main__":
    unittest.main()
