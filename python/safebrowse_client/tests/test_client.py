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
    def test_template_contains_external_site_example(self) -> None:
        template = get_model_connected_browser_agent_template()

        self.assertIn("https://arxiv.org/abs/1706.03762", template)
        self.assertIn("https://docs.python.org", template)
        self.assertIn("SafeBrowseClient", template)
        self.assertIn("use_capability", template)
        self.assertIn("build_html_surface_capture", template)
        self.assertIn("observe_v5", template)
        self.assertIn("action_v5", template)

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
    def test_observe_posts_to_daemon(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"decision": "ALLOW"})
        client = SafeBrowseClient()

        result = client.observe({"text": "hello"})

        self.assertEqual(result["decision"], "ALLOW")
        args, kwargs = mock_urlopen.call_args
        self.assertIn("/v1/observe", args[0].full_url)
        self.assertEqual(kwargs["timeout"], 10.0)

    @patch("safebrowse_client.client.request.urlopen")
    def test_start_session_posts_to_v4_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"session": {"sessionId": "abc"}})
        client = SafeBrowseClient()

        result = client.start_session({"taskId": "task-1", "userGoal": "demo"})

        self.assertEqual(result["session"]["sessionId"], "abc")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v4/session/start", args[0].full_url)

    @patch("safebrowse_client.client.request.urlopen")
    def test_observe_v4_posts_to_v4_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"compiledObservation": {"observationId": "obs-1"}})
        client = SafeBrowseClient()

        result = client.observe_v4({"sessionId": "session-1", "capture": {"surfaceType": "html", "url": "https://safe.example"}})

        self.assertEqual(result["compiledObservation"]["observationId"], "obs-1")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v4/observe", args[0].full_url)

    @patch("safebrowse_client.client.request.urlopen")
    def test_observe_v5_posts_to_v5_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"compiledObservation": {"observationId": "obs-5"}})
        client = SafeBrowseClient()

        result = client.observe_v5({"sessionId": "session-1", "capture": {"surfaceType": "html", "url": "https://safe.example"}})

        self.assertEqual(result["compiledObservation"]["observationId"], "obs-5")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v5/observe", args[0].full_url)

    @patch("safebrowse_client.client.request.urlopen")
    def test_memory_rollback_v4_posts_to_v4_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"verdict": {"decision": "ALLOW"}})
        client = SafeBrowseClient()

        result = client.memory_rollback_v4(
            {"sessionId": "session-1", "recordId": "mem-1", "snapshotId": "snap-1"}
        )

        self.assertEqual(result["verdict"]["decision"], "ALLOW")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v4/memory/rollback", args[0].full_url)

    @patch("safebrowse_client.client.request.urlopen")
    def test_memory_rollback_v5_posts_to_v5_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"verdict": {"decision": "ALLOW"}})
        client = SafeBrowseClient()

        result = client.memory_rollback_v5(
            {"sessionId": "session-1", "recordId": "mem-1", "snapshotId": "snap-1"}
        )

        self.assertEqual(result["verdict"]["decision"], "ALLOW")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v5/memory/rollback", args[0].full_url)

    def test_build_html_surface_capture_returns_v4_shape(self) -> None:
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
        self.assertEqual(
            capture["nestedUnsupportedComponents"], ["encrypted nested pdf"]
        )
        self.assertEqual(
            capture["trustSignals"]["sourceOrigin"], "https://docs.python.org"
        )

    @patch("safebrowse_client.client.request.urlopen")
    def test_replay_wraps_events_payload(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"bundleId": "123"})
        client = SafeBrowseClient()

        result = client.replay([{"eventId": "evt-1"}])

        self.assertEqual(result["bundleId"], "123")
        args, _kwargs = mock_urlopen.call_args
        body = json.loads(args[0].data.decode("utf-8"))
        self.assertEqual(body, {"events": [{"eventId": "evt-1"}]})

    @patch("safebrowse_client.client.request.urlopen")
    def test_tool_prepare_posts_to_v2_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"verdict": {"decision": "BLOCK"}})
        client = SafeBrowseClient()

        result = client.tool_prepare({"toolId": "citation-sync-safe"})

        self.assertEqual(result["verdict"]["decision"], "BLOCK")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v2/tool/prepare", args[0].full_url)

    @patch("safebrowse_client.client.request.urlopen")
    def test_artifact_v2_posts_to_v2_route(self, mock_urlopen) -> None:
        mock_urlopen.return_value = _FakeResponse({"verdict": {"decision": "ALLOW"}})
        client = SafeBrowseClient()

        result = client.artifact_v2({"mimeType": "application/pdf"})

        self.assertEqual(result["verdict"]["decision"], "ALLOW")
        args, _kwargs = mock_urlopen.call_args
        self.assertIn("/v2/artifact", args[0].full_url)


if __name__ == "__main__":
    unittest.main()
