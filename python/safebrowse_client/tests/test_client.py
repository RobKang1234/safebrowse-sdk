from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from safebrowse_client import SafeBrowseClient


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
