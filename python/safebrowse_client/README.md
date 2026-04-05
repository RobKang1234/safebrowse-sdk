# `safebrowse-client`

Thin Python client for the SafeBrowse localhost daemon.

The client is intentionally narrow: policy enforcement lives in the daemon, while this package provides convenient request helpers for the current `/v6/*` API surface.

## Install

```bash
pip install safebrowse-client
```

## What It Covers

- `GET /health`
- `POST /v6/session/start`
- `POST /v6/observe`
- `POST /v6/action/evaluate`
- `POST /v6/artifact/ingest`
- `POST /v6/artifact/extract`
- `POST /v6/approval/issue`
- `POST /v6/tool/prepare`
- `POST /v6/tool/callback/verify`
- `POST /v6/memory/stage`
- `POST /v6/memory/promote`
- `POST /v6/memory/rollback`
- `POST /v6/replay/bundle`

## Basic Example

```python
from safebrowse_client import SafeBrowseClient, build_html_surface_capture

client = SafeBrowseClient("http://127.0.0.1:8787")
session = client.start_session(
    {
        "taskId": "docs-review-1",
        "userGoal": "Read the page and stay read-only unless explicit authority is minted.",
        "allowedOrigins": ["https://docs.python.org"],
        "allowedVerbs": ["navigate", "api_read"],
    }
)

compiled = client.observe(
    {
        "sessionId": session["session"]["sessionId"],
        "capture": build_html_surface_capture(
            url="https://docs.python.org/3/",
            visible_text="Python 3 documentation home page",
            html="<main>Python 3 documentation home page</main>",
        ),
    }
)
```

## Raw Email and OOXML Helpers

The capture builders support either structured extracted fields or raw bytes:

- `build_email_surface_capture(..., raw_mime_bytes=...)`
- `build_docx_surface_capture(..., content_bytes=...)`
- `build_xlsx_surface_capture(..., content_bytes=...)`
- `build_pptx_surface_capture(..., content_bytes=...)`
- `build_external_api_surface_capture(...)`
- `build_attachment_bundle_surface_capture(...)`

Example:

```python
from safebrowse_client import build_email_surface_capture

capture = build_email_surface_capture(
    url="https://mail.example.com/message/123",
    provider_id="mail.example.com",
    subject="Quarterly report",
    body_text="Please review the attachment.",
    raw_mime_bytes=b"From: sender@example.com\r\nSubject: Quarterly report\r\n\r\nPlease review the attachment.",
)
```

## Model-Connected Browser Template

The wheel also includes a starter template:

```python
from safebrowse_client import write_model_connected_browser_agent_template

path = write_model_connected_browser_agent_template("model_connected_browser_agent.py")
print(path)
```

Repository:

- [https://github.com/RobKang1234/safebrowse-sdk](https://github.com/RobKang1234/safebrowse-sdk)
