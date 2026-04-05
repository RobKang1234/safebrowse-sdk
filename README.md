# SafeBrowse SDK

SafeBrowse is app-side security middleware for agents that browse pages, inspect artifacts, and call risky external systems. It sits between a planner and effectful sinks, then returns planner-safe observations, authority candidates, approval-bound execution plans, artifact verdicts, and replay evidence without owning the planner itself.

As of April 5, 2026:

- The canonical secure API in source is `/v6/*` under `secure_v6`.
- The latest published public release is [`v0.1.4`](releases/manifest.json).
- This `V6` branch is ahead of the latest public release.

## What Ships Here

- `@safebrowse/core`: TypeScript security runtime
- `@safebrowse/daemon`: localhost HTTP daemon
- `safebrowse-client`: thin Python client
- `@safebrowse/playwright-adapter`: reference payload builder for Playwright hosts
- KB tooling, release gates, parity tests, and internal assessment tooling

`@safebrowse/kb-tools`, the approval broker, and the private model-guard sidecar are repo components, but they are not all public publish surfaces.

## Secure V6 Contract

`secure_v6` is the claim-bearing runtime profile in the current source tree. It forces:

- parser isolation via `node_permission_process`
- external-service approval broker mode
- verified registry enforcement
- session-bound, digest-bound, non-replayable authorities
- planner-safe observations by default
- replay bundles with actor attribution

The daemon exposes:

- `POST /v6/session/start`
- `POST /v6/observe`
- `POST /v6/action/evaluate`
- `POST /v6/approval/issue`
- `POST /v6/tool/prepare`
- `POST /v6/tool/callback/verify`
- `POST /v6/artifact/ingest`
- `POST /v6/artifact/extract`
- `POST /v6/memory/stage`
- `POST /v6/memory/promote`
- `POST /v6/memory/rollback`
- `POST /v6/replay/bundle`
- `GET /health`

## Supported Secure Surfaces

The V6 runtime currently understands these capture and artifact surfaces:

- `html`
- `pdf`
- `image`
- `tool_manifest`
- `memory_candidate`
- `email_message`
- `docx`
- `xlsx`
- `pptx`
- `attachment_bundle`
- `external_api_response`

Direct raw binary ingestion is now supported for:

- `.eml`
- `.docx`
- `.xlsx`
- `.pptx`

That means callers can either provide already-extracted structured captures or send raw MIME / OOXML bytes as base64 on the V6 surface and let SafeBrowse materialize the secure capture before policy evaluation.

## Authority Model

The current authority system can mint or evaluate:

- `navigate`
- `connector_prepare`
- `memory_promote`
- `email_send`
- `email_reply`
- `email_forward`
- `api_read`
- `api_write`
- `api_delete`
- `api_export`

Authorities stay bound to the session, workflow step, provider or origin, operation class, target metadata, and source evidence digests. Connector, email, and API flows are approval-capable and non-replayable.

## Quick Start

### Daemon

```bash
npx @safebrowse/daemon \
  --host 127.0.0.1 \
  --port 8787 \
  --deployment-profile secure_v6 \
  --approval-broker-public-key-path ./knowledge_base/signing/safebrowse_vf_ed25519_public.pem
```

When `--deployment-profile secure_v6` is set, the daemon forces the strict broker and parser posture internally. You do not need to pass those flags again unless you want the startup command to be explicit.

### Python client

```bash
pip install safebrowse-client
```

```python
from safebrowse_client import SafeBrowseClient, build_email_surface_capture

client = SafeBrowseClient("http://127.0.0.1:8787")
session = client.start_session(
    {
        "taskId": "mail-review-1",
        "userGoal": "Inspect the message and stay read-only unless explicitly approved.",
        "allowedOrigins": ["https://mail.example.com"],
        "allowedVerbs": ["navigate", "email_reply", "api_read"],
    }
)

compiled = client.observe(
    {
        "sessionId": session["session"]["sessionId"],
        "capture": build_email_surface_capture(
            url="https://mail.example.com/message/123",
            provider_id="mail.example.com",
            subject="Quarterly report",
            body_text="Please review the attached workbook.",
            raw_mime_bytes=b"From: ...",
        ),
    }
)
```

### npm packages

```bash
npm install @safebrowse/core
npm install @safebrowse/daemon
npm install @safebrowse/playwright-adapter playwright-core
```

## Public Release State

The published public packages are tracked in [releases/manifest.json](releases/manifest.json). As of April 3, 2026, the latest published release is:

- Git tag: `v0.1.4`
- npm: `@safebrowse/core`, `@safebrowse/daemon`, `@safebrowse/playwright-adapter`
- PyPI: `safebrowse-client`
- GHCR: `ghcr.io/robkang1234/safebrowse-daemon`

This branch contains newer V6 functionality than `v0.1.4`. Do not assume every feature described in this branch README is already present in the latest published artifacts until the next release is cut.

## Internal Assessment vs External Audit

Repo-generated review output is labeled as an internal assessment, not an external audit opinion. The latest saved internal bundle lives under:

- [demo-output/latest/report.md](demo-output/latest/report.md)
- [demo-output/latest/internal-assessment.md](demo-output/latest/internal-assessment.md)

Those files are useful release evidence, but they are not a substitute for a separate external audit statement.

## Developer Commands

```bash
corepack pnpm install
corepack pnpm build
corepack pnpm test
corepack pnpm release:ready
```

Useful V6-specific gates:

- `corepack pnpm auditor:review:v6`
- `corepack pnpm auditor:parity:v6`
- `node scripts/ci/benchmark-daemon-routes.mjs --assert-thresholds`

## More Docs

- [RELEASING.md](RELEASING.md)
- [SECURITY.md](SECURITY.md)
- [packages/core/README.md](packages/core/README.md)
- [packages/daemon/README.md](packages/daemon/README.md)
- [packages/playwright-adapter/README.md](packages/playwright-adapter/README.md)
- [python/safebrowse_client/README.md](python/safebrowse_client/README.md)
