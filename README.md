# SafeBrowse SDK

SafeBrowse is framework-only middleware for browser-use agents. It accepts typed observations, artifacts, tool proposals, and memory writes from external adapters, then returns typed verdicts, replay records, and guarded onboarding data without owning the planner itself.

This repository currently contains:

- A TypeScript core runtime
- A localhost HTTP daemon
- A thin Python client
- A Playwright reference adapter
- Policy and knowledge-base tooling
- A live threat lab and comparison dashboard

The current branch also includes the v2 hardening pass for connector and OAuth abuse observed in the live lab.

## What SafeBrowse Does

SafeBrowse is designed to sit between an agent and risky browser-adjacent surfaces:

- Page observations
- Downloaded artifacts
- Tool and connector onboarding
- OAuth callback handling
- Durable memory writes
- Replay and forensic logging

The runtime keeps the product boundary narrow:

- Adapters observe and propose actions
- SafeBrowse evaluates and constrains
- The planner or model stays external

## Main Features

- Deterministic observation sanitization for prompt-injection and provenance-aware page handling
- Action evaluation for unsafe navigation, write actions, and external sink attempts
- Artifact brokering with hidden-layer and mismatch detection
- Verified registry-backed connector preparation in v2
- Approval-bound onboarding sessions and callback verification in v2
- Artifact to tool taint propagation in v2
- Replay bundle creation with policy-layer provenance
- Local daemon routes for both compatibility (`/v1/*`) and hardened flows (`/v2/*`)
- Thin Python wrapper for daemon access
- Live comparison lab that runs a raw agent and an SDK-shielded agent against the same local model backend

## Repository Layout

- `packages/core`: runtime types, policy compilation, guards, replay
- `packages/daemon`: localhost HTTP server exposing the runtime
- `packages/kb-tools`: policy loading, KB loading, registry verification
- `packages/playwright-adapter`: reference adapter contract and tests
- `python/safebrowse_client`: thin Python client for the daemon
- `policies`: layered YAML policy inputs
- `knowledge_base`: raw KB packs and signing material
- `config`: signed adapter registry and regression fixtures
- `scripts/threat-demo`: comparison demo and live threat lab
- `docs`: development notes and historical v1 limitation writeup

## Core Functions

The TypeScript core exports the following primary runtime functions from [packages/core/src/index.ts](packages/core/src/index.ts):

| Function | Purpose |
| --- | --- |
| `sanitizeObservation` | Normalize and sanitize a raw page observation before planning continues. |
| `evaluateAction` | Evaluate a proposed action such as navigation or a risky sink transition. |
| `brokerArtifact` | Evaluate an artifact handoff for hidden text, mismatch signals, and quarantine decisions. |
| `brokerArtifactV2` | Evaluate an artifact and any follow-on tool request with lineage and taint propagation. |
| `evaluateToolRequest` | Legacy v1 tool evaluation path kept for compatibility. |
| `prepareToolOnboarding` | Hardened v2 tool preparation using the verified registry, approval requirements, and callback policy. |
| `verifyToolCallback` | Verify a v2 OAuth callback against a prepared onboarding session. |
| `evaluateMemoryWrite` | Evaluate durable and non-durable memory writes. |
| `compilePolicy` | Compile layered policy packs into deterministic runtime policy. |
| `buildReplayBundle` | Build replayable forensic bundles from runtime events. |

## Daemon Routes

The localhost daemon in [packages/daemon/src/server.ts](packages/daemon/src/server.ts) exposes:

| Route | Purpose |
| --- | --- |
| `POST /v1/observe` | Observation sanitization |
| `POST /v1/action` | Action evaluation |
| `POST /v1/artifact` | Legacy artifact brokering |
| `POST /v1/tool` | Legacy tool evaluation |
| `POST /v1/memory` | Memory write evaluation |
| `POST /v1/replay` | Replay bundle creation |
| `POST /v2/tool/prepare` | Verified registry-based onboarding preparation |
| `POST /v2/tool/callback/verify` | Approval and state-bound callback verification |
| `POST /v2/artifact` | Artifact evaluation with follow-on tool lineage |
| `GET /health` | Runtime profile, policy provenance, and verified registry metadata |

## User Manual

### 1. Prerequisites

- Node `22+`
- `pnpm` via `corepack`
- Python `3.12+`

### 2. Install dependencies

```powershell
corepack pnpm install
```

### 3. Build the repository

```powershell
corepack pnpm build
```

### 4. Run tests

```powershell
corepack pnpm test
```

### 5. Start the daemon

```powershell
node packages/daemon/dist/index.js
```

The default daemon address is `http://127.0.0.1:8787`.

### 6. Use the Python client

```python
from safebrowse_client import SafeBrowseClient

client = SafeBrowseClient("http://127.0.0.1:8787")

observe_result = client.observe({
    "text": "Summarize this page",
    "trustSignals": {
        "sourceOrigin": "https://safe.example",
        "frameOrigin": "https://safe.example"
    }
})

prepare_result = client.tool_prepare({
    "requestId": "tool-1",
    "toolId": "citation-sync-safe",
    "registryEntryId": "citation-sync-safe",
    "description": "Citation sync connector for scholarly cross-reference enrichment.",
    "authType": "oauth",
    "requestedRedirectUri": "https://safe.example/oauth/callback",
    "callbackUri": "https://safe.example/oauth/callback",
    "callbackOrigin": "https://safe.example",
    "requestedScopes": ["citation:read"],
    "approvalBindingId": "approval-1"
})
```

### 7. Use the daemon directly

Example v2 tool preparation:

```powershell
curl -X POST http://127.0.0.1:8787/v2/tool/prepare ^
  -H "Content-Type: application/json" ^
  -d "{\"requestId\":\"tool-1\",\"toolId\":\"citation-sync-safe\",\"registryEntryId\":\"citation-sync-safe\",\"description\":\"Citation sync connector for scholarly cross-reference enrichment.\",\"authType\":\"oauth\",\"requestedRedirectUri\":\"https://safe.example/oauth/callback\",\"callbackUri\":\"https://safe.example/oauth/callback\",\"callbackOrigin\":\"https://safe.example\",\"requestedScopes\":[\"citation:read\"],\"approvalBindingId\":\"approval-1\"}"
```

### 8. Run the comparison demo

```powershell
corepack pnpm demo:compare
```

Artifacts are written under `demo-output/latest`.

### 9. Run the live threat lab

```powershell
corepack pnpm demo:watch-live
```

The live lab:

- Serves a dashboard
- Generates hostile local threat pages
- Runs a raw agent and an SDK-shielded agent against the same model backend when available
- Logs decisions, sink hits, and comparison output

### 10. Read the live output

The most useful outputs are:

- `demo-output/live-watch/report.html`
- `demo-output/live-watch/report.md`
- `demo-output/live-watch/state.json`
- `demo-output/live-watch/events.ndjson`
- `demo-output/live-watch/sink-hits.json`

## Current v2 Hardening

The v2 work in this repository closes the compromised connector families observed in the live lab by adding:

- Signed local registry loading and signature verification
- Exact registry entry resolution
- Manifest and schema hash comparison
- Exact redirect and callback-origin verification
- Approval-bound onboarding preparation
- Callback verification with state binding
- Artifact-derived tool taint propagation
- Per-layer policy provenance in replay data and health metadata

In the current live model-backed lab, the raw agent and the SafeBrowse-protected agent use the same local Qwen backend. The raw agent is compromised on the connector abuse families, while the SDK path is currently blocking them.

## Limitations

SafeBrowse is much stronger in v2, but this repository still has important limitations:

- The live lab is a local threat simulation, not a full production browser isolation system.
- Durable memory snapshot and rollback are still surfaced as runtime constraints rather than fully persisted storage operations.
- The nightly evaluation story is still lighter than the full long-term plan. BrowserGym and AgentDojo-style coverage are not yet fully wired into release-grade CI.
- The `/v1/*` routes are preserved for compatibility and do not provide the same connector safeguards as the hardened `/v2/*` flow.
- The current live threat lab focuses on adversarial cases, so the positive allow-path for connector onboarding is mainly covered by unit and daemon tests rather than a long-running benign OAuth demo.

## Documentation

- Historical v1 note: [docs/v1-limitations-and-model-backed-evaluation.md](docs/v1-limitations-and-model-backed-evaluation.md)
- Development source plan: [docs/safebrowse_sdk_vf_development_plan.docx](docs/safebrowse_sdk_vf_development_plan.docx)

## Recommended Workflow

For normal development:

1. Update policy or KB inputs as needed.
2. Run `corepack pnpm test`.
3. Run `corepack pnpm build`.
4. Run `corepack pnpm demo:compare` for a snapshot.
5. Run `corepack pnpm demo:watch-live` for model-backed observation and regression hunting.

SafeBrowse is most useful when it is evaluated against the same agent backend with and without the middleware in front of it. That is the default comparison model used in this repo.
