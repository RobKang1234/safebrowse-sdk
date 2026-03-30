# SafeBrowse SDK

SafeBrowse is app-side security middleware for browser-use agents. It sits on the action path between an agent and risky external surfaces, then returns structured decisions, capability-bound execution plans, replay data, and guarded connector flows without owning the planner itself.

The current claim-bearing path is `/v4/*`: for supported surfaces, untrusted content may affect extraction or summaries, but it should not be able to cause unauthorized effects such as fresh navigation targets, secret exposure, connector onboarding, durable trusted-state mutation, or outbound data flow without explicit authorization.

## What Ships Here

- A TypeScript core runtime
- A localhost HTTP daemon
- A thin Python client
- A Playwright reference adapter
- Policy and knowledge-base tooling
- A model-backed threat lab, wrapper-parity gate, and auditor-review pipeline

## Public Surfaces

| Surface | Name | Purpose |
| --- | --- | --- |
| PyPI | `safebrowse-client` | Thin Python client for the daemon |
| npm | `@safebrowse/core` | Core runtime library |
| npm | `@safebrowse/daemon` | Installable daemon package with `safebrowse-daemon` |
| npm | `@safebrowse/playwright-adapter` | Reference adapter package |
| GHCR | `ghcr.io/robkang1234/safebrowse-daemon` | Containerized daemon image |

`@safebrowse/kb-tools` remains internal-only.

## Current V4 Boundary

The V4 path is built around:

- Server-owned observation compilation
- Parser isolation for supported capture formats
- Session-bound, non-replayable capability minting
- Approval-envelope-bound connector onboarding
- Tiered memory authority separation
- System-wide secret redaction and noninterference checks
- Wrapper parity across direct, Python, and npm-installed execution paths

Supported V4 claim surfaces:

- HTML and DOM captures
- PDFs
- Tool manifests
- OAuth and connector flows
- Images and OCR
- Memory

Unsupported or partially parsed surfaces fail closed and are outside the prevention claim.

## Latest Auditor-Backed Results

The latest full model-backed auditor run is preserved in [demo-output/latest/report.html](demo-output/latest/report.html), [demo-output/latest/report.md](demo-output/latest/report.md), [demo-output/latest/summary.json](demo-output/latest/summary.json), [demo-output/latest/auditor-opinion.md](demo-output/latest/auditor-opinion.md), and [demo-output/latest/auditor-opinion.json](demo-output/latest/auditor-opinion.json).

As of March 30, 2026, against the repo-pinned auditor corpus in [config/auditor/v4_prompt_injection_coverage_suite.json](config/auditor/v4_prompt_injection_coverage_suite.json):

- Total cases: `29`
- Deterministic raw compromises: `25`
- Raw Qwen compromises: `2`
- SDK compromises: `0`
- SDK expectation passes: `28`
- SDK expectation fails: `0`
- Auditor verdict: `qualified_positive_with_open_approximations`

The remaining non-pass is one benign baseline approximation (`TC27`), because the model chose the safe path on planner-safe input. There are currently no unresolved parity gaps and no observed unauthorized-effect escapes on the supported V4 corpus.

## What "Fully Tested" Means Here

In this repository, "fully tested" now means more than unit tests passing.

For the supported V4 prevention surface, the same hostile and benign cases are checked through:

- The direct daemon path
- The installed Python wrapper and generated template path
- The npm-installed daemon and adapter path

Those three paths must agree on the normalized claim-relevant outputs:

- Parse status
- Planner-safe visible excerpt and structured facts
- Quoted untrusted blocks
- Risk markers and blocked channels
- Candidate capability kinds
- Final verdict decision and reason codes

That parity gate runs through [scripts/ci/run-wrapper-parity.mjs](scripts/ci/run-wrapper-parity.mjs). The full auditor review run is driven by [scripts/threat-demo/run-auditor-suite.ts](scripts/threat-demo/run-auditor-suite.ts).

## Quick Install

### Daemon

```bash
npx @safebrowse/daemon --host 127.0.0.1 --port 8787
```

### Python client

```bash
pip install safebrowse-client
```

### npm libraries

```bash
npm install @safebrowse/core
npm install @safebrowse/playwright-adapter playwright-core
```

### Docker

```bash
docker run --rm -p 8787:8787 ghcr.io/robkang1234/safebrowse-daemon:latest
```

## Recommended V4 Flow

### 1. Start a session

```python
from safebrowse_client import SafeBrowseClient

client = SafeBrowseClient("http://127.0.0.1:8787")

session = client.start_session(
    {
        "taskId": "vendor-review-1",
        "userGoal": "Review the page and stay read-only unless an explicitly granted capability says otherwise.",
        "allowedOrigins": ["https://docs.python.org", "https://arxiv.org"],
        "allowedVerbs": ["navigate", "summarize"]
    }
)
```

### 2. Compile an observation

```python
compiled = client.observe_v4(
    {
        "sessionId": session["session"]["sessionId"],
        "capture": {
            "surfaceType": "html",
            "url": "https://docs.python.org/3/",
            "visibleText": "Python 3 documentation home page ...",
            "hiddenText": [],
            "metadataText": []
        }
    }
)
```

### 3. Let the model choose only from minted capabilities

```python
planner_input = compiled["plannerInput"]
capabilities = planner_input["candidateCapabilities"]

selected = capabilities[0]
result = client.action_v4(
    {
        "sessionId": session["session"]["sessionId"],
        "capabilityId": selected["capabilityId"],
        "parameters": {}
    }
)
```

The model does not get to invent a new URL, selector, callback URI, or sink. It may only choose from server-minted capabilities bound to the session, workflow step, origin, target class, parameter schema, and source evidence.

### 4. Use the packaged starter template

The Python package also ships a model-connected browser template helper:

```python
from safebrowse_client import write_model_connected_browser_agent_template

write_model_connected_browser_agent_template("model_connected_browser_agent.py")
```

## Core Runtime Functions

The main runtime entrypoints exported from [packages/core/src/index.ts](packages/core/src/index.ts) are:

| Function | Purpose |
| --- | --- |
| `compileObservation` | Compile a supported surface into a provenance-aware observation and planner-safe view |
| `mintCapabilitiesForObservation` | Mint session-bound, non-replayable capabilities from compiled evidence |
| `evaluateCapabilityUse` | Enforce capability-bound action execution |
| `prepareToolOnboardingV4` | Enforce registry-backed, approval-envelope-bound connector preparation |
| `verifyToolCallbackV4` | Verify V4 callback state, origin, and payload fields |
| `evaluateMemoryWriteV4` | Place memory into trusted, candidate, or tainted tiers |
| `promoteMemoryRecordV4` | Promote candidate memory into trusted durable state with approval or validation |
| `rollbackMemoryRecordV4` | Restore a trusted snapshot after contradiction or operator action |
| `assertNoSecretsInJson` | Enforce secret noninterference for JSON payloads |
| `buildReplayBundle` | Build replayable forensic bundles from runtime events |

Legacy `v1` and transitional `v2` functions remain exported for compatibility, but they are not part of the V4 prevention claim.

## Daemon Routes

The localhost daemon in [packages/daemon/src/server.ts](packages/daemon/src/server.ts) exposes:

| Route | Purpose |
| --- | --- |
| `POST /v4/session/start` | Start a server-owned task session |
| `POST /v4/observe` | Compile a supported surface into a planner-safe observation |
| `POST /v4/action/evaluate` | Evaluate a single capability use |
| `POST /v4/approval/grant` | Issue an approval envelope for exact connector or sink use |
| `POST /v4/tool/prepare` | Prepare a brokered connector or OAuth flow |
| `POST /v4/tool/callback/verify` | Verify callback origin, state, scope, and allowlisted fields |
| `POST /v4/artifact/ingest` | Ingest an artifact under the V4 fail-closed path |
| `POST /v4/memory/write` | Write candidate or tainted memory records |
| `POST /v4/memory/promote` | Promote memory into trusted durable state |
| `POST /v4/memory/rollback` | Restore a trusted snapshot |
| `GET /health` | Report runtime profile, registry metadata, and parser isolation probe |

Compatibility routes remain available on `/v1/*` and `/v2/*`. They now emit explicit deprecation telemetry and claim-scope metadata so they are excluded from prevention dashboards by default.

## User Manual

### 1. Prerequisites

- Node `22+`
- `pnpm` via `corepack`
- Python `3.12+`

### 2. Install dependencies from source

```powershell
corepack pnpm install
```

### 3. Build and test

```powershell
corepack pnpm build
corepack pnpm test
```

### 4. Start the daemon from source

```powershell
node packages/daemon/dist/index.js --host 127.0.0.1 --port 8787
```

### 5. Run the auditor-backed threat lab

```powershell
corepack pnpm auditor:review
```

This writes a validated timestamped archive under `demo-output/auditor-suite-<timestamp>` and refreshes the stable latest bundle under `demo-output/latest`.

### 6. Run the wrapper-parity gate

```powershell
corepack pnpm auditor:parity
```

### 7. Run the live comparison lab

```powershell
corepack pnpm demo:watch-live
```

That mode can use the same local model backend for both the raw agent and the SDK-protected agent when available.

## CI and Release Gates

The repository now treats hostile-corpus coverage as a PR gate, not just a nightly diagnostic.

Key workflows:

- [`.github/workflows/pr.yml`](.github/workflows/pr.yml): normal PR validation, including auditor parity
- [`.github/workflows/auditor-review.yml`](.github/workflows/auditor-review.yml): full auditor review artifacts on PRs and manual dispatch
- [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml): longer archived nightly runs
- [`.github/workflows/release.yml`](.github/workflows/release.yml): npm, PyPI, GHCR, and release asset publishing on tags

Release smoke and packaging parity are enforced through:

- [scripts/release/smoke-public-artifacts.mjs](scripts/release/smoke-public-artifacts.mjs)
- [scripts/release/audit-public-artifacts.mjs](scripts/release/audit-public-artifacts.mjs)
- [scripts/ci/run-wrapper-parity.mjs](scripts/ci/run-wrapper-parity.mjs)

## Why SafeBrowse Still Matters With Frontier Models

Hosted models can be better at resisting obvious prompt injection, but SafeBrowse is useful for a different reason: it is the deterministic reference monitor on the action path.

Model-side safety helps with:

- Better refusal behavior
- Better resistance to obvious jailbreaks
- Guardrail and moderation layers
- Tool approval primitives

SafeBrowse adds app-side enforcement for:

- Capability-bound action execution
- Connector registry verification
- Approval-envelope-bound onboarding
- Callback origin and payload enforcement
- Secret isolation and replay hygiene
- Memory authority separation
- Auditable, reproducible outcomes

The practical rule is simple:

- The model decides what it wants to do
- SafeBrowse decides what it is allowed to do

## Limitations

The current V4 path is materially stronger than the legacy routes, but there are still important limits:

- The prevention claim applies only to supported `/v4/*` routes and supported surfaces.
- Legacy `/v1/*` and transitional `/v2/*` paths remain for compatibility and are explicitly outside the prevention claim.
- Parser isolation is process-level hardening with denied egress and scrubbed ambient state, not yet a full OS or container sandbox.
- The current auditor verdict is still qualified because one benign baseline case remains approximate rather than perfectly forced.
- The threat lab is a controlled evaluation harness, not a full browser isolation system.

## License

SafeBrowse is released under the `SafeBrowse Non-Commercial License 1.0`. Copyright is retained by the author, and all rights not expressly granted are reserved. See [LICENSE](LICENSE).

## Documentation

- Security policy: [SECURITY.md](SECURITY.md)
- Release guide: [RELEASING.md](RELEASING.md)
- Historical v1 note: [docs/v1-limitations-and-model-backed-evaluation.md](docs/v1-limitations-and-model-backed-evaluation.md)
- Development source plan: [docs/safebrowse_sdk_vf_development_plan.docx](docs/safebrowse_sdk_vf_development_plan.docx)
