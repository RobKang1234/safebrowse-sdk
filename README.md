# SafeBrowse SDK

SafeBrowse is app-side security middleware for browser-use agents. It sits on the action path between an agent and risky external surfaces, then returns structured decisions, capability-bound execution plans, replay data, and guarded connector flows without owning the planner itself.

The repository now ships one canonical secure surface. `secure_v6` owns the claim-bearing `/v6/*` API, including the staged-memory, artifact-reference, connector-binding, and replay capabilities that were consolidated out of earlier versioned lanes.

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

## Current Secure Profiles

`secure_v6` is the only first-class secure deployment profile:

- Server-owned observation compilation
- Parser isolation for supported capture formats
- DOM-aware capability minting from supported authority surfaces only
- Session-bound, digest-bound, non-replayable capabilities
- Broker-signed, semantically bound approval envelopes
- Connector handles instead of model-visible token material
- Tiered memory authority separation
- System-wide secret isolation and noninterference checks
- Wrapper parity across direct, Python, and npm-installed execution paths in `secure_v6`
- Planner-safe observations by default
- Optional private model-guard sidecar that may only tighten decisions; it never weakens deterministic V6 blocks, approval requirements, or fail-closed parse outcomes
- Explicit authority candidates alongside historical capability descriptors
- Registry-hash-bound connector preparation and callback verification
- Artifact references with mismatch metadata and quarantine semantics
- Staged memory with source-class rules, corroboration, and rollback to the prior trusted baseline
- Replay bundles with actor attribution

Supported V6 claim surfaces:

- HTML and DOM captures
- Verified tool manifests
- OAuth and connector flows
- Server-owned memory promotion paths

Other supported content surfaces may still be observed and summarized, but they do not directly mint effectful capabilities in the V6 claim-bearing profile. Unsupported or partially parsed surfaces fail closed and are outside the prevention claim.

Older versioned routes are retired from the public claim-bearing surface. Current callers should use `/v6/*` and `secure_v6`.

## Private Model Guard

SafeBrowse V6 can attach a private localhost Python sidecar that scores compiled observations after deterministic parsing and policy extraction.

- The daemon remains the final policy owner.
- The model is tightener-only:
  - deterministic `BLOCK` stays `BLOCK`
  - deterministic approval requirements stay required
  - model `require_shadow_replay` downgrades to `REPLAN_READ_ONLY`
  - model `require_user_approval` escalates authorities to `requiresApproval=true`
  - model `deny` blocks direct authority minting
- `GET /health` now reports a coarse `modelGuard` block with readiness, runtime mode, bundle version, and enforcement mode.
- The training dataset directory is manifest-only in git. Raw JSONL payloads resolve from `SAFEBROWSE_DATA_ROOT`, not from committed repo files.

## Latest Internal Assessment

The latest repo-generated internal assessment bundle is preserved in [demo-output/latest/report.html](demo-output/latest/report.html), [demo-output/latest/report.md](demo-output/latest/report.md), [demo-output/latest/summary.json](demo-output/latest/summary.json), [demo-output/latest/internal-assessment.md](demo-output/latest/internal-assessment.md), and [demo-output/latest/internal-assessment.json](demo-output/latest/internal-assessment.json).

As of April 3, 2026, against the repo-pinned secure-claim corpus in [config/auditor/v6_secure_claim_suite.json](config/auditor/v6_secure_claim_suite.json):

- Total cases: `7`
- Passed: `7`
- Failed: `0`
- Verdict: `qualified_positive_pending_external_audit`

The saved bundle is deterministic and claim-scoped: it checks hidden-authority suppression, visible navigation, connector approval binding, callback mismatch rejection, unsigned approval rejection, and legacy-route disablement under `secure_v6`.

This is intentionally labeled as an internal assessment. External audit status is tracked separately and should not be inferred from repo-generated artifacts alone.

## What "Fully Tested" Means Here

In this repository, "fully tested" now means more than unit tests passing.

For the supported V6 prevention surface, the same hostile and benign cases are checked through:

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

That parity gate runs through [scripts/ci/run-wrapper-parity-v6.mjs](scripts/ci/run-wrapper-parity-v6.mjs). The full deterministic auditor review run is driven by [scripts/threat-demo/run-auditor-suite-v6.ts](scripts/threat-demo/run-auditor-suite-v6.ts).

## Quick Install

### Daemon

```bash
npx @safebrowse/daemon --host 127.0.0.1 --port 8787 --deployment-profile secure_v6 --approval-broker-public-key-path ./knowledge_base/signing/safebrowse_vf_ed25519_public.pem
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

## Recommended V6 Flow

### 1. Start a session

```python
from safebrowse_client import SafeBrowseClient

client = SafeBrowseClient("http://127.0.0.1:8787")

session = client.start_session(
    {
        "taskId": "vendor-review-1",
        "userGoal": "Review the page and stay read-only unless an explicitly granted authority says otherwise.",
        "allowedOrigins": ["https://docs.python.org", "https://arxiv.org"],
        "allowedVerbs": ["navigate", "summarize"]
    }
)
```

### 2. Compile an observation

```python
from safebrowse_client import build_html_surface_capture

compiled = client.observe(
    {
        "sessionId": session["session"]["sessionId"],
        "capture": build_html_surface_capture(
            url="https://docs.python.org/3/",
            html="<main>Python 3 documentation home page ...</main>",
            visible_text="Python 3 documentation home page ..."
        )
    }
)
```

### 3. Let the model choose only from minted authorities

```python
planner_view = compiled["plannerView"]
authorities = compiled["authorityCandidates"]

selected = authorities[0]
result = client.action(
    {
        "sessionId": session["session"]["sessionId"],
        "authorityId": selected["authorityId"],
        "authorityDigest": selected["authorityDigest"],
        "parameters": {}
    }
)
```

The model does not get to invent a new URL, selector, callback URI, or sink. It may only choose from server-minted authorities bound to the session, workflow step, origin, target class, parameter schema, digest, and source evidence.

### 4. Use the packaged starter template

The Python package also ships a model-connected browser template helper:

```python
from safebrowse_client import write_model_connected_browser_agent_template

write_model_connected_browser_agent_template("model_connected_browser_agent.py")
```

## Core Runtime Functions

The main runtime entrypoints exported from [packages/core/src/index.ts](packages/core/src/index.ts) include:

| Function | Purpose |
| --- | --- |
| `compileObservationV6` | Compile a supported surface into a provenance-aware observation and planner-safe view |
| `mintCapabilitiesForObservationV6` | Mint session-bound, digest-bound, non-replayable capabilities from supported authority evidence |
| `evaluateCapabilityUseV6` | Enforce capability-bound action execution |
| `createApprovalIntentPayloadV6` | Build the broker-signed approval payload that binds capability and workflow intent |
| `issueApprovalEnvelopeV6` | Enforce broker-signed, semantically bound approval issuance |
| `prepareToolOnboardingV6` | Enforce registry-backed, approval-envelope-bound connector preparation |
| `verifyToolCallbackV6` | Verify callback state, origin, registry binding, and allowlisted payload fields |
| `stageMemoryRecordV6` | Stage V6 memory with source-class, corroboration, and lineage metadata |
| `promoteStagedMemoryRecordV6` | Promote staged V6 memory with approval-bound ticket consumption |
| `promoteMemoryRecordV6` | Promote candidate memory into trusted durable state with validation or approval |
| `rollbackMemoryRecordV6` | Restore a trusted snapshot after contradiction or operator action |
| `assertNoSecretsInJson` | Enforce secret noninterference for JSON payloads |
| `buildReplayBundle` | Build replayable forensic bundles from runtime events |

Legacy `v1`, `v2`, `v4`, and `v5` functions are archived only; they are not part of the V6 prevention claim.

## Daemon Routes

The localhost daemon in [packages/daemon/src/server.ts](packages/daemon/src/server.ts) exposes:

| Route | Purpose |
| --- | --- |
| `POST /v6/session/start` | Start a server-owned secure session under `secure_v6` |
| `POST /v6/observe` | Compile a supported surface into a planner-safe observation; returns authority candidates and replay evidence |
| `POST /v6/action/evaluate` | Evaluate observation, authority, and effect decisions on the canonical action path |
| `POST /v6/approval/issue` | Issue a broker-signed approval envelope for an exact connector, navigation, or promotion flow |
| `POST /v6/tool/prepare` | Prepare a brokered connector or OAuth flow |
| `POST /v6/tool/callback/verify` | Verify callback origin, state, registry binding, and allowlisted fields |
| `POST /v6/artifact/ingest` | Ingest an artifact and return the active profile's fail-closed or artifact-reference response |
| `POST /v6/memory/stage` | Canonical staged memory path with source-class and corroboration semantics |
| `POST /v6/memory/promote` | Promote memory into trusted durable state |
| `POST /v6/memory/rollback` | Restore a trusted snapshot |
| `POST /v6/replay/bundle` | Build a replay bundle from actor-attributed runtime events |
| `GET /health` | Report runtime profile, secure deployment posture, registry metadata, parser isolation probe, and private model-guard readiness |

Compatibility routes are retired from the public claim-bearing surface. Archived fixtures may still reference them, but they are no longer part of the release contract.

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
node packages/daemon/dist/index.js --host 127.0.0.1 --port 8787 --deployment-profile secure_v6 --approval-broker-public-key-path knowledge_base/signing/safebrowse_vf_ed25519_public.pem
```

`secure_v6` now forces `approvalBrokerMode=external_service` and `parserIsolationMode=node_permission_process` internally. Passing those flags explicitly is allowed but redundant.

### 5. Run the auditor-backed threat lab

```powershell
corepack pnpm auditor:review:v6
```

This writes a validated timestamped archive under `demo-output/auditor-suite-<timestamp>` and refreshes the stable latest bundle under `demo-output/latest`.

### 6. Run the wrapper-parity gate

```powershell
corepack pnpm auditor:parity:v6
```

### 7. Run the live comparison lab

```powershell
corepack pnpm demo:watch-live
```

That mode can use the same local model backend for both the raw agent and the SDK-protected agent when available.

### 8. Start the private model-guard demo sidecar

```powershell
corepack pnpm model:bundle:demo
node packages/daemon/dist/index.js --host 127.0.0.1 --port 8787 --deployment-profile secure_v6 --model-guard-url http://127.0.0.1:8788 --model-guard-enforcement-mode tighten --approval-broker-public-key-path knowledge_base/signing/safebrowse_vf_ed25519_public.pem
corepack pnpm model:serve:demo
```

For real training and promoted runtime bundles, see [python/safebrowse_model_guard/README.md](python/safebrowse_model_guard/README.md).

## CI and Release Gates

The repository now treats hostile-corpus coverage as a PR gate, not just a nightly diagnostic.

Key workflows:

- [`.github/workflows/pr.yml`](.github/workflows/pr.yml): normal PR validation, including auditor parity
- [`.github/workflows/auditor-review.yml`](.github/workflows/auditor-review.yml): full auditor review artifacts on PRs and manual dispatch
- [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml): longer archived nightly runs
- [`.github/workflows/private-model-guard-retrain.yml`](.github/workflows/private-model-guard-retrain.yml): self-hosted nightly evaluation and weekly private model-guard retraining with MLflow Projects
- [`.github/workflows/release.yml`](.github/workflows/release.yml): npm, PyPI, GHCR, and release asset publishing on tags

Release smoke and packaging parity are enforced through:

- [scripts/release/smoke-public-artifacts.mjs](scripts/release/smoke-public-artifacts.mjs)
- [scripts/release/audit-public-artifacts.mjs](scripts/release/audit-public-artifacts.mjs)
- [scripts/ci/run-wrapper-parity-v6.mjs](scripts/ci/run-wrapper-parity-v6.mjs)

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

The secure profiles are materially stronger than the legacy routes, but there are still important limits:

- The prevention claim applies only to supported `/v6/*` routes under `secure_v6` and supported authority surfaces.
- Historical pre-V6 content now lives under `archieve/` for reference only, and it is not part of the active release contract.
- Legacy `/v1/*`, `/v2/*`, `/v4/*`, and `/v5/*` paths are archived migration artifacts and are explicitly outside the prevention claim.
- Parser isolation is process-level hardening with denied egress and scrubbed ambient state, not yet a full OS or container sandbox.
- Repo-generated internal assessments are not a substitute for external audit.
- The threat lab is a controlled evaluation harness, not a full browser isolation system.

## License

SafeBrowse is released under the `SafeBrowse Non-Commercial License 1.0`. Copyright is retained by the author, and all rights not expressly granted are reserved. See [LICENSE](LICENSE).

## Documentation

- Security policy: [SECURITY.md](SECURITY.md)
- Release guide: [RELEASING.md](RELEASING.md)
- Archived V5 remediation note: [archieve/docs/v5-remediation-note.md](archieve/docs/v5-remediation-note.md)
- Archived v1 note: [archieve/docs/v1-limitations-and-model-backed-evaluation.md](archieve/docs/v1-limitations-and-model-backed-evaluation.md)
- Development source plan: [docs/safebrowse_sdk_vf_development_plan.docx](docs/safebrowse_sdk_vf_development_plan.docx)
