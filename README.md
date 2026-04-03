# SafeBrowse SDK

SafeBrowse is app-side security middleware for browser-use agents. It sits on the action path between an agent and risky external surfaces, then returns structured decisions, capability-bound execution plans, replay data, and guarded connector flows without owning the planner itself.

The repository now carries two secure tracks. `secure_v5` is the frozen bounded claim surface on `/v5/*`. `secure_v6` is the clean-slate vf-aligned surface on `/v6/*` with stricter tool attestation, artifact-first handoff, staged memory promotion, and first-class replay attribution.

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

`secure_v5` remains the externally reviewable bounded claim lane:

- Server-owned observation compilation
- Parser isolation for supported capture formats
- DOM-aware capability minting from supported authority surfaces only
- Session-bound, digest-bound, non-replayable capabilities
- Broker-signed, semantically bound approval envelopes
- Connector handles instead of model-visible token material
- Tiered memory authority separation
- System-wide secret isolation and noninterference checks
- Wrapper parity across direct, Python, and npm-installed execution paths in `secure_v5`

Supported V5 claim surfaces:

- HTML and DOM captures
- Verified tool manifests
- OAuth and connector flows
- Server-owned memory promotion paths

Other supported content surfaces may still be observed and summarized, but they do not directly mint effectful capabilities in the V5 claim-bearing profile. Unsupported or partially parsed surfaces fail closed and are outside the prevention claim.

`secure_v6` is the vf-aligned redesign lane:

- Planner-safe observations by default
- Explicit authority candidates instead of implicit action carryover
- Registry-hash-bound connector preparation and callback verification
- Artifact references with mismatch metadata and quarantine semantics
- Staged memory with source-class rules, corroboration, and rollback to the prior trusted baseline
- Replay bundles with actor attribution

## Latest Internal Assessment

The latest repo-generated V5 internal assessment bundle is preserved in [demo-output/latest/report.html](demo-output/latest/report.html), [demo-output/latest/report.md](demo-output/latest/report.md), [demo-output/latest/summary.json](demo-output/latest/summary.json), [demo-output/latest/internal-assessment.md](demo-output/latest/internal-assessment.md), and [demo-output/latest/internal-assessment.json](demo-output/latest/internal-assessment.json).

As of April 2, 2026, against the repo-pinned V5 secure-claim corpus in [config/auditor/v5_secure_claim_suite.json](config/auditor/v5_secure_claim_suite.json):

- Total cases: `7`
- Passed: `7`
- Failed: `0`
- Verdict: `qualified_positive_pending_external_audit`

The saved V5 bundle is deterministic and claim-scoped: it checks hidden-authority suppression, visible navigation, connector approval binding, callback mismatch rejection, unsigned approval rejection, and legacy-route disablement under `secure_v5`.

This is intentionally labeled as an internal assessment. External audit status is tracked separately and should not be inferred from repo-generated artifacts alone.

## What "Fully Tested" Means Here

In this repository, "fully tested" now means more than unit tests passing.

For the supported V5 prevention surface, the same hostile and benign cases are checked through:

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

That parity gate runs through [scripts/ci/run-wrapper-parity-v5.mjs](scripts/ci/run-wrapper-parity-v5.mjs). The full deterministic auditor review run is driven by [scripts/threat-demo/run-auditor-suite-v5.ts](scripts/threat-demo/run-auditor-suite-v5.ts).

## Quick Install

### Daemon

Frozen V5 lane:

```bash
npx @safebrowse/daemon --host 127.0.0.1 --port 8787 --deployment-profile secure_v5 --approval-broker-public-key-path ./knowledge_base/signing/safebrowse_vf_ed25519_public.pem
```

Vf-aligned V6 lane:

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

## Recommended V5 Flow

### 1. Start a session

```python
from safebrowse_client import SafeBrowseClient

client = SafeBrowseClient("http://127.0.0.1:8787")

session = client.start_session_v5(
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
compiled = client.observe_v5(
    {
        "sessionId": session["session"]["sessionId"],
        "capture": {
            "surfaceType": "html",
            "url": "https://docs.python.org/3/",
            "html": "<main>Python 3 documentation home page ...</main>",
            "visibleText": "Python 3 documentation home page ...",
            "hiddenText": [],
            "metadataText": []
        }
    }
)
```

### 3. Let the model choose only from minted capabilities

```python
planner_view = compiled["plannerView"]
capabilities = compiled["capabilities"]

selected = capabilities[0]
result = client.action_v5(
    {
        "sessionId": session["session"]["sessionId"],
        "capabilityId": selected["capabilityId"],
        "capabilityDigest": selected["capabilityDigest"],
        "parameters": {}
    }
)
```

The model does not get to invent a new URL, selector, callback URI, or sink. It may only choose from server-minted capabilities bound to the session, workflow step, origin, target class, parameter schema, digest, and source evidence.

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
| `compileObservationV5` | Compile a supported surface into a provenance-aware observation and planner-safe view |
| `mintCapabilitiesForObservationV5` | Mint session-bound, digest-bound, non-replayable capabilities from supported authority evidence |
| `evaluateCapabilityUseV5` | Enforce capability-bound action execution |
| `createApprovalIntentPayloadV5` | Build the broker-signed approval payload that binds capability and workflow intent |
| `issueApprovalEnvelopeV5` | Enforce broker-signed, semantically bound approval issuance |
| `prepareToolOnboardingV5` | Enforce registry-backed, approval-envelope-bound connector preparation |
| `verifyToolCallbackV5` | Verify callback state, origin, registry binding, and allowlisted payload fields |
| `evaluateMemoryWriteV5` | Place memory into trusted, candidate, or tainted tiers without caller authority metadata |
| `promoteMemoryRecordV5` | Promote candidate memory into trusted durable state with validation or approval |
| `rollbackMemoryRecordV5` | Restore a trusted snapshot after contradiction or operator action |
| `stageMemoryRecordV6` | Stage V6 memory with source-class, corroboration, and lineage metadata |
| `promoteMemoryRecordV6` | Promote staged V6 memory with approval-bound ticket consumption |
| `assertNoSecretsInJson` | Enforce secret noninterference for JSON payloads |
| `buildReplayBundle` | Build replayable forensic bundles from runtime events |

Legacy `v1`, `v2`, and transitional `v4` functions remain exported for compatibility, but they are not part of the V5 prevention claim.

## Daemon Routes

The localhost daemon in [packages/daemon/src/server.ts](packages/daemon/src/server.ts) exposes:

| Route | Purpose |
| --- | --- |
| `POST /v5/session/start` | Start a server-owned secure V5 task session |
| `POST /v5/observe` | Compile a supported surface into a planner-safe observation and V5 capabilities |
| `POST /v5/capability/use` | Evaluate a single capability use |
| `POST /v5/approval/issue` | Issue a broker-signed approval envelope for an exact connector flow |
| `POST /v5/tool/prepare` | Prepare a brokered connector or OAuth flow |
| `POST /v5/tool/callback/verify` | Verify callback origin, state, registry binding, and allowlisted fields |
| `POST /v5/artifact/ingest` | Ingest an artifact under the V5 fail-closed path |
| `POST /v5/memory/write` | Write candidate or tainted memory records |
| `POST /v5/memory/promote` | Promote memory into trusted durable state |
| `POST /v5/memory/rollback` | Restore a trusted snapshot |
| `POST /v6/session/start` | Start a server-owned secure V6 task session |
| `POST /v6/observe` | Compile planner-safe observation output and explicit V6 authority candidates |
| `POST /v6/action/evaluate` | Return separate observation, authority, and effect decisions plus execution plan |
| `POST /v6/approval/issue` | Issue approval for V6 connector or memory promotion envelopes |
| `POST /v6/tool/prepare` | Prepare a registry-hash-bound V6 connector flow |
| `POST /v6/tool/callback/verify` | Verify exact callback binding and carried registry hashes |
| `POST /v6/artifact/ingest` | Return planner-safe artifact projection plus artifact reference and mismatch signals |
| `POST /v6/memory/stage` | Stage V6 memory and mint a promotion ticket when durable promotion is eligible |
| `POST /v6/memory/promote` | Promote V6 memory with ticket and approval consumption |
| `POST /v6/memory/rollback` | Restore the exact prior trusted baseline for a staged key |
| `POST /v6/replay/bundle` | Build a replay bundle from actor-attributed V6 runtime events |
| `GET /health` | Report runtime profile, secure deployment posture, registry metadata, and parser isolation probe |

Compatibility routes remain available on `/v1/*`, `/v2/*`, and `/v4/*` in development mode. Under `secure_v5` and `secure_v6`, they are disabled and explicitly outside the prevention claim.

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
node packages/daemon/dist/index.js --host 127.0.0.1 --port 8787 --deployment-profile secure_v5 --approval-broker-public-key-path knowledge_base/signing/safebrowse_vf_ed25519_public.pem
```

`secure_v5` and `secure_v6` now force `approvalBrokerMode=external_service` and `parserIsolationMode=node_permission_process` internally. Passing those flags explicitly is allowed but redundant.

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
- [scripts/ci/run-wrapper-parity-v5.mjs](scripts/ci/run-wrapper-parity-v5.mjs)

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

- The prevention claim applies only to supported `/v5/*` routes under `secure_v5` and supported authority surfaces.
- `secure_v6` is implemented in this repository, but it does not yet have a refreshed external audit opinion.
- Legacy `/v1/*`, `/v2/*`, and `/v4/*` paths remain for migration and are explicitly outside the prevention claim.
- Parser isolation is process-level hardening with denied egress and scrubbed ambient state, not yet a full OS or container sandbox.
- Repo-generated internal assessments are not a substitute for external audit.
- The threat lab is a controlled evaluation harness, not a full browser isolation system.

## License

SafeBrowse is released under the `SafeBrowse Non-Commercial License 1.0`. Copyright is retained by the author, and all rights not expressly granted are reserved. See [LICENSE](LICENSE).

## Documentation

- Security policy: [SECURITY.md](SECURITY.md)
- Release guide: [RELEASING.md](RELEASING.md)
- V5 remediation note: [docs/v5-remediation-note.md](docs/v5-remediation-note.md)
- Historical v1 note: [docs/v1-limitations-and-model-backed-evaluation.md](docs/v1-limitations-and-model-backed-evaluation.md)
- Development source plan: [docs/safebrowse_sdk_vf_development_plan.docx](docs/safebrowse_sdk_vf_development_plan.docx)
