# `@safebrowse/daemon`

Localhost SafeBrowse daemon with bundled runtime assets for policy, verified registry, and KB loading.

## Install

```bash
npm install @safebrowse/daemon
```

## Run

```bash
npx @safebrowse/daemon \
  --host 127.0.0.1 \
  --port 8787 \
  --deployment-profile secure_v6 \
  --approval-broker-public-key-path ./knowledge_base/signing/safebrowse_vf_ed25519_public.pem
```

When `secure_v6` is selected, the daemon forces:

- approval broker mode `external_service`
- parser isolation mode `node_permission_process`

## Model Guard

The daemon supports a model-guard sidecar protocol for compatible private runtimes. The SDK does not publish model weights or runtime bundles.

```bash
npx @safebrowse/daemon \
  --model-guard-url http://127.0.0.1:8788 \
  --model-guard-enforcement-mode shadow
```

Supported modes:

- `off`: default; no scoring, even when a URL is configured
- `shadow`: records `compiledObservation.modelAssessment` for deterministic `ALLOW` observations without changing verdicts or authorities
- `tighten`: only applies stricter outcomes such as approval, read-only replan, or block

`GET /health` reports model-guard readiness, bundle/schema metadata, and digest metadata when the sidecar provides it. `secure_v6` claim readiness does not require model availability.

## Routes

- `GET /health`
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

## Secure Surface Notes

The daemon now accepts both pre-extracted structured captures and direct raw binary inputs for:

- MIME email via `rawMimeBase64`
- DOCX, XLSX, and PPTX via `contentBase64`

Those raw inputs are materialized into secure typed captures before normal policy and authority evaluation.

## Environment Variables

- `SAFEBROWSE_HOST`
- `SAFEBROWSE_PORT`
- `SAFEBROWSE_ROOT_DIR`
- `SAFEBROWSE_DEPLOYMENT_PROFILE`
- `SAFEBROWSE_APPROVAL_BROKER_PUBLIC_KEY_PATH`
- `SAFEBROWSE_APPROVAL_BROKER_MODE`
- `SAFEBROWSE_PARSER_ISOLATION_MODE`
- `SAFEBROWSE_MODEL_GUARD_URL`
- `SAFEBROWSE_MODEL_GUARD_TIMEOUT_MS`
- `SAFEBROWSE_MODEL_GUARD_ENFORCEMENT_MODE` (`off`, `shadow`, or `tighten`)

See the repository README for release and security guidance:

- [https://github.com/RobKang1234/safebrowse-sdk](https://github.com/RobKang1234/safebrowse-sdk)
