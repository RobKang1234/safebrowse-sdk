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
- `SAFEBROWSE_MODEL_GUARD_ENFORCEMENT_MODE`

See the repository README for release and security guidance:

- [https://github.com/RobKang1234/safebrowse-sdk](https://github.com/RobKang1234/safebrowse-sdk)
