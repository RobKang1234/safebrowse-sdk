# `@safebrowse/playwright-adapter`

Reference payload builder for wiring Playwright-hosted agents to the SafeBrowse V6 daemon surface.

## Install

```bash
npm install @safebrowse/playwright-adapter playwright-core
```

`playwright-core` stays a peer dependency so hosts can control their own browser runtime.

## What It Provides

- page snapshot helpers for `/v6/observe`
- artifact ingest helpers for rendered page captures
- email observe payload builders
- office artifact ingest payload builders for DOCX, XLSX, and PPTX
- external API observe payload builders
- attachment extraction payload builders
- action payload builders for minted V6 authorities

Useful exports include:

- `createSurfaceCaptureFromSnapshot`
- `buildObservePayloadV6`
- `buildArtifactIngestPayloadV6`
- `buildEmailObservePayloadV6`
- `buildOfficeArtifactIngestPayloadV6`
- `buildExternalApiObservePayloadV6`
- `buildAttachmentExtractPayloadV6`
- `buildActionEvaluatePayloadV6`

The email and office snapshot types also support direct raw binary handoff through:

- `EmailSnapshot.rawMimeBase64`
- `OfficeDocumentSnapshot.contentBase64`

See the repository README for the full runtime contract:

- [https://github.com/RobKang1234/safebrowse-sdk](https://github.com/RobKang1234/safebrowse-sdk)
