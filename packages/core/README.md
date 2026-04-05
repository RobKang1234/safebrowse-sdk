# `@safebrowse/core`

Core SafeBrowse runtime for secure observation compilation, authority minting, approval binding, artifact handling, and replay construction.

## Install

```bash
npm install @safebrowse/core
```

## Current V6 Coverage

- HTML observation compilation and action evaluation
- connector preparation, approval issuance, and callback verification
- staged memory, promotion, and rollback
- replay bundle construction
- email-message and external-API surfaces
- DOCX, XLSX, PPTX, and attachment-bundle surfaces
- raw MIME and OOXML materialization before policy evaluation

## Key Exports

- `compileObservationV6`
- `mintCapabilitiesForObservationV6`
- `evaluateCapabilityUseV6`
- `createApprovalIntentPayloadV6`
- `issueApprovalEnvelopeV6`
- `prepareToolOnboardingV6`
- `verifyToolCallbackV6`
- `stageMemoryRecordV6`
- `promoteStagedMemoryRecordV6`
- `rollbackMemoryRecordV6`
- `extractAttachmentGraphV6`
- `materializeBinarySurfaceCapture`
- `buildReplayBundle`

## Capability Classes

The V6 runtime can evaluate:

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

See the repository README for daemon routes, release state, and operational guidance:

- [https://github.com/RobKang1234/safebrowse-sdk](https://github.com/RobKang1234/safebrowse-sdk)
