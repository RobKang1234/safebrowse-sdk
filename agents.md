# SafeBrowse SDK Agent Notes

This file is the quick operating guide for contributors, automations, and coding agents working in this repository.

## Current Repo State

- Canonical secure API in source: `/v6/*`
- Canonical secure profile in source: `secure_v6`
- Latest published public release as of April 5, 2026: `v0.1.4`
- Current working branch may be ahead of the latest public release

Check [releases/manifest.json](releases/manifest.json) before claiming that a feature is already published.

## Public Surfaces

- npm: `@safebrowse/core`
- npm: `@safebrowse/daemon`
- npm: `@safebrowse/playwright-adapter`
- PyPI: `safebrowse-client`
- GHCR: `ghcr.io/robkang1234/safebrowse-daemon`

Internal-only or non-public surfaces must not be described as public release contracts.

## Current Secure Feature Set

The V6 source tree now covers:

- HTML, PDF, image, tool-manifest, and memory-candidate captures
- email-message captures
- DOCX, XLSX, and PPTX captures
- attachment-bundle extraction
- external API response captures
- raw `.eml`, `.docx`, `.xlsx`, and `.pptx` ingestion through the secure V6 path
- browser, connector, memory, email, and API authority classes

## Files To Keep Aligned

When changing public behavior, update these together:

- `README.md`
- `RELEASING.md`
- `SECURITY.md`
- `packages/core/README.md`
- `packages/daemon/README.md`
- `packages/playwright-adapter/README.md`
- `python/safebrowse_client/README.md`
- `releases/manifest.json` when a public release is actually cut

## Release Rules

- `main` is the release branch.
- `.github/workflows/main-release.yml` cuts the next patch release on pushes to `main`.
- `.github/workflows/release.yml` publishes from `v*` tags.
- Do not claim a branch-only feature is shipped until the release manifest and registries say it is.

## Validation Commands

Use these before calling a change release-ready:

```bash
corepack pnpm build
corepack pnpm test
corepack pnpm release:ready
```

Useful targeted checks:

- `corepack pnpm auditor:review:v6`
- `corepack pnpm auditor:parity:v6`
- `node scripts/ci/benchmark-daemon-routes.mjs --assert-thresholds`

## Security and Evidence Rules

- Never label repo-generated output as an external audit opinion.
- Never commit private signing keys, prompt-injection raw datasets, or local model bundles.
- Keep release notes and public docs grounded in the latest published version, not just the branch head.
- If evidence is missing for a claim, say so directly and point to the next measurement or validation step.
