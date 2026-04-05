# Security Policy

## Supported Releases

As of April 5, 2026, SafeBrowse is still pre-`1.0`.

Support applies to the latest published public release line from `main`, plus the next unreleased hardening work on `main` when a fix is in progress. Long-lived development branches, including `V6`, may contain newer mitigations but are not the stable public support target until they are merged and released.

The latest published release recorded in [releases/manifest.json](releases/manifest.json) is `v0.1.4`.

## Reporting a Vulnerability

Do not open a public GitHub issue for a new vulnerability.

Preferred path:

- GitHub Security Advisories for private reporting, if enabled

Fallback:

- contact the maintainer through a private channel listed on the repository profile

Include:

- affected package, image, or route surface
- SafeBrowse version or image digest
- environment details
- reproduction steps
- expected vs actual behavior
- whether the issue can exfiltrate secrets, bypass policy, or weaken provenance

## Scope

In-scope components include:

- `@safebrowse/core`
- `@safebrowse/daemon`
- `safebrowse-client`
- `@safebrowse/playwright-adapter`
- approval and callback binding
- verified registry enforcement
- raw MIME and OOXML ingestion
- attachment extraction
- email and external-API authority binding
- replay and redaction logic
- public release artifacts on npm, PyPI, and GHCR

The live threat lab and demo output are research surfaces, not production isolation boundaries, but vulnerabilities that weaken the real daemon or runtime through those paths are still in scope.

## Response Goals

- acknowledge receipt within 5 business days
- triage severity before public disclosure
- ship a fix or mitigation before full advisory details when feasible

## Release Security Baseline

Public releases are expected to use:

- npm Trusted Publishing
- PyPI Trusted Publishing or scoped token fallback
- GHCR provenance and SBOM attestations
- keyless Cosign image signing
- protected GitHub environments for prerelease and production publishing

## Disclosure Notes

Repo-generated internal assessment files are not external auditor opinions. If a vulnerability affects a release claim, update the public docs, release notes, and version manifest together so users can tell which published versions are impacted.
