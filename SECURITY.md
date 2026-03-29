# Security Policy

## Supported Releases

SafeBrowse is currently pre-`1.0`. The active hardening branch is `v3`, and the supported public release line will be the latest published `0.y.z` release after launch.

## Reporting a Vulnerability

Please do not open a public GitHub issue for a new security vulnerability.

Use GitHub Security Advisories for private reporting if enabled on the repository. If you cannot use that path, contact the maintainer through a private channel referenced in the repository profile.

When reporting, include:

- affected package or image name
- SafeBrowse version or image digest
- environment details
- reproduction steps
- expected vs actual behavior
- whether the issue can exfiltrate secrets, bypass policy, or weaken provenance

## Response Goals

- acknowledge receipt within 5 business days
- triage severity and impact before requesting public disclosure
- publish a fix or mitigation note before public advisory details when feasible

## Release Security Baseline

Public releases are expected to use:

- PyPI Trusted Publishing
- npm Trusted Publishing
- GHCR provenance and SBOM attestations
- keyless Cosign image signing
- protected GitHub environments for prerelease and production publishing

## Scope Notes

The live threat lab is a research/demo surface, not a production isolation boundary. Vulnerabilities in the daemon, core runtime, connector enforcement, provenance validation, or release artifacts should be treated as in scope.
