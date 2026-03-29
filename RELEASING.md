# Releasing SafeBrowse v3

This repo is set up for coordinated public release across npm, PyPI, and GHCR.

## One-Time Setup

Before the first public release:

1. Confirm ownership of the npm scope `@safebrowse`.
2. Configure PyPI Trusted Publishing for:
   - TestPyPI
   - PyPI
3. Configure npm Trusted Publishing for this GitHub repository.
4. Create protected GitHub environments:
   - `release-rc`
   - `release-prod`
5. Add the production KB signing secret:
   - `SAFEBROWSE_KB_SIGNING_KEY_B64`
6. Enable GitHub repository hygiene features where available:
   - Dependabot alerts
   - secret scanning
   - push protection

## Local Release Prep

Use Changesets for npm-side version orchestration, then sync the Python client version:

```bash
pnpm changeset
pnpm release:version
```

That flow keeps the public npm packages, the internal workspace packages, the root version, and `python/safebrowse_client/pyproject.toml` aligned.

## Local Validation

Run the release gate locally before tagging:

```bash
pnpm build
pnpm test
python -m pip install build twine
pnpm release:build:python
pnpm release:check:python
pnpm release:audit
pnpm release:smoke:artifacts
pnpm release:smoke:docker
```

## Tagging Strategy

- prerelease: `vX.Y.Z-rc.N`
- production: `vX.Y.Z`

Examples:

- `v0.2.0-rc.1`
- `v0.2.0`

The Git tag keeps npm/GHCR SemVer form. The Python package version is derived automatically:

- tag `v0.2.0-rc.1`
- PyPI version `0.2.0rc1`

## GitHub Release Workflow

The release workflow will:

- validate build, tests, packaging, and Docker smoke checks
- build KB artifacts with the protected signing key instead of a dev key
- publish npm packages with provenance
- publish `safebrowse-client` through Trusted Publishing
- publish the daemon image to GHCR with provenance and SBOM
- sign the GHCR image with Cosign
- attach release notes and artifacts to the GitHub Release

## Operational Notes

- Deploy containers by digest, not just by tag.
- Do not publish `@safebrowse/kb-tools`.
- Do not ship `knowledge_base/signing/private`, `demo-output/`, or threat-lab logs in public artifacts.
- Treat missing PyPI/npm Trusted Publisher setup as a release blocker, not a warning.
