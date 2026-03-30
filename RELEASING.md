# Releasing SafeBrowse v3

This repo is set up for coordinated public release across npm, PyPI, and GHCR.

The repository is no longer Apache-licensed. Future releases should carry the
`SafeBrowse Non-Commercial License 1.0` terms and preserve the package-level
`LICENSE` files included in each public distribution surface.

## One-Time Setup

Before the first public release:

1. Confirm ownership of the npm scope `@safebrowse`.
2. Configure PyPI publishing for:
   - TestPyPI
   - PyPI
   - Prefer Trusted Publishing, but this repo also supports GitHub Actions secrets named `TEST_PYPI_API_TOKEN` and `PYPI_API_TOKEN` for token-backed uploads.
3. Configure npm Trusted Publishing for these packages against `.github/workflows/release.yml`:
   - `@safebrowse/core`
   - `@safebrowse/daemon`
   - `@safebrowse/playwright-adapter`
   - Do not set a GitHub environment name for npm trusted publishing. The npm publish job intentionally runs without an Actions environment so the same workflow can handle both prerelease and production tags with one npm trusted publisher configuration per package.
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
- publish npm packages with provenance through npm Trusted Publishing from `.github/workflows/release.yml`
- publish `safebrowse-client` through Trusted Publishing when configured, or through `PYPI_API_TOKEN` / `TEST_PYPI_API_TOKEN` when those secrets are present
- publish the daemon image to GHCR with provenance and SBOM
- sign the GHCR image with Cosign
- attach release notes and artifacts to the GitHub Release

## PyPI-First Publishing

If you want to ship the Python client before npm and GHCR are live, use the dedicated Actions workflow:

- Workflow: `publish-pypi`
- Inputs:
  - `ref`
  - `version`
  - `repository` (`pypi` or `testpypi`)
  - `skip_existing`

Recommended setup for the current repo:

1. Add `PYPI_API_TOKEN` as a GitHub Actions secret in the `release-prod` environment.
2. Optionally add `TEST_PYPI_API_TOKEN` in the `release-rc` environment for TestPyPI prereleases.
3. Keep any local token file outside git. This repo ignores `pypi_token.txt` to reduce accidental commits.
4. Run the `publish-pypi` workflow from the GitHub Actions UI when you are ready.

Important: `safebrowse-client 0.1.0` was already published to PyPI before this
license change. If you want PyPI to reflect the non-commercial terms, publish a
new version rather than trying to retroactively change the old release.

## Operational Notes

- Deploy containers by digest, not just by tag.
- Do not publish `@safebrowse/kb-tools`.
- Do not ship `knowledge_base/signing/private`, `demo-output/`, or threat-lab logs in public artifacts.
- Treat missing PyPI/npm Trusted Publisher setup as a release blocker, not a warning.
