# Releasing SafeBrowse

This repository publishes coordinated releases to npm, PyPI, and GHCR.

As of April 5, 2026:

- The latest published public release is `v0.1.4`.
- Version history is tracked in [releases/manifest.json](releases/manifest.json).
- `main` is the release branch.
- The `V6` branch is ahead of the latest public release and is not published automatically until it is merged to `main`.

## Release Automation

The repo now has two release-facing GitHub Actions workflows:

- `.github/workflows/main-release.yml`
  - triggers on pushes to `main`
  - computes the next patch version
  - syncs package versions
  - updates `releases/manifest.json`
  - runs `pnpm release:ready`
  - commits the version bump and tags `vX.Y.Z`
- `.github/workflows/release.yml`
  - triggers on pushed `v*` tags
  - validates the repo again
  - publishes npm packages
  - publishes the Python client
  - publishes the daemon image to GHCR
  - attaches release assets

There is also a manual PyPI fallback workflow in `.github/workflows/publish-pypi.yml`.

## Version Tracking

Use these files and scripts as the single source of truth for public versions:

- `package.json`
- `packages/*/package.json`
- `python/safebrowse_client/pyproject.toml`
- `releases/manifest.json`
- `scripts/release/sync-version.mjs`
- `scripts/release/next-version.mjs`
- `scripts/release/update-release-manifest.mjs`

Do not hand-edit only one public package version and leave the others behind.

## One-Time Setup

Before relying on automated public releases:

1. Confirm ownership of the npm scope `@safebrowse`.
2. Configure npm Trusted Publishing for:
   - `@safebrowse/core`
   - `@safebrowse/daemon`
   - `@safebrowse/playwright-adapter`
3. Configure PyPI Trusted Publishing for `safebrowse-client`, or provide `PYPI_API_TOKEN` / `TEST_PYPI_API_TOKEN`.
4. Create GitHub environments:
   - `release-rc`
   - `release-prod`
5. Add `SAFEBROWSE_KB_SIGNING_KEY_B64`.
6. If branch protection blocks Actions from pushing version bumps or tags to `main`, add `RELEASE_GH_PAT`.

## Normal Release Flow

For routine production releases:

1. Merge the intended changes to `main`.
2. Let `main-release.yml` cut the next patch version automatically.
3. Let `release.yml` publish from the new tag.
4. Confirm registry state against [releases/manifest.json](releases/manifest.json).

This is the preferred path for public releases.

## Local Validation Before Merge

Run the release gate locally when changing publish surfaces:

```bash
corepack pnpm build
corepack pnpm test
corepack pnpm perf:smoke
corepack pnpm perf:daemon:gate
corepack pnpm release:build:python
corepack pnpm release:check:python
corepack pnpm release:audit
corepack pnpm release:smoke:artifacts
corepack pnpm release:smoke:docker
```

The shortcut is:

```bash
corepack pnpm release:ready
```

## Manual Version Cut

If you need to prepare a release locally instead of waiting for `main-release.yml`:

```bash
corepack pnpm changeset
corepack pnpm release:version
```

Then validate, commit the version bump, tag `vX.Y.Z`, and push the tag so `release.yml` can publish.

## Tagging

- prerelease tag: `vX.Y.Z-rc.N`
- production tag: `vX.Y.Z`

Examples:

- `v0.2.0-rc.1`
- `v0.2.0`

Python prerelease versions are derived automatically. For example, `v0.2.0-rc.1` becomes `0.2.0rc1`.

## Artifact Boundaries

Do not publish these in public artifacts:

- private signing keys
- `demo-output/`
- threat-lab logs
- raw prompt-injection datasets
- training checkpoints
- local model bundles
- model adapters, sidecar runtime bundles, and MLflow/CatBoost run outputs
- `.local/model_guard/`
- `python/safebrowse_model_guard/artifacts/`
- `python/safebrowse_model_guard/bundles/`
- `python/safebrowse_model_guard/checkpoints/`
- `knowledge_base/signing/private`

The supported public model-guard surface is the daemon protocol, configuration, health metadata, and tightening semantics. Trained model bundles are private deploy artifacts referenced by path, URL, version, and digest outside the public SDK artifacts.

Before promoting a private model bundle for use with a public release, validate its `bundleVersion`, `featureSchemaVersion`, component digests, and held-out metrics. The current default promotion floor is valid/test threat recall `>= 0.995` and macro F1 `>= 0.98`.

Repo-generated internal assessment output and model-guard assessments are not external audit deliverables and should not be labeled that way in release notes.
