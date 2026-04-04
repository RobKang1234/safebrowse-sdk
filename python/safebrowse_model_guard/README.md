# `safebrowse-model-guard`

Private prompt-injection model guard sidecar and training pipeline for SafeBrowse V6.

This project is intentionally separate from the public `safebrowse-client` package:

- it trains and evaluates the private model guard
- it serves the private localhost sidecar used by the V6 daemon
- it packages promoted runtime bundles
- it expects datasets and intermediate artifacts to live outside the public repo

## Main commands

```bash
node scripts/run-python-module.mjs -m pip install -e python/safebrowse_model_guard[train]
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py prepare_data --manifest model/prompt_injection_ml_dataset/manifest.json
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_sentinel --manifest model/prompt_injection_ml_dataset/manifest.json --output-dir .local/model_guard/sentinel
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_expert --manifest model/prompt_injection_ml_dataset/manifest.json --output-dir .local/model_guard/expert --backbone answerdotai/ModernBERT-base
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_stacker --manifest model/prompt_injection_ml_dataset/manifest.json --sentinel-dir .local/model_guard/sentinel --expert-dir .local/model_guard/expert --output-dir .local/model_guard/stacker
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py package_runtime_bundle --sentinel-dir .local/model_guard/sentinel --expert-dir .local/model_guard/expert --stacker-dir .local/model_guard/stacker --output-dir .local/model_guard/runtime_bundle --bundle-version runtime-bundle-v1
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py serve --bundle-dir .local/model_guard/runtime_bundle --host 127.0.0.1 --port 8788
```

## Data root

The dataset rows are resolved from `SAFEBROWSE_DATA_ROOT`. The repo keeps only manifests and recipes.

Use `corepack pnpm model:data:migrate` once per workstation to move local dataset payloads out of the repo tree and refresh `manifest.json`.

## Current trainer shape

The checked-in package now defaults `train_expert` to a real transformer-backed chunk expert around `answerdotai/ModernBERT-base`, paired with the char-ngram sentinel and CatBoost stacker.

- default expert backend: `transformers`
- explicit fast fallback for tests and low-dependency environments: `--backend smoke`
- the sentinel stage now streams mini-batches with `partial_fit` instead of buffering the full train split in memory before the first log line
- bounded local smoke run example:

```bash
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_expert --manifest model/prompt_injection_ml_dataset/manifest.json --output-dir .local/model_guard/expert --backbone answerdotai/ModernBERT-base --backend transformers --limit 8 --max-length 1024 --top-k-chunks 3 --epochs 1 --batch-size 1
```
