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
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_recipe --manifest model/prompt_injection_ml_dataset/manifest.json --recipe model/prompt_injection_ml_dataset/training_recipe_additional_v2_rtx4060ti_8gb.json --output-dir .local/model_guard/full_recipe --backbone answerdotai/ModernBERT-base --resume
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_stacker --manifest model/prompt_injection_ml_dataset/manifest.json --sentinel-dir .local/model_guard/sentinel --expert-dir .local/model_guard/expert --output-dir .local/model_guard/stacker
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py package_runtime_bundle --sentinel-dir .local/model_guard/sentinel --expert-dir .local/model_guard/expert --stacker-dir .local/model_guard/stacker --output-dir .local/model_guard/runtime_bundle --bundle-version runtime-bundle-v1
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py monitor --run-dir .local/model_guard/full_recipe --host 127.0.0.1 --port 8790
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py serve --bundle-dir .local/model_guard/runtime_bundle --host 127.0.0.1 --port 8788
```

## Data root

The dataset rows are resolved from `SAFEBROWSE_DATA_ROOT`. The repo keeps only manifests and recipes.

Use `corepack pnpm model:data:migrate` once per workstation to move local dataset payloads out of the repo tree and refresh `manifest.json`.

## Current trainer shape

The checked-in package now supports the exact staged recipe for the private `additional_v2` corpus:

- dual sentinel: lexical SGD plus structured XGBoost with OR-threshold tuning
- hierarchical grouped-chunk `ModernBERT-base` expert stages at `1024 -> 2048 -> 4096`
- RTX 4060 Ti batch and gradient accumulation settings taken from the recipe JSON
- hard-negative replay before the final long-context stage
- CatBoost stacker plus packaged runtime bundle and validation/test evaluation
- LoRA adapter checkpoints with `active/latest`, sparse `active/milestones`, and release-only expert artifacts
- root-level `progress.json` and `status.json` for the full recipe run, plus a local dashboard over those files

Use `train_recipe` for the expert-authored pipeline. `train_expert` remains available for bounded experiments and targeted stage work.

- default expert backend: `transformers`
- explicit fast fallback for tests and low-dependency environments: `--backend smoke`
- the sentinel stage now streams mini-batches with `partial_fit` instead of buffering the full train split in memory before the first log line
- the local monitor reads `status.json`, `progress.json`, stage summaries, bundle manifests, and `train.log` from a recipe run root
- bounded local smoke run example:

```bash
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py train_expert --manifest model/prompt_injection_ml_dataset/manifest.json --output-dir .local/model_guard/expert --backbone answerdotai/ModernBERT-base --backend transformers --limit 8 --max-length 1024 --top-k-chunks 3 --epochs 1 --batch-size 1
```

## Monitoring

For live recipe runs, start the local monitor against the recipe output root:

```bash
node scripts/run-python-module.mjs scripts/python/run_model_guard_cli.py monitor --run-dir .local/model_guard/full_recipe --host 127.0.0.1 --port 8790
```

The monitor serves:

- `/health` for liveness
- `/api/state` for merged JSON state
- `/` for a simple HTML dashboard

The dashboard surfaces:

- current stage, overall state, progress fraction, records seen, optimizer step
- latest loss, moving average loss, mean confidence, gradient norm, and non-finite gradient recovery count
- last checkpoint path/time and retention state
- valid/test threat recall and macro F1 once evaluation completes
