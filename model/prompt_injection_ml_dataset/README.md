# Prompt Injection ML Dataset

This directory is manifest-only in the repo.

What stays in git:

- `manifest.json`
- `training_recipe_additional_v2_rtx4060ti_8gb.json`
- `training_recipe_additional_v2_rtx4060ti_8gb.md`

What does not stay in git:

- raw train / valid / test JSONL payloads
- rendered samples beyond the tracked recipe metadata
- checkpoints, adapters, MLflow runs, caches, and packaged bundles

The runtime and training code resolve dataset files from `SAFEBROWSE_DATA_ROOT`. By default, the private dataset root is `~/.safebrowse/private_data/prompt_injection_ml_dataset`.

Use `node scripts/model/migrate-prompt-injection-dataset.mjs` to move local payloads out of the repo tree and refresh the manifest-backed storage layout.
