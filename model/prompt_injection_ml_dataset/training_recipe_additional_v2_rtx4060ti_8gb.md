# Updated training recipe for `prompt_injection_ml_dataset_additional_v2`

## Bottom line

For your RTX 4060 Ti 8GB, the strongest practical system is **not** one giant model. It is a **cost-sensitive cascade**:

1. **High-recall ML sentinel** for `threat` vs `allow_read_only`
2. **Hierarchical deep expert** for the 4-way decision
3. **CatBoost/XGBoost stacker** for conservative final routing

That design is the best trade-off for your new data because the current additional dataset is:
- long-context (average ~4661 chars per train sample)
- multilingual and domain-balanced
- **4-way**, not 5-way (`allow_read_only`, `require_shadow_replay`, `require_user_approval`, `deny`)
- heavily threat-skewed (~81.95% threat-positive)

## Best local build on 8GB

- **Primary expert:** `answerdotai/ModernBERT-base` in a hierarchical setup
- **Multilingual expert:** `microsoft/mdeberta-v3-base` in the same setup
- **Sentinel:** char+word hashing/TF-IDF + LogisticRegression or SGD
- **Stacker:** `CatBoostClassifier` or `XGBoost`

## Why the recipe changed

The previous recipe assumed a generic 5-way space and suggested Longformer for “16k+ single-pass” use. That is no longer the right recommendation.

### Updated realities
- The new additional dataset is **4-way**.
- `allow` is absent in v2, so the main head should be 4-way.
- Longformer official base supports **4096**, not 16k+.
- On an 8GB GPU, the best way to exploit long contexts is **hierarchical chunking**, not forcing one huge single-pass model.

## Recommended architecture

### Stage 1: high-recall sentinel
Train a binary classifier:
- positive = any of `require_shadow_replay`, `require_user_approval`, `deny`
- negative = `allow_read_only`

Use:
- char n-grams 3–6
- word n-grams 1–2
- URL/path features
- action type
- origin relation
- same-origin sensitive flag
- callback-like URI flag
- Unicode confusable score
- typoglycemia score
- approval-language score

Tune the threshold for recall first. The sentinel’s job is to keep true threats from slipping into `allow_read_only`.

### Stage 2: hierarchical deep expert
Build each chunk as:

`[GOAL] goal [SETUP] setup [ACTION] candidate_action [META] surface/lang/domain/channels [CONTEXT] chunk`

Then:
- encode 3 top-ranked chunks with ModernBERT or mDeBERTa
- aggregate with 2-layer Transformer or gated attention
- fuse metadata with an MLP
- predict:
  - 4-way decision
  - binary threat
  - multilabel reasons

### Stage 3: stack and calibrate
Train CatBoost or XGBoost on:
- sentinel probabilities
- deep logits
- pooled embedding features
- structured metadata

Use conservative routing: if the sentinel says “threat”, the final system should rarely emit `allow_read_only`.

## High-value processing rules

### Keep
- `goal`
- `setup`
- `context`
- `candidate_action`
- runtime-available metadata

### Drop as leakage
- `expected_label`
- `unauthorized_effect_risk`
- `reasons`
- `attack_family`
- `threat_basis`
- `difficulty`
- `research_grounding`

### Do not over-normalize
You want the model to see:
- odd punctuation
- Unicode confusables
- misspellings / typoglycemia
- suspicious path fragments
- callback patterns

Those are part of the threat signal.

## Training schedule

1. Smoke test on the 10k rendered sample + 20k new rows
2. Train the binary sentinel on the full 1M train split
3. Deep curriculum:
   - 1024 tokens -> 300k rows
   - 2048 tokens -> 600k rows
   - 4096 tokens -> full 1M with hard-negative replay
4. Train the stacker
5. Calibrate thresholds on validation

## Losses

Use:
- cost-sensitive CE for the 4-way head
- weighted BCE or asymmetric focal for the threat head
- BCE for reason codes
- optional supervised contrastive loss on pooled embeddings

The most important asymmetry:
- **gold threat -> predicted allow_read_only** must be heavily penalized

## 8GB-safe starting configuration

### Deep model
- 1024 tokens: batch 4, grad accumulation 8
- 2048 tokens: batch 2, grad accumulation 16
- 4096 tokens: batch 1, grad accumulation 16

### Memory controls
- gradient checkpointing
- fp16 or bf16
- 8-bit AdamW
- LoRA or DoRA adapters
- optional quantized loading if the backbone supports it

## Metrics that matter

Optimize for:
- threat recall
- threat false negative rate
- deny recall
- approval recall
- cost-weighted error

Also track slices:
- same-origin-sensitive cases
- visible workflow smuggling
- callback drift
- Unicode confusable cases
- multilingual mixed-language cases

## Strongest recommendation

If you want one concrete choice:

**Train a hierarchical ModernBERT-base deep expert, pair it with a char-ngram sentinel, and use CatBoost as the final stacker.**

That is the most sophisticated system I would recommend for your GPU while keeping the priority on reducing dangerous false negatives.
