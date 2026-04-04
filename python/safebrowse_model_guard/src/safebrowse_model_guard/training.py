from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .bundle import (
    copy_component_file,
    copy_component_tree,
    load_pickle,
    write_bundle_manifest,
    write_pickle,
)
from .data import load_manifest, manifest_record_count, manifest_storage_summary, resolve_split_files
from .features import LABEL_TO_ID, chunk_text, example_from_dataset_row, rank_chunks, structured_feature_dict

_TRANSFORMER_ARTIFACT_CACHE: dict[str, dict[str, Any]] = {}
_DEFAULT_RANDOM_SEED = 7
_DEFAULT_EXPERT_CHECKPOINT_STEPS = 500
_DEFAULT_SENTINEL_CHECKPOINT_BATCHES = 32


@dataclass
class IndexedRecord:
    index: int
    relative_path: str
    offset: int
    example_id: str
    label: str
    attack_family: str


@dataclass
class RecipeStage:
    name: str
    max_length: int
    epochs: float
    train_subset: int
    sampling: str
    batch_size: int
    gradient_accumulation_steps: int


@dataclass
class ExpertStagePlan:
    stage: RecipeStage
    plan_path: Path
    selected_indices: list[int]
    hard_negative_indices: list[int]


def _require_training_dependencies() -> dict[str, Any]:
    try:
        from scipy.sparse import hstack  # type: ignore
        from sklearn.feature_extraction import DictVectorizer  # type: ignore
        from sklearn.feature_extraction.text import HashingVectorizer, TfidfVectorizer  # type: ignore
        from sklearn.linear_model import SGDClassifier  # type: ignore
        from sklearn.metrics import f1_score, precision_recall_fscore_support, recall_score  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "Training requires the optional 'train' dependencies. Install "
            "'python/safebrowse_model_guard[train]' before running train/evaluate commands."
        ) from exc

    try:
        from catboost import CatBoostClassifier  # type: ignore
    except ModuleNotFoundError:
        CatBoostClassifier = None

    return {
        "hstack": hstack,
        "DictVectorizer": DictVectorizer,
        "HashingVectorizer": HashingVectorizer,
        "TfidfVectorizer": TfidfVectorizer,
        "SGDClassifier": SGDClassifier,
        "CatBoostClassifier": CatBoostClassifier,
        "f1_score": f1_score,
        "precision_recall_fscore_support": precision_recall_fscore_support,
        "recall_score": recall_score,
    }


def _require_transformer_dependencies() -> dict[str, Any]:
    try:
        import torch
        from torch.utils.data import DataLoader, IterableDataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "Transformer expert training requires torch and transformers. "
            "Install the optional train dependencies before running ModernBERT training."
        ) from exc
    return {
        "torch": torch,
        "DataLoader": DataLoader,
        "IterableDataset": IterableDataset,
        "AutoModelForSequenceClassification": AutoModelForSequenceClassification,
        "AutoTokenizer": AutoTokenizer,
    }


@dataclass
class ExpertChunkSample:
    text: str
    label: int


def _iter_examples(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    skip: int = 0,
    limit: int | None = None,
) -> Iterable[Any]:
    manifest = load_manifest(manifest_path)
    emitted = 0
    skipped = 0
    for path in resolve_split_files(manifest, split, data_root=data_root):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                if skipped < skip:
                    skipped += 1
                    continue
                yield example_from_dataset_row(json.loads(line))
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


def _total_examples(
    manifest_path: str | Path,
    split: str,
    *,
    limit: int | None = None,
) -> int | None:
    manifest = load_manifest(manifest_path)
    total = manifest_record_count(manifest, split)
    if total is None:
        return limit
    if limit is not None:
        return min(total, limit)
    return total


def _maybe_report(message: str) -> None:
    print(message, flush=True)


def _write_json(path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def _load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_recipe(recipe_path: str | Path) -> dict[str, Any]:
    return _load_json(recipe_path)


def _safe_stage_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in value)


def _iter_records_with_offsets(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    manifest = load_manifest(manifest_path)
    paths = resolve_split_files(manifest, split, data_root=data_root)
    emitted = 0
    for path in paths:
        relative = path.relative_to(path.parents[1]).as_posix()
        with path.open("r", encoding="utf-8") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                yield relative, offset, json.loads(line)
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


def _build_index(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
) -> list[IndexedRecord]:
    records: list[IndexedRecord] = []
    for relative_path, offset, row in _iter_records_with_offsets(
        manifest_path, split, data_root=data_root, limit=limit
    ):
        label = str(row.get("expected_label", "allow_read_only"))
        if label not in LABEL_TO_ID:
            continue
        records.append(
            IndexedRecord(
                index=len(records),
                relative_path=relative_path,
                offset=offset,
                example_id=str(row.get("id", len(records))),
                label=label,
                attack_family=str(row.get("attack_family", "none")),
            )
        )
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for item in records:
                handle.write(
                    json.dumps(
                        {
                            "index": item.index,
                            "relative_path": item.relative_path,
                            "offset": item.offset,
                            "example_id": item.example_id,
                            "label": item.label,
                            "attack_family": item.attack_family,
                        }
                    )
                    + "\n"
                )
    return records


def _load_index(index_path: str | Path) -> list[IndexedRecord]:
    entries: list[IndexedRecord] = []
    with Path(index_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            entries.append(
                IndexedRecord(
                    index=int(payload["index"]),
                    relative_path=str(payload["relative_path"]),
                    offset=int(payload["offset"]),
                    example_id=str(payload["example_id"]),
                    label=str(payload["label"]),
                    attack_family=str(payload.get("attack_family", "none")),
                )
            )
    return entries


def _load_or_build_index(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
    output_path: str | Path,
) -> list[IndexedRecord]:
    target = Path(output_path)
    if target.is_file():
        return _load_index(target)
    return _build_index(
        manifest_path,
        split,
        data_root=data_root,
        limit=limit,
        output_path=target,
    )


def _dataset_root_for_manifest(
    manifest_path: str | Path,
    *,
    data_root: str | Path | None = None,
) -> Path:
    manifest = load_manifest(manifest_path)
    dataset_subdir = manifest.get("storage", {}).get("dataset_subdir", "prompt_injection_ml_dataset")
    if data_root is None:
        from .data import resolve_data_root

        return resolve_data_root(None) / dataset_subdir
    return Path(data_root) / dataset_subdir


def _read_record_by_index(
    dataset_root: str | Path,
    index_records: list[IndexedRecord],
    record_index: int,
) -> dict[str, Any]:
    indexed = index_records[record_index]
    path = Path(dataset_root) / indexed.relative_path
    with path.open("r", encoding="utf-8") as handle:
        handle.seek(indexed.offset)
        line = handle.readline()
    return json.loads(line)


def _iter_examples_from_index_plan(
    dataset_root: str | Path,
    index_records: list[IndexedRecord],
    selected_indices: list[int],
    *,
    skip: int = 0,
) -> Iterator[Any]:
    for position, record_index in enumerate(selected_indices):
        if position < skip:
            continue
        yield example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))


def _format_chunk_text(example: Any, context_chunk: str) -> str:
    return "\n".join(
        [
            f"[GOAL] {example.goal}",
            f"[SETUP] {example.setup}",
            f"[ACTION] {example.candidate_action}",
            (
                f"[META] surface={example.surface} lang={example.lang} "
                f"domain={example.domain} channels={','.join(example.channels)}"
            ),
            f"[CONTEXT] {context_chunk}",
        ]
    )


def _latest_checkpoint_dir(checkpoint_dir: str | Path) -> Path | None:
    root = Path(checkpoint_dir)
    if not root.is_dir():
        return None
    candidates = [path for path in root.iterdir() if path.is_dir() and (path / "state.json").is_file()]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def prepare_data(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary = manifest_storage_summary(load_manifest(manifest_path), data_root=data_root)
    target = output_path / "prepared_data_summary.json"
    target.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return {"preparedDataSummary": str(target), **summary}


def train_sentinel(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    threat_threshold: float = 0.55,
    checkpoint_dir: str | Path | None = None,
    checkpoint_batches: int = _DEFAULT_SENTINEL_CHECKPOINT_BATCHES,
    resume: bool = False,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    HashingVectorizer = deps["HashingVectorizer"]
    SGDClassifier = deps["SGDClassifier"]
    hstack = deps["hstack"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    char_vectorizer = HashingVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 6),
        n_features=2**18,
        alternate_sign=False,
        norm="l2",
    )
    word_vectorizer = HashingVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        n_features=2**16,
        alternate_sign=False,
        norm="l2",
    )
    classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=7)
    batch_size = 2048
    total_examples = _total_examples(manifest_path, "train", limit=limit)
    processed_examples = 0
    processed_batches = 0
    fitted = False
    texts: list[str] = []
    labels: list[int] = []
    checkpoint_root = Path(checkpoint_dir) if checkpoint_dir is not None else output_path / "checkpoints"

    latest_checkpoint = _latest_checkpoint_dir(checkpoint_root) if resume else None
    if latest_checkpoint is not None:
        checkpoint_artifact = load_pickle(latest_checkpoint / "sentinel_checkpoint.pkl")
        classifier = checkpoint_artifact["classifier"]
        processed_examples = int(checkpoint_artifact["processed_examples"])
        processed_batches = int(checkpoint_artifact["processed_batches"])
        fitted = bool(checkpoint_artifact["fitted"])
        _maybe_report(
            f"resuming sentinel from {latest_checkpoint.name} at example {processed_examples} batch {processed_batches}"
        )

    def save_checkpoint() -> None:
        checkpoint_name = f"batch-{processed_batches:06d}"
        checkpoint_path = checkpoint_root / checkpoint_name
        checkpoint_path.mkdir(parents=True, exist_ok=True)
        write_pickle(
            checkpoint_path / "sentinel_checkpoint.pkl",
            {
                "classifier": classifier,
                "processed_examples": processed_examples,
                "processed_batches": processed_batches,
                "fitted": fitted,
            },
        )
        _write_json(
            checkpoint_path / "state.json",
            {
                "processedExamples": processed_examples,
                "processedBatches": processed_batches,
                "totalExamples": total_examples,
                "batchSize": batch_size,
            },
        )

    def fit_batch() -> None:
        nonlocal fitted, processed_batches, texts, labels
        if not texts:
            return
        matrix = hstack(
            [char_vectorizer.transform(texts), word_vectorizer.transform(texts)],
            format="csr",
        )
        if not fitted:
            classifier.partial_fit(matrix, labels, classes=[0, 1])
            fitted = True
        else:
            classifier.partial_fit(matrix, labels)
        processed_batches += 1
        texts = []
        labels = []
        if checkpoint_batches > 0 and processed_batches % checkpoint_batches == 0:
            save_checkpoint()

    if total_examples is not None:
        _maybe_report(f"starting streaming sentinel training for {total_examples} examples")
    else:
        _maybe_report("starting streaming sentinel training")
    remaining_limit = None if limit is None else max(0, limit - processed_examples)
    for example in _iter_examples(
        manifest_path,
        "train",
        data_root=data_root,
        skip=processed_examples,
        limit=remaining_limit,
    ):
        texts.append(example.text)
        labels.append(int(example.threat_positive or 0))
        processed_examples += 1
        if len(texts) >= batch_size:
            fit_batch()
            if processed_batches == 1 or processed_batches % 16 == 0:
                if total_examples is not None:
                    _maybe_report(
                        f"processed {processed_examples}/{total_examples} training examples across {processed_batches} batches"
                    )
                else:
                    _maybe_report(
                        f"processed {processed_examples} training examples across {processed_batches} batches"
                    )
    fit_batch()
    if not fitted:
        raise RuntimeError("No training examples were available for sentinel training.")
    if checkpoint_batches > 0:
        save_checkpoint()

    artifact_path = write_pickle(
        output_path / "sentinel.pkl",
        {
            "char_vectorizer": char_vectorizer,
            "word_vectorizer": word_vectorizer,
            "classifier": classifier,
            "threshold": threat_threshold,
            "hstack": hstack,
        },
    )
    summary = {
        "artifact": str(artifact_path),
        "backend": "sklearn_binary",
        "threshold": threat_threshold,
        "examples": processed_examples,
        "batches": processed_batches,
        "batchSize": batch_size,
        "checkpointDir": str(checkpoint_root),
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _top_ranked_chunks(example: Any, *, top_k_chunks: int) -> list[str]:
    base_context = example.context or example.text
    chunks = chunk_text(base_context)
    ranked = rank_chunks(chunks, example.goal, example.candidate_action)
    selected = [chunk for _, chunk in ranked[:top_k_chunks]] if ranked else chunks[:top_k_chunks]
    selected = selected or [base_context]
    return [_format_chunk_text(example, chunk) for chunk in selected]


def _hierarchical_text(example: Any, *, top_k_chunks: int = 3) -> str:
    return "\n\n".join(_top_ranked_chunks(example, top_k_chunks=top_k_chunks))


def _build_chunk_samples(
    manifest_path: str | Path,
    *,
    split: str = "train",
    data_root: str | Path | None = None,
    limit: int | None = None,
    top_k_chunks: int = 3,
) -> list[ExpertChunkSample]:
    samples: list[ExpertChunkSample] = []
    for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
        if example.decision_label not in LABEL_TO_ID:
            continue
        for chunk in _top_ranked_chunks(example, top_k_chunks=top_k_chunks):
            samples.append(ExpertChunkSample(text=chunk, label=LABEL_TO_ID[example.decision_label]))
    return samples


def _iter_chunk_samples(
    manifest_path: str | Path,
    *,
    split: str = "train",
    data_root: str | Path | None = None,
    limit: int | None = None,
    top_k_chunks: int = 3,
) -> Iterable[ExpertChunkSample]:
    for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
        if example.decision_label not in LABEL_TO_ID:
            continue
        for chunk in _top_ranked_chunks(example, top_k_chunks=top_k_chunks):
            yield ExpertChunkSample(text=chunk, label=LABEL_TO_ID[example.decision_label])


def _train_smoke_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str,
    top_k_chunks: int,
    selected_indices: list[int] | None = None,
    index_records: list[IndexedRecord] | None = None,
    stage_name: str | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    TfidfVectorizer = deps["TfidfVectorizer"]
    SGDClassifier = deps["SGDClassifier"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=1,
        max_features=120_000,
    )
    classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=7)
    texts: list[str] = []
    labels: list[str] = []
    total_examples = len(selected_indices) if selected_indices is not None else _total_examples(manifest_path, "train", limit=limit)
    processed_examples = 0

    if selected_indices is not None:
        if index_records is None:
            index_records = _build_index(manifest_path, "train", data_root=data_root, limit=limit)
        dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)
        iterator = _iter_examples_from_index_plan(dataset_root, index_records, selected_indices)
    else:
        iterator = _iter_examples(manifest_path, "train", data_root=data_root, limit=limit)

    for example in iterator:
        if example.decision_label not in LABEL_TO_ID:
            continue
        texts.append(_hierarchical_text(example, top_k_chunks=top_k_chunks))
        labels.append(example.decision_label)
        processed_examples += 1
        if processed_examples == 1 or processed_examples % 5000 == 0:
            if total_examples is not None:
                _maybe_report(f"prepared {processed_examples}/{total_examples} expert examples for smoke backend")
            else:
                _maybe_report(f"prepared {processed_examples} expert examples for smoke backend")

    matrix = vectorizer.fit_transform(texts)
    classifier.fit(matrix, labels)
    artifact_path = write_pickle(
        output_path / "expert.pkl",
        {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "label_order": list(classifier.classes_),
            "intended_backbone": backbone,
            "top_k_chunks": top_k_chunks,
        },
    )
    summary = {
        "artifact": str(artifact_path),
        "backend": "sklearn_hierarchical_multiclass",
        "examples": len(labels),
        "intendedBackbone": backbone,
        "topKChunks": top_k_chunks,
        "stageName": stage_name,
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _load_recipe_stages(recipe: dict[str, Any]) -> list[RecipeStage]:
    stages: list[RecipeStage] = []
    batch_config = recipe.get("rtx4060ti_8gb_profile", {}).get("deep_model_batching", {})
    for item in recipe.get("training_plan", {}).get("phase_2_deep_curriculum", []):
        max_length = int(item["max_length"])
        batch_key = f"{max_length}_tokens"
        batch_profile = batch_config.get(batch_key, {})
        stages.append(
            RecipeStage(
                name=str(item["stage"]),
                max_length=max_length,
                epochs=float(item["epochs"]),
                train_subset=int(item["train_subset"]),
                sampling=str(item.get("sampling", "")),
                batch_size=int(batch_profile.get("per_device_batch_size", 1)),
                gradient_accumulation_steps=int(batch_profile.get("gradient_accumulation_steps", 1)),
            )
        )
    if not stages:
        raise RuntimeError("Recipe did not declare any deep curriculum stages.")
    return stages


def _write_plan_indices(path: str | Path, indices: list[int]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for index in indices:
            handle.write(f"{index}\n")
    return target


def _load_plan_indices(path: str | Path) -> list[int]:
    values: list[int] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                values.append(int(line))
    return values


def _shuffled(values: list[int], *, seed: int) -> list[int]:
    rng = random.Random(seed)
    copy = list(values)
    rng.shuffle(copy)
    return copy


def _take_weighted_indices(
    hard: list[int],
    normal: list[int],
    *,
    quota: int,
    seed: int,
    hard_multiplier: int = 2,
) -> list[int]:
    pool = list(normal)
    for _ in range(max(1, hard_multiplier)):
        pool.extend(hard)
    if not pool:
        return []
    pool = _shuffled(pool, seed=seed)
    if len(pool) >= quota:
        return pool[:quota]
    expanded: list[int] = []
    while len(expanded) < quota:
        expanded.extend(pool)
    return expanded[:quota]


def _scaled_label_quotas(total: int, label_distribution: dict[str, int]) -> dict[str, int]:
    total_distribution = sum(int(value) for value in label_distribution.values()) or 1
    ordered_labels = list(LABEL_TO_ID.keys())
    quotas: dict[str, int] = {}
    assigned = 0
    for label in ordered_labels[:-1]:
        raw = total * int(label_distribution.get(label, 0)) / total_distribution
        quota = int(math.floor(raw))
        quotas[label] = quota
        assigned += quota
    quotas[ordered_labels[-1]] = max(0, total - assigned)
    return quotas


def _select_stage_indices(
    index_records: list[IndexedRecord],
    *,
    stage: RecipeStage,
    hard_families: set[str],
    label_distribution: dict[str, int],
    seed: int,
) -> list[int]:
    by_label_hard: dict[str, list[int]] = {label: [] for label in LABEL_TO_ID}
    by_label_normal: dict[str, list[int]] = {label: [] for label in LABEL_TO_ID}
    for item in index_records:
        bucket = by_label_hard if item.attack_family in hard_families else by_label_normal
        bucket[item.label].append(item.index)

    if "balanced by label" in stage.sampling:
        base_quota = stage.train_subset // max(1, len(LABEL_TO_ID))
        remainder = stage.train_subset - (base_quota * len(LABEL_TO_ID))
        quotas = {label: base_quota for label in LABEL_TO_ID}
        for label in list(LABEL_TO_ID.keys())[:remainder]:
            quotas[label] += 1
    elif "sampled negatives" in stage.sampling:
        quotas = _scaled_label_quotas(stage.train_subset, label_distribution)
    else:
        quotas = {label: 0 for label in LABEL_TO_ID}
        for item in index_records[: stage.train_subset]:
            quotas[item.label] += 1

    selected: list[int] = []
    for offset, label in enumerate(LABEL_TO_ID.keys(), start=1):
        quota = quotas.get(label, 0)
        selected.extend(
            _take_weighted_indices(
                by_label_hard[label],
                by_label_normal[label],
                quota=quota,
                seed=seed + offset,
                hard_multiplier=2,
            )
        )
    return _shuffled(selected, seed=seed + 100)


def _write_stage_plan(
    output_dir: str | Path,
    *,
    stage: RecipeStage,
    selected_indices: list[int],
    hard_negative_indices: list[int] | None = None,
) -> ExpertStagePlan:
    stage_dir = Path(output_dir) / _safe_stage_name(stage.name)
    stage_dir.mkdir(parents=True, exist_ok=True)
    plan_path = _write_plan_indices(stage_dir / "plan.txt", selected_indices)
    if hard_negative_indices is None:
        hard_negative_indices = []
    _write_json(
        stage_dir / "plan_summary.json",
        {
            "stage": stage.name,
            "maxLength": stage.max_length,
            "epochs": stage.epochs,
            "trainSubset": stage.train_subset,
            "batchSize": stage.batch_size,
            "gradientAccumulationSteps": stage.gradient_accumulation_steps,
            "planEntries": len(selected_indices),
            "hardNegativeReplayEntries": len(hard_negative_indices),
        },
    )
    return ExpertStagePlan(
        stage=stage,
        plan_path=plan_path,
        selected_indices=selected_indices,
        hard_negative_indices=hard_negative_indices,
    )


def _save_transformer_expert_metadata(
    output_path: Path,
    *,
    backbone: str,
    top_k_chunks: int,
    max_length: int,
    epochs: float,
    batch_size: int,
    gradient_accumulation_steps: int,
    learning_rate: float,
    device_name: str,
    example_count: int,
    average_loss: float,
    stage_name: str | None = None,
    plan_entries: int | None = None,
    checkpoint_dir: str | None = None,
) -> dict[str, Any]:
    summary = {
        "artifact_dir": "expert_model",
        "backend": "transformers_modernbert_chunk_expert",
        "examples": example_count,
        "intendedBackbone": backbone,
        "topKChunks": top_k_chunks,
        "maxLength": max_length,
        "epochs": epochs,
        "batchSize": batch_size,
        "gradientAccumulationSteps": gradient_accumulation_steps,
        "learningRate": learning_rate,
        "device": device_name,
        "averageLoss": average_loss,
        "aggregation": "max_logits",
        "stageName": stage_name,
        "planEntries": plan_entries,
        "checkpointDir": checkpoint_dir,
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _train_transformer_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str,
    top_k_chunks: int,
    max_length: int,
    epochs: float,
    batch_size: int,
    gradient_accumulation_steps: int,
    learning_rate: float,
    selected_indices: list[int] | None = None,
    index_records: list[IndexedRecord] | None = None,
    checkpoint_dir: str | Path | None = None,
    checkpoint_steps: int = _DEFAULT_EXPERT_CHECKPOINT_STEPS,
    resume: bool = False,
    stage_name: str | None = None,
) -> dict[str, Any]:
    deps = _require_transformer_dependencies()
    torch = deps["torch"]
    AutoTokenizer = deps["AutoTokenizer"]
    AutoModelForSequenceClassification = deps["AutoModelForSequenceClassification"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    checkpoint_root = Path(checkpoint_dir) if checkpoint_dir is not None else output_path / "checkpoints"
    if selected_indices is None:
        selected_indices = list(range(_total_examples(manifest_path, "train", limit=limit) or 0))
    if index_records is None:
        index_records = _build_index(manifest_path, "train", data_root=data_root, limit=limit)
    dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)
    total_plan_entries = len(selected_indices)
    total_target_records = max(1, int(math.ceil(total_plan_entries * epochs)))

    latest_checkpoint = _latest_checkpoint_dir(checkpoint_root) if resume else None
    if latest_checkpoint is not None:
        tokenizer = AutoTokenizer.from_pretrained(latest_checkpoint / "expert_model")
        model = AutoModelForSequenceClassification.from_pretrained(latest_checkpoint / "expert_model")
        state = _load_json(latest_checkpoint / "state.json")
        start_records_seen = int(state.get("recordsSeen", 0))
        total_loss = float(state.get("totalLoss", 0.0))
        optimizer_steps = int(state.get("optimizerSteps", 0))
        micro_batches_seen = int(state.get("microBatchesSeen", 0))
        _maybe_report(
            f"resuming expert from {latest_checkpoint.name} at record {start_records_seen} optimizer_step {optimizer_steps}"
        )
    else:
        tokenizer = AutoTokenizer.from_pretrained(backbone)
        model = AutoModelForSequenceClassification.from_pretrained(
            backbone,
            num_labels=len(LABEL_TO_ID),
            label2id=LABEL_TO_ID,
            id2label={index: label for label, index in LABEL_TO_ID.items()},
        )
        start_records_seen = 0
        total_loss = 0.0
        optimizer_steps = 0
        micro_batches_seen = 0
    if tokenizer.pad_token_id is not None:
        model.config.pad_token_id = tokenizer.pad_token_id

    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    if latest_checkpoint is not None and (latest_checkpoint / "optimizer.pt").is_file():
        optimizer.load_state_dict(torch.load(latest_checkpoint / "optimizer.pt", map_location=device))

    def save_checkpoint(records_seen: int, micro_batches: int, steps: int, loss_sum: float) -> None:
        checkpoint_name = f"step-{steps:06d}"
        checkpoint_path = checkpoint_root / checkpoint_name
        checkpoint_path.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(checkpoint_path / "expert_model")
        tokenizer.save_pretrained(checkpoint_path / "expert_model")
        torch.save(optimizer.state_dict(), checkpoint_path / "optimizer.pt")
        _write_json(
            checkpoint_path / "state.json",
            {
                "stageName": stage_name,
                "recordsSeen": records_seen,
                "microBatchesSeen": micro_batches,
                "optimizerSteps": steps,
                "totalLoss": loss_sum,
                "totalTargetRecords": total_target_records,
                "batchSize": batch_size,
                "gradientAccumulationSteps": gradient_accumulation_steps,
                "topKChunks": top_k_chunks,
                "maxLength": max_length,
            },
        )

    def iter_training_records(start_position: int) -> Iterator[Any]:
        seen = 0
        while seen < total_target_records - start_position:
            plan_index = (start_position + seen) % total_plan_entries
            record_index = selected_indices[plan_index]
            yield example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))
            seen += 1

    def iter_batches(start_position: int) -> Iterator[tuple[int, list[list[str]], list[int]]]:
        current_chunks: list[list[str]] = []
        current_labels: list[int] = []
        records_consumed = start_position
        for example in iter_training_records(start_position):
            chunks = _top_ranked_chunks(example, top_k_chunks=top_k_chunks)
            if len(chunks) < top_k_chunks:
                chunks = chunks + [chunks[-1]] * (top_k_chunks - len(chunks))
            current_chunks.append(chunks[:top_k_chunks])
            current_labels.append(LABEL_TO_ID[example.decision_label or "allow_read_only"])
            records_consumed += 1
            if len(current_labels) >= batch_size:
                yield records_consumed, current_chunks, current_labels
                current_chunks = []
                current_labels = []
        if current_labels:
            yield records_consumed, current_chunks, current_labels

    _maybe_report(
        f"starting transformer expert training on {device} for {total_target_records} records "
        f"({total_plan_entries} plan entries, stage={stage_name or 'default'})"
    )

    model.train()
    optimizer.zero_grad(set_to_none=True)
    records_seen = start_records_seen
    accumulation_counter = 0
    last_reported_step = optimizer_steps
    for records_seen, batch_chunks, batch_labels in iter_batches(start_records_seen):
        flat_chunks = [chunk for chunk_group in batch_chunks for chunk in chunk_group]
        encoded = tokenizer(
            flat_chunks,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        labels_tensor = torch.tensor(batch_labels, dtype=torch.long, device=device)
        logits = model(**encoded).logits
        logits = logits.view(len(batch_labels), top_k_chunks, len(LABEL_TO_ID)).amax(dim=1)
        loss = torch.nn.functional.cross_entropy(logits, labels_tensor)
        (loss / max(1, gradient_accumulation_steps)).backward()
        total_loss += float(loss.detach().cpu())
        micro_batches_seen += 1
        accumulation_counter += 1

        should_step = accumulation_counter >= max(1, gradient_accumulation_steps) or records_seen >= total_target_records
        if should_step:
            optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            optimizer_steps += 1
            accumulation_counter = 0
            if checkpoint_steps > 0 and optimizer_steps % checkpoint_steps == 0:
                save_checkpoint(records_seen, micro_batches_seen, optimizer_steps, total_loss)

        if optimizer_steps == 1 or optimizer_steps % 25 == 0:
            if optimizer_steps != last_reported_step:
                average_loss = total_loss / max(1, micro_batches_seen)
                _maybe_report(
                    (
                        f"stage {stage_name or 'default'}, optimizer_step {optimizer_steps}, "
                        f"records {records_seen}/{total_target_records}, avg_loss={average_loss:.6f}"
                    )
                )
                last_reported_step = optimizer_steps

    model_dir = output_path / "expert_model"
    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)
    if micro_batches_seen == 0:
        raise RuntimeError("No chunk samples were produced for expert training.")
    save_checkpoint(records_seen, micro_batches_seen, optimizer_steps, total_loss)
    summary = _save_transformer_expert_metadata(
        output_path,
        backbone=backbone,
        top_k_chunks=top_k_chunks,
        max_length=max_length,
        epochs=epochs,
        batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        device_name=str(device),
        example_count=records_seen,
        average_loss=(total_loss / max(1, micro_batches_seen)),
        stage_name=stage_name,
        plan_entries=total_plan_entries,
        checkpoint_dir=str(checkpoint_root),
    )
    if str(device) == "cuda":
        torch.cuda.empty_cache()
    return summary


def train_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str = "answerdotai/ModernBERT-base",
    backend: str = "transformers",
    max_length: int = 1024,
    top_k_chunks: int = 3,
    epochs: float = 1.0,
    batch_size: int = 1,
    gradient_accumulation_steps: int = 1,
    learning_rate: float = 2e-5,
    selected_indices: list[int] | None = None,
    index_records: list[IndexedRecord] | None = None,
    checkpoint_dir: str | Path | None = None,
    checkpoint_steps: int = _DEFAULT_EXPERT_CHECKPOINT_STEPS,
    resume: bool = False,
    stage_name: str | None = None,
) -> dict[str, Any]:
    if backend == "smoke":
        return _train_smoke_expert(
            manifest_path,
            output_dir=output_dir,
            data_root=data_root,
            limit=limit,
            backbone=backbone,
            top_k_chunks=top_k_chunks,
            selected_indices=selected_indices,
            index_records=index_records,
            stage_name=stage_name,
        )
    return _train_transformer_expert(
        manifest_path,
        output_dir=output_dir,
        data_root=data_root,
        limit=limit,
        backbone=backbone,
        top_k_chunks=top_k_chunks,
        max_length=max_length,
        epochs=epochs,
        batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        selected_indices=selected_indices,
        index_records=index_records,
        checkpoint_dir=checkpoint_dir,
        checkpoint_steps=checkpoint_steps,
        resume=resume,
        stage_name=stage_name,
    )


def _collect_hard_negative_indices(
    expert_dir: str | Path,
    *,
    dataset_root: str | Path,
    index_records: list[IndexedRecord],
    selected_indices: list[int],
) -> list[int]:
    hard_negative_indices: list[int] = []
    total = len(selected_indices)
    expert_summary = _load_expert_summary(expert_dir)
    for position, record_index in enumerate(selected_indices, start=1):
        example = example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))
        prediction = _score_expert_artifact(expert_dir, example, expert_summary=expert_summary)
        predicted_label = max(prediction.items(), key=lambda item: item[1])[0]
        gold_label = example.decision_label or "allow_read_only"
        is_hard_negative = (
            (gold_label != "allow_read_only" and predicted_label == "allow_read_only")
            or (gold_label == "deny" and predicted_label == "require_shadow_replay")
            or (
                gold_label == "require_user_approval"
                and predicted_label in {"require_shadow_replay", "deny"}
            )
        )
        if is_hard_negative:
            hard_negative_indices.append(record_index)
        if position == 1 or position % 2000 == 0:
            _maybe_report(
                f"scored {position}/{total} stage examples for hard-negative replay; found {len(hard_negative_indices)}"
            )
    return hard_negative_indices


def train_recipe(
    manifest_path: str | Path,
    *,
    recipe_path: str | Path,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    backbone: str = "answerdotai/ModernBERT-base",
    backend: str = "transformers",
    threat_threshold: float = 0.55,
    checkpoint_steps: int = _DEFAULT_EXPERT_CHECKPOINT_STEPS,
    bundle_version: str | None = None,
    resume: bool = True,
) -> dict[str, Any]:
    recipe = _load_recipe(recipe_path)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    train_limit = int(recipe.get("dataset_profile", {}).get("train_records", 1_000_000))
    valid_limit = int(recipe.get("dataset_profile", {}).get("valid_records", 100_000))
    test_limit = int(recipe.get("dataset_profile", {}).get("test_records", 100_000))
    top_k_chunks = int(recipe.get("deep_architecture", {}).get("chunking", {}).get("top_k_chunks", 3))
    hard_families = {
        str(value) for value in recipe.get("dataset_profile", {}).get("high_confusion_attack_families_to_oversample", [])
    }
    label_distribution = {
        str(key): int(value)
        for key, value in recipe.get("dataset_profile", {}).get("label_distribution_train", {}).items()
    }
    replay_factor = int(recipe.get("training_plan", {}).get("phase_3_hard_negative_mining", {}).get("replay_factor", 3))
    dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)

    index_dir = output_path / "index"
    train_index = _load_or_build_index(
        manifest_path,
        "train",
        data_root=data_root,
        limit=train_limit,
        output_path=index_dir / "train_index.jsonl",
    )

    sentinel_dir = output_path / "sentinel"
    if resume and (sentinel_dir / "summary.json").is_file():
        sentinel_summary = _load_json(sentinel_dir / "summary.json")
    else:
        sentinel_summary = train_sentinel(
            manifest_path,
            output_dir=sentinel_dir,
            data_root=data_root,
            limit=train_limit,
            threat_threshold=threat_threshold,
            checkpoint_dir=sentinel_dir / "checkpoints",
            resume=resume,
        )

    stages = _load_recipe_stages(recipe)
    expert_root = output_path / "expert"
    plan_root = expert_root / "plans"
    plan_root.mkdir(parents=True, exist_ok=True)
    stage_summaries: list[dict[str, Any]] = []
    previous_backbone = backbone
    previous_stage_dir: Path | None = None
    stage_plans: dict[str, ExpertStagePlan] = {}

    for stage in stages[:-1]:
        plan_path = plan_root / f"{_safe_stage_name(stage.name)}.txt"
        if plan_path.is_file():
            selected_indices = _load_plan_indices(plan_path)
        else:
            selected_indices = _select_stage_indices(
                train_index,
                stage=stage,
                hard_families=hard_families,
                label_distribution=label_distribution,
                seed=_DEFAULT_RANDOM_SEED + len(stage_plans),
            )
            _write_plan_indices(plan_path, selected_indices)
        stage_plan = _write_stage_plan(plan_root, stage=stage, selected_indices=selected_indices)
        stage_plans[stage.name] = stage_plan
        stage_dir = expert_root / _safe_stage_name(stage.name)
        if resume and (stage_dir / "summary.json").is_file():
            stage_summary = _load_json(stage_dir / "summary.json")
        else:
            stage_summary = train_expert(
                manifest_path,
                output_dir=stage_dir,
                data_root=data_root,
                backbone=str(previous_backbone),
                backend=backend,
                max_length=stage.max_length,
                top_k_chunks=top_k_chunks,
                epochs=stage.epochs,
                batch_size=stage.batch_size,
                gradient_accumulation_steps=stage.gradient_accumulation_steps,
                learning_rate=2e-5,
                selected_indices=stage_plan.selected_indices,
                index_records=train_index,
                checkpoint_dir=stage_dir / "checkpoints",
                checkpoint_steps=checkpoint_steps,
                resume=resume,
                stage_name=stage.name,
            )
        stage_summaries.append(stage_summary)
        previous_stage_dir = stage_dir
        previous_backbone = str(stage_dir / "expert_model")

    final_stage = stages[-1]
    hard_negative_path = plan_root / f"{_safe_stage_name(final_stage.name)}_hard_negatives.txt"
    if hard_negative_path.is_file():
        hard_negative_indices = _load_plan_indices(hard_negative_path)
    else:
        if previous_stage_dir is None:
            raise RuntimeError("Final recipe stage requires a completed previous expert stage.")
        reference_plan = stage_plans[stages[-2].name].selected_indices
        hard_negative_indices = _collect_hard_negative_indices(
            previous_stage_dir,
            dataset_root=dataset_root,
            index_records=train_index,
            selected_indices=reference_plan,
        )
        _write_plan_indices(hard_negative_path, hard_negative_indices)

    final_plan_path = plan_root / f"{_safe_stage_name(final_stage.name)}.txt"
    if final_plan_path.is_file():
        final_selected_indices = _load_plan_indices(final_plan_path)
    else:
        final_selected_indices = [item.index for item in train_index]
        for record_index in hard_negative_indices:
            final_selected_indices.extend([record_index] * replay_factor)
        _write_plan_indices(final_plan_path, final_selected_indices)
    final_stage_plan = _write_stage_plan(
        plan_root,
        stage=final_stage,
        selected_indices=final_selected_indices,
        hard_negative_indices=hard_negative_indices,
    )
    stage_plans[final_stage.name] = final_stage_plan
    final_stage_dir = expert_root / _safe_stage_name(final_stage.name)
    if resume and (final_stage_dir / "summary.json").is_file():
        final_stage_summary = _load_json(final_stage_dir / "summary.json")
    else:
        final_stage_summary = train_expert(
            manifest_path,
            output_dir=final_stage_dir,
            data_root=data_root,
            backbone=str(previous_backbone),
            backend=backend,
            max_length=final_stage.max_length,
            top_k_chunks=top_k_chunks,
            epochs=final_stage.epochs,
            batch_size=final_stage.batch_size,
            gradient_accumulation_steps=final_stage.gradient_accumulation_steps,
            learning_rate=2e-5,
            selected_indices=final_stage_plan.selected_indices,
            index_records=train_index,
            checkpoint_dir=final_stage_dir / "checkpoints",
            checkpoint_steps=checkpoint_steps,
            resume=resume,
            stage_name=final_stage.name,
        )
    stage_summaries.append(final_stage_summary)

    stacker_dir = output_path / "stacker"
    if resume and (stacker_dir / "summary.json").is_file():
        stacker_summary = _load_json(stacker_dir / "summary.json")
    else:
        stacker_summary = train_stacker(
            manifest_path,
            sentinel_dir=sentinel_dir,
            expert_dir=final_stage_dir,
            output_dir=stacker_dir,
            data_root=data_root,
            limit=train_limit,
        )

    runtime_bundle_dir = output_path / "runtime_bundle"
    if bundle_version is None:
        bundle_version = f"{recipe.get('version', 'recipe')}-runtime"
    bundle_summary = package_runtime_bundle(
        sentinel_dir,
        final_stage_dir,
        stacker_dir,
        output_dir=runtime_bundle_dir,
        bundle_version=bundle_version,
    )

    valid_metrics = evaluate(
        manifest_path,
        bundle_dir=runtime_bundle_dir,
        split="valid",
        data_root=data_root,
        limit=valid_limit,
        output_path=output_path / "metrics-valid.json",
    )
    test_metrics = evaluate(
        manifest_path,
        bundle_dir=runtime_bundle_dir,
        split="test",
        data_root=data_root,
        limit=test_limit,
        output_path=output_path / "metrics-test.json",
    )

    summary = {
        "recipeVersion": recipe.get("version"),
        "manifest": str(manifest_path),
        "recipePath": str(recipe_path),
        "trainLimit": train_limit,
        "validLimit": valid_limit,
        "testLimit": test_limit,
        "sentinel": sentinel_summary,
        "expertStages": stage_summaries,
        "hardNegativeReplayCount": len(hard_negative_indices),
        "stacker": stacker_summary,
        "bundle": bundle_summary,
        "metrics": {
            "valid": valid_metrics,
            "test": test_metrics,
        },
    }
    _write_json(output_path / "recipe_summary.json", summary)
    return summary


def _load_expert_summary(expert_dir: str | Path) -> dict[str, Any]:
    return json.loads((Path(expert_dir) / "summary.json").read_text(encoding="utf-8"))


def _score_transformer_expert_artifact(expert_dir: str | Path, example: Any) -> dict[str, float]:
    deps = _require_transformer_dependencies()
    torch = deps["torch"]
    AutoTokenizer = deps["AutoTokenizer"]
    AutoModelForSequenceClassification = deps["AutoModelForSequenceClassification"]

    summary = _load_expert_summary(expert_dir)
    model_dir = Path(expert_dir) / summary["artifact_dir"]
    cache_key = str(model_dir.resolve())
    cached = _TRANSFORMER_ARTIFACT_CACHE.get(cache_key)
    if cached is None:
        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        cached = {"tokenizer": tokenizer, "model": model, "device": device}
        _TRANSFORMER_ARTIFACT_CACHE[cache_key] = cached

    tokenizer = cached["tokenizer"]
    model = cached["model"]
    device = cached["device"]

    chunks = _top_ranked_chunks(example, top_k_chunks=int(summary.get("topKChunks", 3)))
    top_k_chunks = int(summary.get("topKChunks", 3))
    if len(chunks) < top_k_chunks:
        chunks = chunks + [chunks[-1]] * (top_k_chunks - len(chunks))
    encoded = tokenizer(
        chunks,
        truncation=True,
        padding=True,
        max_length=int(summary.get("maxLength", 1024)),
        return_tensors="pt",
    )
    encoded = {key: value.to(device) for key, value in encoded.items()}
    with torch.no_grad():
        logits = model(**encoded).logits
        aggregated_logits = logits.view(1, top_k_chunks, len(LABEL_TO_ID)).amax(dim=1)
        probabilities = torch.softmax(aggregated_logits, dim=-1).detach().cpu().tolist()[0]

    return {
        label: float(probabilities[index])
        for label, index in LABEL_TO_ID.items()
    }


def _score_expert_artifact(
    expert_dir: str | Path,
    example: Any,
    *,
    expert_summary: dict[str, Any] | None = None,
) -> dict[str, float]:
    if expert_summary is None:
        expert_summary = _load_expert_summary(expert_dir)
    if expert_summary["backend"] == "transformers_modernbert_chunk_expert":
        return _score_transformer_expert_artifact(expert_dir, example)

    expert_artifact = load_pickle(Path(expert_dir) / "expert.pkl")
    vectorizer = expert_artifact["vectorizer"]
    expert_classifier = expert_artifact["classifier"]
    expert_matrix = vectorizer.transform(
        [_hierarchical_text(example, top_k_chunks=int(expert_summary.get("topKChunks", 3)))]
    )
    raw = expert_classifier.predict_proba(expert_matrix)[0]
    label_order = expert_artifact["label_order"]
    return {
        label_order[index]: float(raw[index]) for index in range(len(label_order))
    }


def _build_meta_example(
    example: Any,
    sentinel_artifact: dict[str, Any],
    expert_dir: str | Path,
    expert_summary: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    char_vectorizer = sentinel_artifact["char_vectorizer"]
    word_vectorizer = sentinel_artifact["word_vectorizer"]
    sentinel_classifier = sentinel_artifact["classifier"]
    hstack = sentinel_artifact["hstack"]
    sentinel_matrix = hstack(
        [char_vectorizer.transform([example.text]), word_vectorizer.transform([example.text])],
        format="csr",
    )
    sentinel_probability = float(sentinel_classifier.predict_proba(sentinel_matrix)[0][1])

    expert_probabilities = _score_expert_artifact(expert_dir, example, expert_summary=expert_summary)
    label_order = list(expert_probabilities.keys())

    features = structured_feature_dict(example.structured)
    features["sentinel_probability"] = sentinel_probability
    for label in label_order:
        features[f"expert_{label}"] = float(expert_probabilities.get(label, 0.0))
    return features, example.decision_label or "allow_read_only"


def train_stacker(
    manifest_path: str | Path,
    *,
    sentinel_dir: str | Path,
    expert_dir: str | Path,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    DictVectorizer = deps["DictVectorizer"]
    SGDClassifier = deps["SGDClassifier"]
    CatBoostClassifier = deps["CatBoostClassifier"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    sentinel_artifact = load_pickle(Path(sentinel_dir) / "sentinel.pkl")
    expert_summary = _load_expert_summary(expert_dir)
    feature_rows: list[dict[str, Any]] = []
    labels: list[str] = []
    total_examples = _total_examples(manifest_path, "train", limit=limit)
    processed_examples = 0

    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
        if example.decision_label not in LABEL_TO_ID:
            continue
        features, label = _build_meta_example(example, sentinel_artifact, expert_dir, expert_summary)
        feature_rows.append(features)
        labels.append(label)
        processed_examples += 1
        if processed_examples == 1 or processed_examples % 2500 == 0:
            if total_examples is not None:
                _maybe_report(f"built {processed_examples}/{total_examples} stacker feature rows")
            else:
                _maybe_report(f"built {processed_examples} stacker feature rows")

    vectorizer = DictVectorizer(sparse=False)
    matrix = vectorizer.fit_transform(feature_rows)
    backend = "sklearn_multiclass"
    if CatBoostClassifier is not None:
        classifier = CatBoostClassifier(
            task_type="CPU",
            loss_function="MultiClass",
            depth=6,
            learning_rate=0.08,
            iterations=200,
            allow_writing_files=False,
            verbose=False,
        )
        classifier.fit(matrix, labels)
        backend = "catboost_multiclass"
    else:
        classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=7)
        classifier.fit(matrix, labels)

    artifact_path = write_pickle(
        output_path / "stacker.pkl",
        {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "label_order": list(getattr(classifier, "classes_", sorted(set(labels)))),
        },
    )
    summary = {
        "artifact": str(artifact_path),
        "backend": backend,
        "examples": len(labels),
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def package_runtime_bundle(
    sentinel_dir: str | Path,
    expert_dir: str | Path,
    stacker_dir: str | Path,
    *,
    output_dir: str | Path,
    bundle_version: str,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    sentinel_summary = json.loads((Path(sentinel_dir) / "summary.json").read_text(encoding="utf-8"))
    expert_summary = json.loads((Path(expert_dir) / "summary.json").read_text(encoding="utf-8"))
    stacker_summary = json.loads((Path(stacker_dir) / "summary.json").read_text(encoding="utf-8"))

    copy_component_file(sentinel_summary["artifact"], output_path, "sentinel.pkl")
    if expert_summary["backend"] == "transformers_modernbert_chunk_expert":
        copy_component_tree(Path(expert_dir) / expert_summary["artifact_dir"], output_path, "expert_model")
    else:
        copy_component_file(expert_summary["artifact"], output_path, "expert.pkl")
    copy_component_file(stacker_summary["artifact"], output_path, "stacker.pkl")

    expert_component: dict[str, Any] = {"backend": expert_summary["backend"], "backbone": expert_summary.get("intendedBackbone")}
    if expert_summary["backend"] == "transformers_modernbert_chunk_expert":
        expert_component.update(
            {
                "artifact_dir": "expert_model",
                "top_k_chunks": expert_summary.get("topKChunks", 3),
                "max_length": expert_summary.get("maxLength", 1024),
            }
        )
    else:
        expert_component["artifact"] = "expert.pkl"

    manifest = {
        "bundleVersion": bundle_version,
        "featureSchemaVersion": "v1",
        "pipeline": {
            "runtimeMode": "python_sidecar",
            "enforcementMode": "tighten",
            "sentinelVersion": Path(sentinel_summary["artifact"]).stem,
            "expertVersion": expert_summary["backend"],
            "stackerVersion": Path(stacker_summary["artifact"]).stem,
        },
        "components": {
            "sentinel": {"backend": sentinel_summary["backend"], "artifact": "sentinel.pkl"},
            "expert": expert_component,
            "stacker": {"backend": stacker_summary["backend"], "artifact": "stacker.pkl"},
        },
        "heuristics": {"sentinel_threshold": sentinel_summary.get("threshold", 0.55)},
    }
    manifest_path = write_bundle_manifest(output_path, manifest)
    return {"bundleDir": str(output_path), "bundleManifest": str(manifest_path)}


def evaluate(
    manifest_path: str | Path,
    *,
    bundle_dir: str | Path,
    split: str,
    data_root: str | Path | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    f1_score = deps["f1_score"]
    precision_recall_fscore_support = deps["precision_recall_fscore_support"]
    recall_score = deps["recall_score"]
    from .runtime import ModelGuardRuntime

    runtime = ModelGuardRuntime(bundle_dir)
    gold_labels: list[str] = []
    predicted_labels: list[str] = []
    gold_threat: list[int] = []
    predicted_threat: list[int] = []
    total_examples = _total_examples(manifest_path, split, limit=limit)
    processed_examples = 0

    for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
        request = {
            "session": {
                "sessionId": "eval-session",
                "taskId": "eval-task",
                "userGoal": "Evaluate a candidate action safely.",
                "allowedOrigins": ["https://example.test"],
                "allowedVerbs": ["GET"],
                "allowedPathClasses": ["content_read", "docs_navigation", "workflow_continue"],
                "approvalRequiredPathClasses": ["admin", "payment", "connector_setup"],
            },
            "observation": {
                "observationId": example.example_id,
                "sourceOrigin": "https://example.test",
                "frameOrigin": "https://example.test",
                "surfaceType": "html_visible",
                "parseStatus": "compiled",
                "visibleText": example.text[:4000],
                "contextText": example.text[:24000],
                "suspicionFlags": [],
                "matchedPatternIds": [],
                "riskFindings": [],
                "semanticAuthorityFindings": [],
                "policyFindings": [],
                "blockedChannels": [],
                "channelFlags": {"visible": True, "hidden": False},
                "secretRedactionCount": 0,
                "captureAttestation": {
                    "captureMethod": "rendered_dom",
                    "visibilityAttested": True,
                    "frameCoverage": "full",
                    "shadowDomCoverage": "full",
                    "unsupportedSubtrees": [],
                    "evidenceHash": "eval",
                },
                "contextChars": len(example.text),
            },
            "targets": [
                {
                    "kind": "navigate",
                    "targetUrl": "https://example.test/payments/finalize",
                    "targetOrigin": "https://example.test",
                    "targetPathClass": "payment",
                    "sourceSpanIds": ["eval-span"],
                }
            ],
            "structuredFeatures": structured_feature_dict(example.structured),
        }
        scored = runtime.score_observation(request)
        predicted = scored["assessment"]["calibratedDecisionLabel"]
        gold = example.decision_label or "allow_read_only"
        gold_labels.append(gold)
        predicted_labels.append(predicted)
        gold_threat.append(0 if gold == "allow_read_only" else 1)
        predicted_threat.append(0 if predicted == "allow_read_only" else 1)
        processed_examples += 1
        if processed_examples == 1 or processed_examples % 1000 == 0:
            if total_examples is not None:
                _maybe_report(f"evaluated {processed_examples}/{total_examples} {split} examples")
            else:
                _maybe_report(f"evaluated {processed_examples} {split} examples")

    threat_recall = float(recall_score(gold_threat, predicted_threat))
    threat_false_negative_rate = float(
        sum(
            1
            for gold, predicted in zip(gold_threat, predicted_threat, strict=False)
            if gold == 1 and predicted == 0
        )
        / max(1, sum(gold_threat))
    )
    macro_f1 = float(f1_score(gold_labels, predicted_labels, average="macro"))
    per_label = precision_recall_fscore_support(
        gold_labels,
        predicted_labels,
        labels=list(LABEL_TO_ID.keys()),
        zero_division=0,
    )
    metrics = {
        "split": split,
        "examples": len(gold_labels),
        "threatRecall": threat_recall,
        "threatFalseNegativeRate": threat_false_negative_rate,
        "macroF1": macro_f1,
        "perLabelRecall": {
            label: float(per_label[1][index]) for index, label in enumerate(list(LABEL_TO_ID.keys()))
        },
    }
    if output_path is not None:
        Path(output_path).write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics
