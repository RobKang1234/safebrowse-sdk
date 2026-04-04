from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

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
    limit: int | None = None,
) -> Iterable[Any]:
    manifest = load_manifest(manifest_path)
    emitted = 0
    for path in resolve_split_files(manifest, split, data_root=data_root):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
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

    if total_examples is not None:
        _maybe_report(f"starting streaming sentinel training for {total_examples} examples")
    else:
        _maybe_report("starting streaming sentinel training")
    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
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
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _top_ranked_chunks(example: Any, *, top_k_chunks: int) -> list[str]:
    chunks = chunk_text(example.text)
    ranked = rank_chunks(chunks, example.text[:256], example.candidate_action)
    selected = [chunk for _, chunk in ranked[:top_k_chunks]] if ranked else chunks[:top_k_chunks]
    return selected or [example.text]


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
    total_examples = _total_examples(manifest_path, "train", limit=limit)
    processed_examples = 0

    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
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
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _save_transformer_expert_metadata(
    output_path: Path,
    *,
    backbone: str,
    top_k_chunks: int,
    max_length: int,
    epochs: float,
    batch_size: int,
    learning_rate: float,
    device_name: str,
    example_count: int,
    average_loss: float,
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
        "learningRate": learning_rate,
        "device": device_name,
        "averageLoss": average_loss,
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
    learning_rate: float,
) -> dict[str, Any]:
    deps = _require_transformer_dependencies()
    torch = deps["torch"]
    DataLoader = deps["DataLoader"]
    IterableDataset = deps["IterableDataset"]
    AutoTokenizer = deps["AutoTokenizer"]
    AutoModelForSequenceClassification = deps["AutoModelForSequenceClassification"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    total_examples = _total_examples(manifest_path, "train", limit=limit)
    approx_total_samples = total_examples * top_k_chunks if total_examples is not None else None

    tokenizer = AutoTokenizer.from_pretrained(backbone)
    model = AutoModelForSequenceClassification.from_pretrained(
        backbone,
        num_labels=len(LABEL_TO_ID),
        label2id=LABEL_TO_ID,
        id2label={index: label for label, index in LABEL_TO_ID.items()},
    )
    if tokenizer.pad_token_id is not None:
        model.config.pad_token_id = tokenizer.pad_token_id

    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    class ChunkIterableDataset(IterableDataset):  # type: ignore[misc]
        def __iter__(self) -> Iterable[dict[str, Any]]:
            for item in _iter_chunk_samples(
                manifest_path,
                data_root=data_root,
                limit=limit,
                top_k_chunks=top_k_chunks,
            ):
                yield {"text": item.text, "label": item.label}

    def collate(batch: list[dict[str, Any]]) -> dict[str, Any]:
        encoded = tokenizer(
            [item["text"] for item in batch],
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor([item["label"] for item in batch], dtype=torch.long)
        return encoded

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    total_loss = 0.0
    total_steps = 0
    total_samples_seen = 0
    epochs_to_run = max(1, int(round(epochs)))

    if approx_total_samples is not None:
        _maybe_report(
            f"starting transformer expert training on {device} with about {approx_total_samples} chunk samples"
        )
    else:
        _maybe_report(f"starting transformer expert training on {device}")

    for epoch_index in range(epochs_to_run):
        model.train()
        optimizer.zero_grad(set_to_none=True)
        loader = DataLoader(ChunkIterableDataset(), batch_size=batch_size, collate_fn=collate)
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            total_loss += float(loss.detach().cpu())
            total_steps += 1
            batch_examples = int(batch["labels"].shape[0])
            total_samples_seen += batch_examples
            if total_steps == 1 or total_steps % 250 == 0:
                average_loss = total_loss / max(1, total_steps)
                _maybe_report(
                    (
                        f"epoch {epoch_index + 1}/{epochs_to_run}, step {total_steps}, "
                        f"samples {total_samples_seen}, avg_loss={average_loss:.6f}"
                    )
                )

    model_dir = output_path / "expert_model"
    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)
    if total_steps == 0:
        raise RuntimeError("No chunk samples were produced for expert training.")
    summary = _save_transformer_expert_metadata(
        output_path,
        backbone=backbone,
        top_k_chunks=top_k_chunks,
        max_length=max_length,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        device_name=str(device),
        example_count=total_samples_seen,
        average_loss=(total_loss / max(1, total_steps)),
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
    learning_rate: float = 2e-5,
) -> dict[str, Any]:
    if backend == "smoke":
        return _train_smoke_expert(
            manifest_path,
            output_dir=output_dir,
            data_root=data_root,
            limit=limit,
            backbone=backbone,
            top_k_chunks=top_k_chunks,
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
        learning_rate=learning_rate,
    )


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
        probabilities = torch.softmax(logits, dim=-1).detach().cpu().tolist()

    per_label: dict[str, list[float]] = {label: [] for label in LABEL_TO_ID}
    for chunk_probs in probabilities:
        for label, index in LABEL_TO_ID.items():
            per_label[label].append(float(chunk_probs[index]))

    aggregated = {
        "allow_read_only": sum(per_label["allow_read_only"]) / max(1, len(per_label["allow_read_only"])),
        "require_shadow_replay": max(per_label["require_shadow_replay"], default=0.0),
        "require_user_approval": max(per_label["require_user_approval"], default=0.0),
        "deny": max(per_label["deny"], default=0.0),
    }
    total = sum(aggregated.values()) or 1.0
    return {label: value / total for label, value in aggregated.items()}


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

    if expert_summary["backend"] == "transformers_modernbert_chunk_expert":
        expert_probabilities = _score_transformer_expert_artifact(expert_dir, example)
        label_order = list(LABEL_TO_ID.keys())
    else:
        expert_artifact = load_pickle(Path(expert_dir) / "expert.pkl")
        vectorizer = expert_artifact["vectorizer"]
        expert_classifier = expert_artifact["classifier"]
        expert_matrix = vectorizer.transform(
            [_hierarchical_text(example, top_k_chunks=int(expert_summary.get("topKChunks", 3)))]
        )
        raw = expert_classifier.predict_proba(expert_matrix)[0]
        label_order = expert_artifact["label_order"]
        expert_probabilities = {
            label_order[index]: float(raw[index]) for index in range(len(label_order))
        }

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
