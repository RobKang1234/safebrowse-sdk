from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .bundle import copy_component_file, load_pickle, write_bundle_manifest, write_pickle
from .data import load_manifest, manifest_storage_summary, resolve_split_files
from .features import (
    LABEL_TO_ID,
    chunk_text,
    example_from_dataset_row,
    rank_chunks,
    structured_feature_dict,
)


def _require_training_dependencies() -> dict[str, Any]:
    try:
        from scipy.sparse import hstack  # type: ignore
        from sklearn.feature_extraction import DictVectorizer  # type: ignore
        from sklearn.feature_extraction.text import HashingVectorizer, TfidfVectorizer  # type: ignore
        from sklearn.linear_model import SGDClassifier  # type: ignore
        from sklearn.metrics import (  # type: ignore
            f1_score,
            precision_recall_fscore_support,
            recall_score,
        )
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
    texts: list[str] = []
    labels: list[int] = []

    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
        texts.append(example.text)
        labels.append(int(example.threat_positive or 0))

    matrix = hstack(
        [char_vectorizer.transform(texts), word_vectorizer.transform(texts)],
        format="csr",
    )
    classifier.fit(matrix, labels)
    artifact = {
        "char_vectorizer": char_vectorizer,
        "word_vectorizer": word_vectorizer,
        "classifier": classifier,
        "threshold": threat_threshold,
        "hstack": hstack,
    }
    artifact_path = write_pickle(output_path / "sentinel.pkl", artifact)
    summary = {
        "artifact": str(artifact_path),
        "backend": "sklearn_binary",
        "threshold": threat_threshold,
        "examples": len(labels),
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _hierarchical_text(example: Any) -> str:
    chunks = chunk_text(example.text)
    ranked = rank_chunks(chunks, example.text[:256], example.candidate_action)
    top_chunks = [chunk for _, chunk in ranked[:3]] if ranked else chunks[:3]
    return "\n\n".join(top_chunks)


def train_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str = "answerdotai/ModernBERT-base",
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

    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
        if example.decision_label not in LABEL_TO_ID:
            continue
        texts.append(_hierarchical_text(example))
        labels.append(example.decision_label)

    matrix = vectorizer.fit_transform(texts)
    classifier.fit(matrix, labels)
    artifact_path = write_pickle(
        output_path / "expert.pkl",
        {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "label_order": list(classifier.classes_),
            "intended_backbone": backbone,
            "backend_note": "lexical_hierarchical_smoke",
        },
    )
    summary = {
        "artifact": str(artifact_path),
        "backend": "sklearn_hierarchical_multiclass",
        "examples": len(labels),
        "intendedBackbone": backbone,
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _build_meta_example(
    example: Any,
    sentinel_artifact: dict[str, Any],
    expert_artifact: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    char_vectorizer = sentinel_artifact["char_vectorizer"]
    word_vectorizer = sentinel_artifact["word_vectorizer"]
    sentinel_classifier = sentinel_artifact["classifier"]
    hstack = sentinel_artifact["hstack"]
    vectorizer = expert_artifact["vectorizer"]
    expert_classifier = expert_artifact["classifier"]
    sentinel_matrix = hstack(
        [char_vectorizer.transform([example.text]), word_vectorizer.transform([example.text])],
        format="csr",
    )
    expert_matrix = vectorizer.transform([_hierarchical_text(example)])
    sentinel_probability = float(sentinel_classifier.predict_proba(sentinel_matrix)[0][1])
    expert_probabilities = expert_classifier.predict_proba(expert_matrix)[0]
    features = structured_feature_dict(example.structured)
    features["sentinel_probability"] = sentinel_probability
    for index, label in enumerate(expert_artifact["label_order"]):
        features[f"expert_{label}"] = float(expert_probabilities[index])
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
    expert_artifact = load_pickle(Path(expert_dir) / "expert.pkl")
    feature_rows: list[dict[str, Any]] = []
    labels: list[str] = []

    for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
        if example.decision_label not in LABEL_TO_ID:
            continue
        features, label = _build_meta_example(example, sentinel_artifact, expert_artifact)
        feature_rows.append(features)
        labels.append(label)

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
    copy_component_file(expert_summary["artifact"], output_path, "expert.pkl")
    copy_component_file(stacker_summary["artifact"], output_path, "stacker.pkl")
    manifest = {
        "bundleVersion": bundle_version,
        "featureSchemaVersion": "v1",
        "pipeline": {
            "runtimeMode": "python_sidecar",
            "enforcementMode": "tighten",
            "sentinelVersion": Path(sentinel_summary["artifact"]).stem,
            "expertVersion": Path(expert_summary["artifact"]).stem,
            "stackerVersion": Path(stacker_summary["artifact"]).stem,
        },
        "components": {
            "sentinel": {
                "backend": sentinel_summary["backend"],
                "artifact": "sentinel.pkl",
            },
            "expert": {
                "backend": expert_summary["backend"],
                "artifact": "expert.pkl",
                "backbone": expert_summary.get("intendedBackbone"),
            },
            "stacker": {
                "backend": stacker_summary["backend"],
                "artifact": "stacker.pkl",
            },
        },
        "heuristics": {
            "sentinel_threshold": sentinel_summary.get("threshold", 0.55),
        },
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
            label: float(per_label[1][index])
            for index, label in enumerate(list(LABEL_TO_ID.keys()))
        },
    }
    if output_path is not None:
        Path(output_path).write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics
