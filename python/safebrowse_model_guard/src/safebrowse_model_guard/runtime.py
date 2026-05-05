from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bundle import BUNDLE_MANIFEST, load_bundle_manifest, load_pickle
from .features import (
    coarse_reason_codes_from_example,
    encode_recipe_categorical,
    encode_recipe_numeric,
    example_from_observation_request,
    rank_chunks,
    softmax,
    structured_feature_dict,
)
from .recipe_model import load_recipe_expert_artifact


def _sigmoid(value: float) -> float:
    if value >= 0:
        exp = math.exp(-value)
        return 1.0 / (1.0 + exp)
    exp = math.exp(value)
    return exp / (1.0 + exp)


@dataclass
class LoadedComponent:
    backend: str
    payload: dict[str, Any]


class ModelGuardRuntime:
    def __init__(self, bundle_dir: str | Path):
        self.bundle_dir = Path(bundle_dir)
        self.manifest = load_bundle_manifest(self.bundle_dir)
        self.bundle_version = self.manifest.get("bundleVersion", "unknown")
        self.feature_schema_version = self.manifest.get("featureSchemaVersion", "v1")
        self.pipeline = self.manifest.get("pipeline", {})
        self.release_manifest = self._load_release_manifest()
        self.bundle_digest = self._hash_file(self.bundle_dir / BUNDLE_MANIFEST)
        self.component_digests = self._component_digests()
        self.components = self._load_components()

    def _load_release_manifest(self) -> dict[str, Any]:
        path = self.bundle_dir / "manifest.json"
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _hash_file(self, path: Path) -> str | None:
        if not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _component_digests(self) -> dict[str, str]:
        hashes = self.release_manifest.get("componentHashes")
        if not isinstance(hashes, dict):
            return {}
        return {
            str(name): str(value)
            for name, value in hashes.items()
            if isinstance(name, str) and isinstance(value, str)
        }

    def _load_components(self) -> dict[str, LoadedComponent]:
        components: dict[str, LoadedComponent] = {}
        for name, component in self.manifest.get("components", {}).items():
            backend = component.get("backend", "heuristic")
            payload: dict[str, Any] = dict(component)
            artifact_name = component.get("artifact")
            artifact_dir = component.get("artifact_dir")
            if artifact_name:
                payload["artifact_payload"] = load_pickle(self.bundle_dir / artifact_name)
            if artifact_dir:
                payload["artifact_path"] = self.bundle_dir / artifact_dir
            components[name] = LoadedComponent(backend=backend, payload=payload)
        return components

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "ready": (self.bundle_dir / BUNDLE_MANIFEST).is_file(),
            "runtimeMode": "python_sidecar",
            "enforcementMode": self.pipeline.get("enforcementMode", "tighten"),
            "bundleVersion": self.bundle_version,
            "featureSchemaVersion": self.feature_schema_version,
            "bundleDigest": self.bundle_digest,
            "componentDigests": self.component_digests,
        }

    def _heuristic_sentinel_probability(self, text: str, example: Any) -> float:
        heuristics = self.manifest.get("heuristics", {})
        keywords = [keyword.lower() for keyword in heuristics.get("deny_keywords", [])]
        approval_keywords = [keyword.lower() for keyword in heuristics.get("approval_keywords", [])]
        shadow_keywords = [keyword.lower() for keyword in heuristics.get("shadow_replay_keywords", [])]
        lower = text.lower()
        score = 0.05
        score += 0.18 * sum(1 for keyword in keywords if keyword in lower)
        score += 0.12 * sum(1 for keyword in approval_keywords if keyword in lower)
        score += 0.14 * sum(1 for keyword in shadow_keywords if keyword in lower)
        if example.structured.get("contains_callback_like_uri"):
            score += 0.12
        if example.structured.get("contains_same_origin_sensitive_path"):
            score += 0.14
        if example.structured.get("channel_hidden"):
            score += 0.18
        if example.structured.get("blocked_channel_count", 0) > 0:
            score += 0.12
        if example.structured.get("matched_pattern_count", 0) > 0:
            score += 0.08
        if example.structured.get("suspicion_flag_count", 0) > 0:
            score += 0.08
        if example.structured.get("secret_redaction_count", 0) > 0:
            score += 0.1
        return max(0.0, min(1.0, score))

    def _score_sentinel(self, example: Any) -> dict[str, float]:
        component = self.components.get("sentinel")
        if component is None or component.backend == "heuristic":
            probability = self._heuristic_sentinel_probability(example.text, example)
            return {"lexical": probability, "structured": probability, "max": probability}

        artifact = component.payload["artifact_payload"]
        lexical = artifact["lexical"]
        structured = artifact["structured"]
        from scipy.sparse import hstack  # type: ignore

        lexical_matrix = hstack(
            [
                lexical["char_vectorizer"].transform([example.text]),
                lexical["word_vectorizer"].transform([example.text]),
            ],
            format="csr",
        )
        lexical_probability = float(lexical["classifier"].predict_proba(lexical_matrix)[0][1])

        structured_matrix = hstack(
            [
                structured["dict_vectorizer"].transform([structured_feature_dict(example.structured)]),
                structured["text_vectorizer"].transform([example.text]),
            ],
            format="csr",
        ).astype("float32")
        if str(structured.get("backend", "")).startswith("xgboost_binary"):
            try:
                import xgboost as xgb
            except ModuleNotFoundError as exc:  # pragma: no cover
                raise RuntimeError(
                    "Structured xgboost sentinel runtime requires xgboost to be installed."
                ) from exc
            booster = structured.get("_booster")
            if booster is None:
                classifier_payload = structured["classifier"]
                if isinstance(classifier_payload, xgb.Booster):
                    booster = classifier_payload
                else:
                    booster = xgb.Booster()
                    booster.load_model(bytearray(classifier_payload))
                structured["_booster"] = booster
            structured_probability = float(booster.predict(xgb.DMatrix(structured_matrix))[0])
        elif structured["backend"] == "catboost_binary_cpu":
            structured_probability = float(structured["classifier"].predict_proba(structured_matrix.toarray())[0][1])
        else:
            structured_probability = float(structured["classifier"].predict_proba(structured_matrix)[0][1])
        maximum = max(lexical_probability, structured_probability)

        calibration = self.components.get("calibration")
        if calibration is not None:
            binary_calibration = calibration.payload["artifact_payload"].get("binaryThreatCalibrator", {})
            if binary_calibration.get("kind") == "platt":
                model = binary_calibration["model"]
                maximum = float(model.predict_proba([[maximum]])[0][1])

        return {
            "lexical": lexical_probability,
            "structured": structured_probability,
            "max": maximum,
        }

    def _heuristic_expert_probs(self, example: Any, sentinel_probability: float) -> dict[str, float]:
        scores = {
            "allow_read_only": 2.5 - sentinel_probability * 2.0,
            "require_shadow_replay": 0.9 + sentinel_probability * 2.0,
            "require_user_approval": 0.4 + example.structured.get("approvalish_language_score", 0.0) * 3.0,
            "deny": 0.4 + sentinel_probability * 1.6,
        }
        if example.structured.get("channel_hidden"):
            scores["deny"] += 1.5
        if example.structured.get("contains_same_origin_sensitive_path"):
            scores["require_user_approval"] += 1.2
        if example.structured.get("contains_callback_like_uri"):
            scores["require_user_approval"] += 0.9
        if example.structured.get("origin_relation") == "cross_origin":
            scores["deny"] += 0.6
        if example.structured.get("secret_redaction_count", 0) > 0:
            scores["deny"] += 0.8
        if example.structured.get("matched_pattern_count", 0) > 0:
            scores["require_shadow_replay"] += 0.8
        if example.structured.get("suspicion_flag_count", 0) > 0:
            scores["require_shadow_replay"] += 0.6
        return softmax(scores)

    def _ranked_chunks(self, example: Any, *, sentinel_probability: float) -> list[tuple[int, str]]:
        lines = [line for line in example.text.split("\n") if line.strip()]
        if not lines:
            return [(0, example.text)]
        return rank_chunks(lines, example.goal, example.candidate_action, sentinel_probability=sentinel_probability)

    def _score_smoke_expert(self, component: LoadedComponent, example: Any, sentinel_probability: float) -> dict[str, Any]:
        from scipy.sparse import hstack  # type: ignore

        artifact = component.payload["artifact_payload"]
        dict_vectorizer = artifact["dict_vectorizer"]
        text_vectorizer = artifact["text_vectorizer"]
        classifier = artifact["classifier"]
        label_order = artifact["label_order"]
        matrix = hstack(
            [
                dict_vectorizer.transform([structured_feature_dict(example.structured) | {"sentinel_probability": sentinel_probability}]),
                text_vectorizer.transform([example.text]),
            ],
            format="csr",
        )
        raw = classifier.decision_function(matrix)
        if hasattr(raw, "tolist"):
            raw = raw.tolist()
        logits = [float(value) for value in (raw[0] if isinstance(raw[0], list) else raw)]
        probabilities = softmax({label_order[index]: logits[index] for index in range(len(label_order))})
        dense = matrix.toarray()[0]
        pooled = [float(value) for value in dense[:128]]
        if len(pooled) < 128:
            pooled.extend([0.0] * (128 - len(pooled)))
        return {"probabilities": probabilities, "logits": logits[:4], "pooledEmbedding": pooled}

    def _score_recipe_expert(self, component: LoadedComponent, example: Any, sentinel_probability: float) -> dict[str, Any]:
        try:
            import torch
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "Transformer expert runtime requires torch and transformers to be installed."
            ) from exc

        cache = component.payload
        if "loaded_model" not in cache:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model, tokenizer, config, metadata_vocab = load_recipe_expert_artifact(
                cache["artifact_path"],
                device=device,
            )
            cache["loaded_model"] = model
            cache["loaded_tokenizer"] = tokenizer
            cache["loaded_config"] = config
            cache["loaded_metadata_vocab"] = metadata_vocab
            cache["loaded_device"] = device

        model = cache["loaded_model"]
        tokenizer = cache["loaded_tokenizer"]
        config = cache["loaded_config"]
        metadata_vocab = cache["loaded_metadata_vocab"]
        device = cache["loaded_device"]
        ranked = self._ranked_chunks(example, sentinel_probability=sentinel_probability)
        evidence_chunks = [chunk for _, chunk in ranked[: int(config.top_k_chunks)]]
        evidence_chunks = evidence_chunks or [example.text]
        if len(evidence_chunks) < int(config.top_k_chunks):
            evidence_chunks = evidence_chunks + [evidence_chunks[-1]] * (int(config.top_k_chunks) - len(evidence_chunks))
        encoded = tokenizer(
            evidence_chunks,
            truncation=True,
            padding=True,
            max_length=int(config.max_length),
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        metadata_categorical = torch.tensor([encode_recipe_categorical(example, metadata_vocab)], dtype=torch.long, device=device)
        metadata_numeric = torch.tensor([encode_recipe_numeric(example)], dtype=torch.float32, device=device)
        with torch.no_grad():
            outputs = model(
                input_ids=encoded["input_ids"],
                attention_mask=encoded["attention_mask"],
                metadata_categorical=metadata_categorical,
                metadata_numeric=metadata_numeric,
            )
            logits = outputs["decision_logits"][0].detach().cpu().tolist()
            temperature = 1.0
            calibration = self.components.get("calibration")
            if calibration is not None:
                temperature = float(calibration.payload["artifact_payload"].get("expertTemperature", 1.0))
            probabilities = softmax({label: float(logits[index]) / temperature for label, index in {"allow_read_only": 0, "require_shadow_replay": 1, "require_user_approval": 2, "deny": 3}.items()})
            pooled = outputs["pooled_embedding"][0].detach().cpu().tolist()
        return {"probabilities": probabilities, "logits": logits, "pooledEmbedding": pooled}

    def _score_expert(self, example: Any, sentinel_probability: float) -> tuple[dict[str, float], list[dict[str, Any]], dict[str, Any]]:
        component = self.components.get("expert")
        ranked = self._ranked_chunks(example, sentinel_probability=sentinel_probability)
        evidence = [{"chunkId": f"chunk:{index}", "score": score, "excerpt": chunk[:280]} for index, (score, chunk) in enumerate(ranked[:3] or [(0, example.text)])]
        if component is None or component.backend == "heuristic":
            probabilities = self._heuristic_expert_probs(example, sentinel_probability)
            logits = [probabilities[label] for label in ["allow_read_only", "require_shadow_replay", "require_user_approval", "deny"]]
            return probabilities, evidence, {"probabilities": probabilities, "logits": logits, "pooledEmbedding": [0.0] * 128}
        if component.backend == "recipe_hierarchical_smoke":
            scored = self._score_smoke_expert(component, example, sentinel_probability)
            return scored["probabilities"], evidence, scored
        scored = self._score_recipe_expert(component, example, sentinel_probability)
        return scored["probabilities"], evidence, scored

    def _stacker_features(self, example: Any, sentinel_scores: dict[str, float], expert_output: dict[str, Any]) -> dict[str, Any]:
        payload = structured_feature_dict(example.structured)
        payload["sentinel_lexical_probability"] = float(sentinel_scores["lexical"])
        payload["sentinel_structured_probability"] = float(sentinel_scores["structured"])
        payload["sentinel_or_probability"] = float(sentinel_scores["max"])
        label_order = ["allow_read_only", "require_shadow_replay", "require_user_approval", "deny"]
        for index, label in enumerate(label_order):
            payload[f"expert_logit_{label}"] = float(expert_output["logits"][index])
            payload[f"expert_prob_{label}"] = float(expert_output["probabilities"].get(label, 0.0))
        for index, value in enumerate(expert_output["pooledEmbedding"]):
            payload[f"expert_embedding_{index:03d}"] = float(value)
        return payload

    def _score_stacker(self, example: Any, sentinel_scores: dict[str, float], expert_output: dict[str, Any]) -> dict[str, float]:
        component = self.components.get("stacker")
        if component is None or component.backend == "heuristic":
            scores = dict(expert_output["probabilities"])
            if sentinel_scores["max"] >= self.manifest.get("thresholds", {}).get("binaryThreat", 0.55):
                scores["allow_read_only"] = min(scores.get("allow_read_only", 0.0), 0.2)
                scores["require_shadow_replay"] = max(scores.get("require_shadow_replay", 0.0), 0.45)
            return softmax(scores)

        payload = component.payload["artifact_payload"]
        classifier = payload["classifier"]
        vectorizer = payload["vectorizer"]
        label_order = payload["label_order"]
        feature_vector = vectorizer.transform([self._stacker_features(example, sentinel_scores, expert_output)])
        if hasattr(classifier, "predict_proba"):
            if component.backend == "xgboost_multiclass_cpu":
                raw = classifier.predict_proba(feature_vector)[0]
            else:
                raw = classifier.predict_proba(feature_vector)[0]
        else:
            decision = classifier.decision_function(feature_vector)[0]
            raw = decision.tolist() if hasattr(decision, "tolist") else decision
        probabilities = {}
        for index, value in enumerate(raw):
            label = label_order[index] if index < len(label_order) else str(index)
            probabilities[str(label)] = float(value)
        if sum(probabilities.values()) > 1.0001:
            return softmax(probabilities)
        return probabilities

    def score_observation(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        example = example_from_observation_request(request_payload)
        sentinel_scores = self._score_sentinel(example)
        expert_probs, evidence, expert_output = self._score_expert(example, sentinel_scores["max"])
        final_probs = self._score_stacker(example, sentinel_scores, expert_output)
        final_label = max(final_probs.items(), key=lambda item: item[1])[0]
        sentinel_threshold = self.manifest.get("thresholds", {}).get("binaryThreat", 0.55)
        if sentinel_scores["max"] >= sentinel_threshold and final_label == "allow_read_only":
            final_label = "require_shadow_replay"

        reason_codes = coarse_reason_codes_from_example(example)
        reason_codes.append(f"MODEL_GUARD_{final_label.upper()}")
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "assessment": {
                "assessmentId": f"mga_{uuid.uuid4().hex[:24]}",
                "bundleVersion": self.bundle_version,
                "featureSchemaVersion": self.feature_schema_version,
                "bundleDigest": self.bundle_digest,
                "componentDigests": self.component_digests,
                "binaryThreatProbability": sentinel_scores["max"],
                "decisionLabel": final_label,
                "calibratedDecisionLabel": final_label,
                "coarseReasonCodes": reason_codes,
                "evidenceChunkIds": [entry["chunkId"] for entry in evidence],
                "pipeline": {
                    "runtimeMode": "python_sidecar",
                    "enforcementMode": self.pipeline.get("enforcementMode", "tighten"),
                    "scoredAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "latencyMs": latency_ms,
                    "sentinelVersion": self.pipeline.get("sentinelVersion"),
                    "expertVersion": self.pipeline.get("expertVersion"),
                    "stackerVersion": self.pipeline.get("stackerVersion"),
                },
            },
            "evidenceChunks": evidence,
        }

    def score_batch(self, requests: list[dict[str, Any]]) -> dict[str, Any]:
        return {"results": [self.score_observation(request) for request in requests]}
