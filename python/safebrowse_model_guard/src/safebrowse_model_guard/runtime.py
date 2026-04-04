from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bundle import BUNDLE_MANIFEST, load_bundle_manifest, load_pickle
from .features import (
    coarse_reason_codes_from_example,
    example_from_observation_request,
    rank_chunks,
    softmax,
    structured_feature_dict,
)


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
        self.components = self._load_components()

    def _load_components(self) -> dict[str, LoadedComponent]:
        components: dict[str, LoadedComponent] = {}
        for name, component in self.manifest.get("components", {}).items():
            backend = component.get("backend", "heuristic")
            payload: dict[str, Any] = dict(component)
            artifact_name = component.get("artifact")
            if artifact_name:
                payload["artifact_payload"] = load_pickle(self.bundle_dir / artifact_name)
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
        }

    def _heuristic_sentinel_probability(self, text: str, example: Any) -> float:
        heuristics = self.manifest.get("heuristics", {})
        keywords = [keyword.lower() for keyword in heuristics.get("deny_keywords", [])]
        approval_keywords = [
            keyword.lower() for keyword in heuristics.get("approval_keywords", [])
        ]
        shadow_keywords = [
            keyword.lower() for keyword in heuristics.get("shadow_replay_keywords", [])
        ]
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

    def _score_sentinel(self, example: Any) -> float:
        component = self.components.get("sentinel")
        if component is None or component.backend == "heuristic":
            return self._heuristic_sentinel_probability(example.text, example)
        payload = component.payload["artifact_payload"]
        char_vectorizer = payload["char_vectorizer"]
        word_vectorizer = payload["word_vectorizer"]
        classifier = payload["classifier"]
        hstack = payload["hstack"]
        matrix = hstack(
            [char_vectorizer.transform([example.text]), word_vectorizer.transform([example.text])],
            format="csr",
        )
        if hasattr(classifier, "predict_proba"):
            probability = float(classifier.predict_proba(matrix)[0][1])
        else:
            probability = _sigmoid(float(classifier.decision_function(matrix)[0]))
        return max(0.0, min(1.0, probability))

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

    def _score_transformer_expert(self, component: LoadedComponent, chunks: list[str]) -> dict[str, float]:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "Transformer expert runtime requires torch and transformers to be installed."
            ) from exc

        payload = component.payload
        if "tokenizer" not in payload or "model" not in payload:
            model_dir = self.bundle_dir / payload["artifact_dir"]
            tokenizer = AutoTokenizer.from_pretrained(model_dir)
            model = AutoModelForSequenceClassification.from_pretrained(model_dir)
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model.to(device)
            model.eval()
            payload["tokenizer"] = tokenizer
            payload["model"] = model
            payload["device"] = device

        tokenizer = payload["tokenizer"]
        model = payload["model"]
        device = payload["device"]
        max_length = int(payload.get("max_length", 1024))
        encoded = tokenizer(
            chunks,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt",
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = model(**encoded).logits
            probabilities = torch.softmax(logits, dim=-1).detach().cpu().tolist()

        id2label = model.config.id2label
        per_label: dict[str, list[float]] = {
            "allow_read_only": [],
            "require_shadow_replay": [],
            "require_user_approval": [],
            "deny": [],
        }
        for chunk_probs in probabilities:
            for index, value in enumerate(chunk_probs):
                label = str(id2label[index])
                if label in per_label:
                    per_label[label].append(float(value))

        aggregated = {
            "allow_read_only": sum(per_label["allow_read_only"]) / max(1, len(per_label["allow_read_only"])),
            "require_shadow_replay": max(per_label["require_shadow_replay"], default=0.0),
            "require_user_approval": max(per_label["require_user_approval"], default=0.0),
            "deny": max(per_label["deny"], default=0.0),
        }
        return softmax(aggregated)

    def _ranked_chunks(self, example: Any) -> list[tuple[int, str]]:
        lines = [line for line in example.text.split("\n") if line.strip()]
        if not lines:
            return [(0, example.text)]
        return rank_chunks(lines, example.text[:256], example.candidate_action)

    def _score_expert(self, example: Any, sentinel_probability: float) -> tuple[dict[str, float], list[dict[str, Any]]]:
        component = self.components.get("expert")
        ranked = self._ranked_chunks(example)
        evidence = [
            {"chunkId": f"chunk:{index}", "score": score, "excerpt": chunk[:280]}
            for index, (score, chunk) in enumerate(ranked[:3] or [(0, example.text)])
        ]
        chunk_text = "\n\n".join(entry["excerpt"] for entry in evidence)

        if component is None or component.backend == "heuristic":
            return self._heuristic_expert_probs(example, sentinel_probability), evidence

        if component.backend == "transformers_modernbert_chunk_expert":
            return self._score_transformer_expert(
                component,
                [entry["excerpt"] for entry in evidence] or [chunk_text],
            ), evidence

        payload = component.payload["artifact_payload"]
        vectorizer = payload["vectorizer"]
        classifier = payload["classifier"]
        label_order = payload["label_order"]
        matrix = vectorizer.transform([chunk_text])
        if hasattr(classifier, "predict_proba"):
            raw = classifier.predict_proba(matrix)[0]
        else:
            decision = classifier.decision_function(matrix)[0]
            if not isinstance(decision, list):
                decision = decision.tolist()
            raw = [float(value) for value in decision]
        probabilities = {label_order[index]: float(raw[index]) for index in range(len(label_order))}
        if sum(probabilities.values()) > 1.0001:
            return softmax(probabilities), evidence
        return probabilities, evidence

    def _stacker_features(
        self,
        example: Any,
        sentinel_probability: float,
        expert_probs: dict[str, float],
    ) -> dict[str, Any]:
        payload = structured_feature_dict(example.structured)
        payload.update(
            {
                "sentinel_probability": sentinel_probability,
                "expert_allow_read_only": expert_probs.get("allow_read_only", 0.0),
                "expert_require_shadow_replay": expert_probs.get("require_shadow_replay", 0.0),
                "expert_require_user_approval": expert_probs.get("require_user_approval", 0.0),
                "expert_deny": expert_probs.get("deny", 0.0),
            }
        )
        return payload

    def _score_stacker(
        self,
        example: Any,
        sentinel_probability: float,
        expert_probs: dict[str, float],
    ) -> dict[str, float]:
        component = self.components.get("stacker")
        if component is None or component.backend == "heuristic":
            scores = dict(expert_probs)
            if sentinel_probability >= self.manifest.get("heuristics", {}).get("sentinel_threshold", 0.55):
                scores["allow_read_only"] = min(scores.get("allow_read_only", 0.0), 0.2)
                scores["require_shadow_replay"] = max(scores.get("require_shadow_replay", 0.0), 0.45)
            if example.structured.get("contains_same_origin_sensitive_path"):
                scores["require_user_approval"] = max(scores.get("require_user_approval", 0.0), 0.5)
            if example.structured.get("channel_hidden"):
                scores["deny"] = max(scores.get("deny", 0.0), 0.7)
            return softmax(scores)

        payload = component.payload["artifact_payload"]
        classifier = payload["classifier"]
        vectorizer = payload["vectorizer"]
        label_order = payload["label_order"]
        feature_vector = vectorizer.transform(
            [self._stacker_features(example, sentinel_probability, expert_probs)]
        )
        if hasattr(classifier, "predict_proba"):
            raw = classifier.predict_proba(feature_vector)[0]
        else:
            decision = classifier.decision_function(feature_vector)[0]
            if not isinstance(decision, list):
                decision = decision.tolist()
            raw = [float(value) for value in decision]
        probabilities = {label_order[index]: float(raw[index]) for index in range(len(label_order))}
        if sum(probabilities.values()) > 1.0001:
            return softmax(probabilities)
        return probabilities

    def score_observation(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        example = example_from_observation_request(request_payload)
        sentinel_probability = self._score_sentinel(example)
        expert_probs, evidence = self._score_expert(example, sentinel_probability)
        final_probs = self._score_stacker(example, sentinel_probability, expert_probs)
        final_label = max(final_probs.items(), key=lambda item: item[1])[0]
        sentinel_threshold = self.manifest.get("heuristics", {}).get("sentinel_threshold", 0.55)
        if sentinel_probability >= sentinel_threshold and final_label == "allow_read_only":
            final_label = "require_shadow_replay"

        reason_codes = coarse_reason_codes_from_example(example)
        reason_codes.append(f"MODEL_GUARD_{final_label.upper()}")
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "assessment": {
                "assessmentId": f"mga_{uuid.uuid4().hex[:24]}",
                "bundleVersion": self.bundle_version,
                "featureSchemaVersion": self.feature_schema_version,
                "binaryThreatProbability": sentinel_probability,
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
