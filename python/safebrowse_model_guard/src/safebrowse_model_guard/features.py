from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s)>\"]+")
CALLBACK_RE = re.compile(r"/oauth/callback|callback_uri|redirect_uri", re.IGNORECASE)
APPROVAL_RE = re.compile(
    r"\b(approve|approval|authorize|authorization|finalize|payment|billing|submit|confirm|connector|oauth)\b",
    re.IGNORECASE,
)
TYPOGLYCEMIA_RE = re.compile(
    r"\b(ignroe|prevouis|sysetm|developre|instrucitons|credentails)\b", re.IGNORECASE
)
SAME_ORIGIN_SENSITIVE_RE = re.compile(
    r"/(payment|billing|checkout|admin|settings|export|finalize|authorize|oauth|connector|reconciliation)",
    re.IGNORECASE,
)

LABEL_TO_ID = {
    "allow_read_only": 0,
    "require_shadow_replay": 1,
    "require_user_approval": 2,
    "deny": 3,
}
ID_TO_LABEL = {value: key for key, value in LABEL_TO_ID.items()}

RECIPE_REASON_LABELS = [
    "cross_origin",
    "same_origin_sensitive",
    "approval_spoof",
    "callback_drift",
    "manifest_schema_mismatch",
    "memory_promotion_risk",
    "hidden_channel",
    "ocr_or_metadata_risk",
    "unicode_or_typoglycemia",
]

RECIPE_CATEGORICAL_FIELDS = [
    "surface",
    "lang",
    "domain",
    "action_type",
    "origin_relation",
    "target_sensitivity_class",
]

RECIPE_NUMERIC_FIELDS = [
    "context_chars",
    "url_count",
    "cross_origin_url_count",
    "approvalish_language_score",
    "unicode_confusable_score",
    "typoglycemia_score",
    "secret_redaction_count",
    "channel_flag_count",
]


@dataclass
class CanonicalExample:
    example_id: str
    text: str
    decision_label: str | None
    threat_positive: int | None
    structured: dict[str, Any]
    reasons: list[str]
    candidate_action: str
    goal: str
    setup: str
    context: str
    lang: str
    domain: str
    surface: str
    channels: list[str]
    attack_family: str
    target_class: str
    target_url: str | None
    action_type: str


def normalize_text(value: str) -> str:
    return " ".join(value.split())


def approvalish_language_score(text: str) -> float:
    matches = APPROVAL_RE.findall(text)
    return min(1.0, len(matches) / 6.0)


def unicode_confusable_score(text: str) -> float:
    if not text:
        return 0.0
    non_ascii = sum(1 for char in text if ord(char) > 127)
    return min(1.0, non_ascii / max(1, len(text)))


def typoglycemia_score(text: str) -> float:
    return min(1.0, len(TYPOGLYCEMIA_RE.findall(text)) / 3.0)


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def origin_relation(source_origin: str | None, target_url: str | None) -> str:
    if not source_origin or not target_url:
        return "unknown"
    source = urlparse(source_origin)
    target = urlparse(target_url)
    return "same_origin" if source.scheme == target.scheme and source.netloc == target.netloc else "cross_origin"


def action_type_from_record(record: dict[str, Any]) -> str:
    candidate = record.get("candidate_action", {})
    if isinstance(candidate, dict):
        return str(candidate.get("type") or record.get("action") or "unknown")
    return str(record.get("action") or "unknown")


def target_sensitivity_class(target_class: str | None) -> str:
    value = (target_class or "unknown").lower()
    if "cross_origin" in value:
        return "cross_origin"
    if "safe" in value:
        return "safe"
    if "sensitive" in value:
        return "sensitive"
    if "approval" in value or "payment" in value or "connector" in value:
        return "approval_bound"
    return value or "unknown"


def candidate_action_from_record(record: dict[str, Any]) -> str:
    candidate = record.get("candidate_action", {})
    if isinstance(candidate, dict):
        action_type = candidate.get("type") or record.get("action") or "unknown"
        target = candidate.get("target") or candidate.get("target_class") or record.get("target_class") or "unknown"
        return f"{action_type} -> {target}"
    return f"{record.get('action', 'unknown')} -> {record.get('target_class', 'unknown')}"


def build_training_text(record: dict[str, Any]) -> str:
    goal = record.get("goal", "")
    setup = record.get("setup", "")
    context = record.get("context") or record.get("rendered_context", "")
    channels = ",".join(str(value) for value in record.get("channels", []))
    return normalize_text(
        "\n".join(
            [
                f"[GOAL] {goal}",
                f"[SETUP] {setup}",
                f"[ACTION] {candidate_action_from_record(record)}",
                (
                    f"[META] surface={record.get('surface', 'unknown')} "
                    f"lang={record.get('lang', 'unknown')} "
                    f"domain={record.get('domain', 'unknown')} "
                    f"channels={channels}"
                ),
                f"[CONTEXT] {context}",
            ]
        )
    )


def chunk_text(text: str, *, chunk_chars: int = 3200, stride_chars: int = 1200) -> list[str]:
    if len(text) <= chunk_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        chunk = text[start : start + chunk_chars]
        chunks.append(chunk)
        if start + chunk_chars >= len(text):
            break
        start += max(1, chunk_chars - stride_chars)
    return chunks


def rank_chunks(
    chunks: list[str],
    goal: str,
    action_text: str,
    *,
    sentinel_probability: float = 0.0,
) -> list[tuple[int, str]]:
    goal_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", goal.lower()))
    action_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", action_text.lower()))
    ranked: list[tuple[int, str]] = []
    sentinel_boost = int(round(sentinel_probability * 10))
    for index, chunk in enumerate(chunks):
        lower = chunk.lower()
        chunk_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", lower))
        overlap = sum((chunk_terms & goal_terms).values()) + sum((chunk_terms & action_terms).values())
        score = overlap
        score += 5 if CALLBACK_RE.search(lower) else 0
        score += 4 if SAME_ORIGIN_SENSITIVE_RE.search(lower) else 0
        score += 3 if APPROVAL_RE.search(lower) else 0
        score += 2 if URL_RE.search(lower) else 0
        score += sentinel_boost
        ranked.append((score * 10 - index, chunk))
    ranked.sort(reverse=True, key=lambda item: item[0])
    return ranked


def structured_features_from_text(
    text: str,
    *,
    source_origin: str | None,
    target_url: str | None,
    target_class: str | None,
    channels: list[str] | None,
    surface: str | None,
    lang: str | None,
    domain: str | None,
    action_type: str | None,
) -> dict[str, Any]:
    urls = extract_urls(text)
    channel_values = channels or []
    payload = {
        "surface": surface or "unknown",
        "lang": lang or "unknown",
        "domain": domain or "unknown",
        "action_type": action_type or "unknown",
        "target_class": target_class or "unknown",
        "target_sensitivity_class": target_sensitivity_class(target_class),
        "origin_relation": origin_relation(source_origin, target_url),
        "context_chars": len(text),
        "url_count": len(urls),
        "cross_origin_url_count": sum(
            1 for url in urls if origin_relation(source_origin, url) == "cross_origin"
        ),
        "approvalish_language_score": approvalish_language_score(text),
        "unicode_confusable_score": unicode_confusable_score(text),
        "typoglycemia_score": typoglycemia_score(text),
        "secret_redaction_count": 0,
        "channel_flag_count": len(channel_values),
        "channel_visible": "visible" in channel_values,
        "channel_hidden": "hidden" in channel_values,
        "channel_comment": "comment" in channel_values,
        "channel_metadata": "metadata" in channel_values,
        "contains_callback_like_uri": bool(CALLBACK_RE.search(text)),
        "contains_same_origin_sensitive_path": bool(SAME_ORIGIN_SENSITIVE_RE.search(text)),
    }
    return payload


def structured_feature_dict(structured: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in structured.items():
        if isinstance(value, bool):
            payload[key] = 1 if value else 0
        else:
            payload[key] = value
    return payload


def recipe_categorical_values(example: CanonicalExample) -> dict[str, str]:
    structured = example.structured
    return {
        "surface": str(structured.get("surface", example.surface or "unknown")),
        "lang": str(structured.get("lang", example.lang or "unknown")),
        "domain": str(structured.get("domain", example.domain or "unknown")),
        "action_type": str(structured.get("action_type", example.action_type or "unknown")),
        "origin_relation": str(structured.get("origin_relation", "unknown")),
        "target_sensitivity_class": str(
            structured.get(
                "target_sensitivity_class",
                target_sensitivity_class(example.target_class),
            )
        ),
    }


def recipe_numeric_values(example: CanonicalExample) -> dict[str, float]:
    structured = example.structured
    return {
        "context_chars": float(structured.get("context_chars", len(example.text))),
        "url_count": float(structured.get("url_count", 0)),
        "cross_origin_url_count": float(structured.get("cross_origin_url_count", 0)),
        "approvalish_language_score": float(structured.get("approvalish_language_score", 0.0)),
        "unicode_confusable_score": float(structured.get("unicode_confusable_score", 0.0)),
        "typoglycemia_score": float(structured.get("typoglycemia_score", 0.0)),
        "secret_redaction_count": float(structured.get("secret_redaction_count", 0)),
        "channel_flag_count": float(structured.get("channel_flag_count", len(example.channels))),
    }


def encode_recipe_categorical(
    example: CanonicalExample,
    metadata_vocab: dict[str, dict[str, int]],
) -> list[int]:
    values = recipe_categorical_values(example)
    encoded: list[int] = []
    for field in RECIPE_CATEGORICAL_FIELDS:
        vocab = metadata_vocab.get(field, {"unknown": 0})
        encoded.append(int(vocab.get(values.get(field, "unknown"), vocab.get("unknown", 0))))
    return encoded


def encode_recipe_numeric(example: CanonicalExample) -> list[float]:
    values = recipe_numeric_values(example)
    return [float(values[field]) for field in RECIPE_NUMERIC_FIELDS]


def encode_recipe_reason_targets(example: CanonicalExample) -> list[float]:
    values = reason_targets_for_example(example)
    return [float(values[field]) for field in RECIPE_REASON_LABELS]


def reason_targets_for_example(example: CanonicalExample) -> dict[str, int]:
    lower_reasons = " ".join(example.reasons).lower()
    attack_family = example.attack_family.lower()
    structured = example.structured
    return {
        "cross_origin": 1 if structured.get("origin_relation") == "cross_origin" else 0,
        "same_origin_sensitive": 1 if structured.get("contains_same_origin_sensitive_path") else 0,
        "approval_spoof": 1
        if structured.get("approvalish_language_score", 0.0) > 0.2 or "approval" in lower_reasons
        else 0,
        "callback_drift": 1 if structured.get("contains_callback_like_uri") else 0,
        "manifest_schema_mismatch": 1 if "manifest" in lower_reasons or "schema" in lower_reasons else 0,
        "memory_promotion_risk": 1 if "memory" in lower_reasons or "memory" in attack_family else 0,
        "hidden_channel": 1 if structured.get("channel_hidden") or structured.get("blocked_channel_count", 0) > 0 else 0,
        "ocr_or_metadata_risk": 1 if structured.get("channel_metadata") or "metadata" in lower_reasons else 0,
        "unicode_or_typoglycemia": 1
        if structured.get("unicode_confusable_score", 0.0) > 0.0 or structured.get("typoglycemia_score", 0.0) > 0.0
        else 0,
    }


def example_from_dataset_row(record: dict[str, Any]) -> CanonicalExample:
    text = build_training_text(record)
    candidate_action = candidate_action_from_record(record)
    candidate = record.get("candidate_action", {})
    target_url = candidate.get("target") if isinstance(candidate, dict) else None
    goal = str(record.get("goal", ""))
    setup = str(record.get("setup", ""))
    context = str(record.get("context", ""))
    lang = str(record.get("lang", "unknown"))
    domain = str(record.get("domain", "unknown"))
    surface = str(record.get("surface", "unknown"))
    channels = [str(value) for value in record.get("channels", [])]
    attack_family = str(record.get("attack_family", "none"))
    target_class = str(record.get("target_class", "unknown"))
    source_origin = None
    if "Current primary origin:" in context:
        fragment = context.split("Current primary origin:", 1)[1].splitlines()[0].strip()
        source_origin = fragment
    action_type = action_type_from_record(record)
    structured = structured_features_from_text(
        text,
        source_origin=source_origin,
        target_url=target_url,
        target_class=target_class,
        channels=channels,
        surface=surface,
        lang=lang,
        domain=domain,
        action_type=action_type,
    )
    reason_targets = reason_targets_for_example(
        CanonicalExample(
            example_id=str(record.get("id", "")),
            text=text,
            decision_label=record.get("expected_label"),
            threat_positive=0 if record.get("expected_label") == "allow_read_only" else 1,
            structured=structured,
            reasons=list(record.get("reasons", [])),
            candidate_action=candidate_action,
            goal=goal,
            setup=setup,
            context=context,
            lang=lang,
            domain=domain,
            surface=surface,
            channels=channels,
            attack_family=attack_family,
            target_class=target_class,
            target_url=target_url,
            action_type=action_type,
        )
    )
    structured.update({f"reason_{key}": value for key, value in reason_targets.items()})
    return CanonicalExample(
        example_id=str(record.get("id", "")),
        text=text,
        decision_label=record.get("expected_label"),
        threat_positive=0 if record.get("expected_label") == "allow_read_only" else 1,
        structured=structured,
        reasons=list(record.get("reasons", [])),
        candidate_action=candidate_action,
        goal=goal,
        setup=setup,
        context=context,
        lang=lang,
        domain=domain,
        surface=surface,
        channels=channels,
        attack_family=attack_family,
        target_class=target_class,
        target_url=target_url,
        action_type=action_type,
    )


def example_from_observation_request(request_payload: dict[str, Any]) -> CanonicalExample:
    session = request_payload["session"]
    observation = request_payload["observation"]
    targets = request_payload.get("targets", [])
    primary = targets[0] if targets else {}
    action_type = str(primary.get("kind", "navigate"))
    action_text = f"{action_type} -> {primary.get('targetPathClass', 'unknown')}"
    text = normalize_text(
        "\n".join(
            [
                f"[GOAL] {session.get('userGoal', '')}",
                f"[ACTION] {action_text}",
                (
                    f"[META] surface={observation.get('surfaceType', 'unknown')} "
                    f"taskPurpose={session.get('taskPurposeClass', 'unknown')}"
                ),
                f"[CONTEXT] {observation.get('contextText', '')}",
            ]
        )
    )
    channels = [
        key.removeprefix("channel_")
        for key, value in observation.get("channelFlags", {}).items()
        if value is True
    ]
    structured = structured_features_from_text(
        text,
        source_origin=observation.get("sourceOrigin"),
        target_url=primary.get("targetUrl"),
        target_class=primary.get("targetPathClass"),
        channels=channels,
        surface=observation.get("surfaceType"),
        lang=session.get("lang"),
        domain=session.get("domain"),
        action_type=action_type,
    )
    structured.update(
        {
            "secret_redaction_count": observation.get("secretRedactionCount", 0),
            "blocked_channel_count": len(observation.get("blockedChannels", [])),
            "matched_pattern_count": len(observation.get("matchedPatternIds", [])),
            "suspicion_flag_count": len(observation.get("suspicionFlags", [])),
        }
    )
    example = CanonicalExample(
        example_id=observation.get("observationId", ""),
        text=text,
        decision_label=None,
        threat_positive=None,
        structured=structured,
        reasons=list(observation.get("semanticAuthorityFindings", []))
        + list(observation.get("policyFindings", [])),
        candidate_action=action_text,
        goal=str(session.get("userGoal", "")),
        setup="",
        context=str(observation.get("contextText", "")),
        lang=str(session.get("lang", "unknown")),
        domain=str(session.get("domain", "unknown")),
        surface=str(observation.get("surfaceType", "unknown")),
        channels=channels,
        attack_family="runtime_observation",
        target_class=str(primary.get("targetPathClass", "unknown")),
        target_url=primary.get("targetUrl"),
        action_type=action_type,
    )
    structured.update({f"reason_{key}": value for key, value in reason_targets_for_example(example).items()})
    return example


def softmax(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    maximum = max(scores.values())
    exps = {key: math.exp(value - maximum) for key, value in scores.items()}
    total = sum(exps.values()) or 1.0
    return {key: value / total for key, value in exps.items()}


def coarse_reason_codes_from_example(example: CanonicalExample, *, threshold: float = 0.55) -> list[str]:
    reasons: list[str] = []
    structured = example.structured
    if structured.get("origin_relation") == "cross_origin":
        reasons.append("MODEL_GUARD_CROSS_ORIGIN")
    if structured.get("contains_callback_like_uri"):
        reasons.append("MODEL_GUARD_CALLBACK_URI")
    if structured.get("contains_same_origin_sensitive_path"):
        reasons.append("MODEL_GUARD_SENSITIVE_PATH")
    if structured.get("channel_hidden") or structured.get("blocked_channel_count", 0) > 0:
        reasons.append("MODEL_GUARD_HIDDEN_CHANNEL")
    if structured.get("secret_redaction_count", 0) > 0:
        reasons.append("MODEL_GUARD_SECRET_REDACTION")
    if structured.get("unicode_confusable_score", 0.0) >= 0.05:
        reasons.append("MODEL_GUARD_UNICODE_CONFUSABLE")
    if structured.get("typoglycemia_score", 0.0) > 0.0:
        reasons.append("MODEL_GUARD_TYPOGLYCEMIA")
    if structured.get("approvalish_language_score", 0.0) >= threshold:
        reasons.append("MODEL_GUARD_APPROVAL_LANGUAGE")
    if structured.get("matched_pattern_count", 0) > 0:
        reasons.append("MODEL_GUARD_RULE_PATTERN_MATCH")
    if structured.get("suspicion_flag_count", 0) > 0:
        reasons.append("MODEL_GUARD_SUSPICION_FLAGS")
    return reasons
