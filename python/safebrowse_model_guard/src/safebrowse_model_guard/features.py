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


@dataclass
class CanonicalExample:
    example_id: str
    text: str
    decision_label: str | None
    threat_positive: int | None
    structured: dict[str, Any]
    reasons: list[str]
    candidate_action: str


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
    return normalize_text(
        "\n".join(
            [
                f"[GOAL] {goal}",
                f"[SETUP] {setup}",
                f"[ACTION] {candidate_action_from_record(record)}",
                f"[META] surface={record.get('surface', 'unknown')} lang={record.get('lang', 'unknown')} domain={record.get('domain', 'unknown')}",
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


def rank_chunks(chunks: list[str], goal: str, action_text: str) -> list[tuple[int, str]]:
    goal_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", goal.lower()))
    action_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", action_text.lower()))
    ranked: list[tuple[int, str]] = []
    for index, chunk in enumerate(chunks):
        lower = chunk.lower()
        chunk_terms = Counter(re.findall(r"[a-z0-9_:/.-]+", lower))
        overlap = sum((chunk_terms & goal_terms).values()) + sum((chunk_terms & action_terms).values())
        score = overlap
        score += 5 if CALLBACK_RE.search(lower) else 0
        score += 4 if SAME_ORIGIN_SENSITIVE_RE.search(lower) else 0
        score += 3 if APPROVAL_RE.search(lower) else 0
        score += 2 if URL_RE.search(lower) else 0
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
) -> dict[str, Any]:
    urls = extract_urls(text)
    return {
        "surface": surface or "unknown",
        "lang": lang or "unknown",
        "domain": domain or "unknown",
        "target_class": target_class or "unknown",
        "origin_relation": origin_relation(source_origin, target_url),
        "context_chars": len(text),
        "url_count": len(urls),
        "cross_origin_url_count": sum(
            1 for url in urls if origin_relation(source_origin, url) == "cross_origin"
        ),
        "contains_callback_like_uri": bool(CALLBACK_RE.search(text)),
        "contains_same_origin_sensitive_path": bool(SAME_ORIGIN_SENSITIVE_RE.search(text)),
        "approvalish_language_score": approvalish_language_score(text),
        "unicode_confusable_score": unicode_confusable_score(text),
        "typoglycemia_score": typoglycemia_score(text),
        "channel_visible": "visible" in (channels or []),
        "channel_hidden": "hidden" in (channels or []),
        "channel_comment": "comment" in (channels or []),
        "channel_metadata": "metadata" in (channels or []),
    }


def structured_feature_dict(structured: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in structured.items():
        if isinstance(value, bool):
            payload[key] = 1 if value else 0
        else:
            payload[key] = value
    return payload


def example_from_dataset_row(record: dict[str, Any]) -> CanonicalExample:
    text = build_training_text(record)
    candidate_action = candidate_action_from_record(record)
    candidate = record.get("candidate_action", {})
    target_url = candidate.get("target") if isinstance(candidate, dict) else None
    source_origin = None
    context = record.get("context", "")
    if "Current primary origin:" in context:
        fragment = context.split("Current primary origin:", 1)[1].splitlines()[0].strip()
        source_origin = fragment
    structured = structured_features_from_text(
        text,
        source_origin=source_origin,
        target_url=target_url,
        target_class=record.get("target_class"),
        channels=record.get("channels"),
        surface=record.get("surface"),
        lang=record.get("lang"),
        domain=record.get("domain"),
    )
    return CanonicalExample(
        example_id=str(record.get("id", "")),
        text=text,
        decision_label=record.get("expected_label"),
        threat_positive=0 if record.get("expected_label") == "allow_read_only" else 1,
        structured=structured,
        reasons=list(record.get("reasons", [])),
        candidate_action=candidate_action,
    )


def example_from_observation_request(request_payload: dict[str, Any]) -> CanonicalExample:
    session = request_payload["session"]
    observation = request_payload["observation"]
    targets = request_payload.get("targets", [])
    primary = targets[0] if targets else {}
    action_text = f"{primary.get('kind', 'navigate')} -> {primary.get('targetPathClass', 'unknown')}"
    text = normalize_text(
        "\n".join(
            [
                f"[GOAL] {session.get('userGoal', '')}",
                f"[ACTION] {action_text}",
                f"[META] surface={observation.get('surfaceType', 'unknown')} taskPurpose={session.get('taskPurposeClass', 'unknown')}",
                f"[CONTEXT] {observation.get('contextText', '')}",
            ]
        )
    )
    structured = structured_features_from_text(
        text,
        source_origin=observation.get("sourceOrigin"),
        target_url=primary.get("targetUrl"),
        target_class=primary.get("targetPathClass"),
        channels=[
            key.removeprefix("channel_")
            for key, value in observation.get("channelFlags", {}).items()
            if value is True
        ],
        surface=observation.get("surfaceType"),
        lang=session.get("lang"),
        domain=session.get("domain"),
    )
    structured.update(
        {
            "secret_redaction_count": observation.get("secretRedactionCount", 0),
            "blocked_channel_count": len(observation.get("blockedChannels", [])),
            "matched_pattern_count": len(observation.get("matchedPatternIds", [])),
            "suspicion_flag_count": len(observation.get("suspicionFlags", [])),
        }
    )
    return CanonicalExample(
        example_id=observation.get("observationId", ""),
        text=text,
        decision_label=None,
        threat_positive=None,
        structured=structured,
        reasons=list(observation.get("semanticAuthorityFindings", []))
        + list(observation.get("policyFindings", [])),
        candidate_action=action_text,
    )


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
