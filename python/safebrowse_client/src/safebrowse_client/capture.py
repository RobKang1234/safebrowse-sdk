from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlparse


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_html_surface_capture(
    *,
    url: str,
    visible_text: str,
    html: str | None = None,
    frame_url: str | None = None,
    hidden_text: list[str] | None = None,
    metadata_text: list[str] | None = None,
    annotations: list[str] | None = None,
    user_shared: bool = False,
    nested_unsupported_components: list[str] | None = None,
    capture_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    effective_frame_url = frame_url or url
    unsupported_subtrees = nested_unsupported_components or []
    return {
        "surfaceType": "html",
        "url": url,
        "frameUrl": effective_frame_url,
        "html": html,
        "visibleText": visible_text,
        "hiddenText": hidden_text or [],
        "metadataText": metadata_text or [],
        "annotations": annotations or [],
        "userShared": user_shared,
        "nestedUnsupportedComponents": unsupported_subtrees,
        "captureAttestation": capture_attestation
        or {
            "captureMethod": "rendered_dom",
            "visibilityAttested": bool(visible_text.strip()),
            "frameCoverage": "full",
            "shadowDomCoverage": "full",
            "unsupportedSubtrees": unsupported_subtrees,
        },
        "trustSignals": {
            "sourceOrigin": _origin_of(url),
            "frameOrigin": _origin_of(effective_frame_url),
            "sameOriginRelation": "same-origin"
            if _origin_of(url) == _origin_of(effective_frame_url)
            else "cross-origin",
            "visibilityClass": "visible",
            "extractionMethod": "dom",
            "artifactKind": "page",
            "taintClass": "session-discovered",
            "lineageChain": ["python-wrapper-capture"],
            "userSharedFlag": user_shared,
            "sessionDiscoveredFlag": not user_shared,
        },
    }


def _default_extraction_attestation(extractor_id: str) -> dict[str, Any]:
    return {
        "extractorId": extractor_id,
        "extractorVersion": "1.0.0",
        "parserDigest": f"{extractor_id}-digest",
        "networkPolicy": "deny",
        "maxRecursionDepth": 3,
        "maxExpandedBytes": 5_000_000,
        "extractedAt": "2026-04-05T00:00:00.000Z",
    }


def build_email_surface_capture(
    *,
    url: str,
    provider_id: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    mailbox_id: str | None = None,
    account_id: str | None = None,
    message_id: str | None = None,
    thread_id: str | None = None,
    to: list[str] | None = None,
    cc: list[str] | None = None,
    headers: list[str] | None = None,
    auth_results: list[str] | None = None,
    quoted_thread_text: list[str] | None = None,
    remote_content: list[str] | None = None,
    action_candidates: list[dict[str, Any]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    raw_mime_base64: str | None = None,
    raw_mime_bytes: bytes | None = None,
    extraction_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "surfaceType": "email_message",
        "url": url,
        "providerId": provider_id,
        "mailboxId": mailbox_id,
        "accountId": account_id,
        "messageId": message_id,
        "threadId": thread_id,
        "subject": subject,
        "bodyText": body_text,
        "bodyHtml": body_html,
        "to": to or [],
        "cc": cc or [],
        "headers": headers or [],
        "authResults": auth_results or [],
        "quotedThreadText": quoted_thread_text or [],
        "remoteContent": remote_content or [],
        "actionCandidates": action_candidates or [],
        "attachments": attachments or [],
        "rawMimeBase64": raw_mime_base64
        or (
            base64.b64encode(raw_mime_bytes).decode("ascii")
            if raw_mime_bytes is not None
            else None
        ),
        "extractionAttestation": extraction_attestation
        or _default_extraction_attestation("python-email-extractor"),
    }


def _build_office_surface_capture(
    *,
    surface_type: str,
    url: str,
    visible_text: str,
    metadata_text: list[str] | None = None,
    comments: list[str] | None = None,
    notes: list[str] | None = None,
    tracked_changes: list[str] | None = None,
    hidden_text: list[str] | None = None,
    formulas: list[str] | None = None,
    external_relationships: list[str] | None = None,
    embedded_objects: list[str] | None = None,
    links: list[dict[str, Any]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    unsupported_subtrees: list[str] | None = None,
    content_base64: str | None = None,
    content_bytes: bytes | None = None,
    extraction_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "surfaceType": surface_type,
        "url": url,
        "contentBase64": content_base64
        or (
            base64.b64encode(content_bytes).decode("ascii")
            if content_bytes is not None
            else None
        ),
        "visibleText": visible_text,
        "metadataText": metadata_text or [],
        "comments": comments or [],
        "notes": notes or [],
        "trackedChanges": tracked_changes or [],
        "hiddenText": hidden_text or [],
        "formulas": formulas or [],
        "externalRelationships": external_relationships or [],
        "embeddedObjects": embedded_objects or [],
        "links": links or [],
        "attachments": attachments or [],
        "unsupportedSubtrees": unsupported_subtrees or [],
        "extractionAttestation": extraction_attestation
        or _default_extraction_attestation(f"python-{surface_type}-extractor"),
    }


def build_docx_surface_capture(**kwargs: Any) -> dict[str, Any]:
    return _build_office_surface_capture(surface_type="docx", **kwargs)


def build_xlsx_surface_capture(**kwargs: Any) -> dict[str, Any]:
    return _build_office_surface_capture(surface_type="xlsx", **kwargs)


def build_pptx_surface_capture(**kwargs: Any) -> dict[str, Any]:
    return _build_office_surface_capture(surface_type="pptx", **kwargs)


def build_external_api_surface_capture(
    *,
    url: str,
    provider_id: str,
    operation_id: str,
    method: str,
    base_url: str,
    path_template: str,
    response_text: str | None = None,
    response_fields: list[str] | None = None,
    linked_urls: list[str] | None = None,
    action_candidates: list[dict[str, Any]] | None = None,
    request_schema_hash: str | None = None,
    response_schema_hash: str | None = None,
    extraction_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "surfaceType": "external_api_response",
        "url": url,
        "providerId": provider_id,
        "operationId": operation_id,
        "method": method,
        "baseUrl": base_url,
        "pathTemplate": path_template,
        "responseText": response_text,
        "responseFields": response_fields or [],
        "linkedUrls": linked_urls or [],
        "actionCandidates": action_candidates or [],
        "requestSchemaHash": request_schema_hash,
        "responseSchemaHash": response_schema_hash,
        "extractionAttestation": extraction_attestation
        or _default_extraction_attestation("python-api-extractor"),
    }


def build_attachment_bundle_surface_capture(
    *,
    url: str,
    attachments: list[dict[str, Any]],
    root_attachment_id: str | None = None,
    extraction_attestations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "surfaceType": "attachment_bundle",
        "url": url,
        "rootAttachmentId": root_attachment_id,
        "attachments": attachments,
        "extractionAttestations": extraction_attestations
        or [_default_extraction_attestation("python-attachment-extractor")],
    }
