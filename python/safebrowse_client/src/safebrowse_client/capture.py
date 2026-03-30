from __future__ import annotations

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
) -> dict[str, Any]:
    effective_frame_url = frame_url or url
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
        "nestedUnsupportedComponents": nested_unsupported_components,
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
