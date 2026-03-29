from __future__ import annotations

from pathlib import Path


MODEL_CONNECTED_BROWSER_AGENT_TEMPLATE = """import json
import uuid
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from safebrowse_client import SafeBrowseClient


def call_model(messages: list[dict]) -> dict:
    \"""
    Replace this with your OpenAI, Claude, or other model client.

    Return JSON like:
    {"action": "summarize"}
    or
    {"action": "navigate", "target_url": "https://docs.python.org/3/tutorial/"}
    \"""
    raise NotImplementedError("Plug your model client in here")


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def make_observation_payload(page, visible_text: str) -> dict:
    current_url = page.url
    return {
        "observationId": str(uuid.uuid4()),
        "sourceType": "page",
        "text": visible_text,
        "fragments": [
            {
                "text": visible_text,
                "visibilityClass": "visible",
                "medium": "text",
                "sourceOrigin": current_url,
                "frameOrigin": current_url,
            }
        ],
        "trustSignals": {
            "sourceOrigin": current_url,
            "frameOrigin": current_url,
            "sameOriginRelation": "same-origin",
            "visibilityClass": "visible",
            "extractionMethod": "dom",
            "artifactKind": "page",
            "taintClass": "session-discovered",
            "lineageChain": [str(uuid.uuid4())],
            "userSharedFlag": False,
            "sessionDiscoveredFlag": True,
        },
    }


def make_action_payload(page, target_url: str) -> dict:
    current_url = page.url
    current_origin = origin_of(current_url)
    target_origin = origin_of(target_url)
    return {
        "actionId": str(uuid.uuid4()),
        "verb": "navigate",
        "currentOrigin": current_origin,
        "targetOrigin": target_origin,
        "targetUrl": target_url,
        "riskClass": "low",
        "requestedWrite": False,
        "trustSignals": {
            "sourceOrigin": current_origin,
            "frameOrigin": current_origin,
            "sameOriginRelation": "cross-site" if current_origin != target_origin else "same-origin",
            "visibilityClass": "visible",
            "extractionMethod": "dom",
            "artifactKind": "page",
            "taintClass": "tainted",
            "lineageChain": [str(uuid.uuid4())],
            "userSharedFlag": False,
            "sessionDiscoveredFlag": True,
        },
    }


def extract_visible_text(page) -> str:
    body = page.locator("body")
    text = body.inner_text(timeout=5000)
    return text[:12000]


def run_agent():
    sb = SafeBrowseClient("http://127.0.0.1:8787")

    print("Daemon health:", sb.health())

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        page.goto("https://arxiv.org/abs/1706.03762", wait_until="domcontentloaded")

        for step in range(5):
            visible_text = extract_visible_text(page)
            observe_result = sb.observe(make_observation_payload(page, visible_text))
            print(f"\\n[step {step}] observe:", json.dumps(observe_result, indent=2)[:800])

            model_input = [
                {
                    "role": "system",
                    "content": (
                        "You are a browsing agent. "
                        "Return only JSON. "
                        "Allowed actions: summarize, navigate. "
                        "If navigating, choose a helpful public documentation or research URL."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "current_url": page.url,
                            "page_excerpt": observe_result.get("normalizedText", visible_text[:3000]),
                            "suspicion_flags": observe_result.get("suspicionFlags", []),
                        }
                    ),
                },
            ]

            decision = call_model(model_input)
            print(f"[step {step}] model:", decision)

            if decision["action"] == "summarize":
                print("[agent] summary requested; stopping.")
                break

            if decision["action"] == "navigate":
                target_url = decision["target_url"]
                verdict = sb.action(make_action_payload(page, target_url))
                print(f"[step {step}] verdict:", json.dumps(verdict, indent=2))

                if verdict["decision"] != "ALLOW":
                    print("[agent] navigation blocked by SafeBrowse")
                    break

                page.goto(target_url, wait_until="domcontentloaded")
                continue

            print("[agent] unknown model action; stopping.")
            break

        browser.close()


if __name__ == "__main__":
    run_agent()
"""


def get_model_connected_browser_agent_template() -> str:
    return MODEL_CONNECTED_BROWSER_AGENT_TEMPLATE


def write_model_connected_browser_agent_template(path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(MODEL_CONNECTED_BROWSER_AGENT_TEMPLATE, encoding="utf-8")
    return destination
