from __future__ import annotations

from pathlib import Path


MODEL_CONNECTED_BROWSER_AGENT_TEMPLATE = """import json
import uuid

from playwright.sync_api import sync_playwright
from safebrowse_client import SafeBrowseClient, build_html_surface_capture


def call_model(messages: list[dict]) -> dict:
    \"""
    Replace this with your OpenAI, Claude, or other model client.

    Return JSON like:
    {"action": "summarize"}
    or:
    {"action": "use_authority", "authority_id": "..."}
    \"""
    raise NotImplementedError("Plug your model client in here")


def make_surface_capture(page, visible_text: str, html: str) -> dict:
    return build_html_surface_capture(url=page.url, visible_text=visible_text, html=html)


def extract_visible_text(page) -> str:
    body = page.locator("body")
    text = body.inner_text(timeout=5000)
    return text[:12000]


def run_agent():
    sb = SafeBrowseClient("http://127.0.0.1:8787")

    print("Daemon health:", sb.health())
    session = sb.start_session(
        {
            "taskId": f"task-{uuid.uuid4()}",
            "userGoal": "Summarize relevant public research pages without leaving the allowed origin set unless SafeBrowse mints a capability.",
            "allowedOrigins": [
                "https://arxiv.org",
                "https://docs.python.org",
            ],
            "allowedVerbs": ["navigate"],
            "forbiddenSinks": [],
        }
    )["session"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        page.goto("https://arxiv.org/abs/1706.03762", wait_until="domcontentloaded")

        for step in range(5):
            visible_text = extract_visible_text(page)
            html = page.content()
            observe_result = sb.observe(
                {
                    "sessionId": session["sessionId"],
                    "capture": make_surface_capture(page, visible_text, html),
                }
            )
            print(f"\\n[step {step}] observe:", json.dumps(observe_result, indent=2)[:800])
            planner_view = observe_result["plannerView"]
            authorities = observe_result["authorityCandidates"]

            model_input = [
                {
                    "role": "system",
                    "content": (
                        "You are a browsing agent. "
                        "Return only JSON. "
                        "Allowed actions: summarize, use_authority. "
                        "Use only one authority from the supplied list. "
                        "Do not invent URLs, selectors, connectors, or tool callbacks."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "current_url": page.url,
                            "planner_view": planner_view,
                            "authorities": authorities,
                        }
                    ),
                },
            ]

            decision = call_model(model_input)
            print(f"[step {step}] model:", decision)

            if decision["action"] == "summarize":
                print("[agent] summary requested; stopping.")
                break

            if decision["action"] == "use_authority":
                result = sb.action(
                    {
                        "sessionId": session["sessionId"],
                        "authorityId": decision["authority_id"],
                        "authorityDigest": next(
                            authority["authorityDigest"]
                            for authority in authorities
                            if authority["authorityId"] == decision["authority_id"]
                        ),
                        "parameters": {},
                    }
                )
                print(f"[step {step}] action:", json.dumps(result, indent=2))

                effect_decision = result.get("effectDecision", {})
                if effect_decision.get("decision") == "APPROVAL_REQUIRED":
                    print("[agent] action requires an approval envelope; stopping.")
                    break
                if effect_decision.get("decision") != "ALLOW":
                    print("[agent] navigation blocked by SafeBrowse")
                    break

                execution_plan = result.get("executionPlan", {})
                target_url = execution_plan.get("targetUrl")
                if not target_url:
                    print("[agent] no target URL returned; stopping.")
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
