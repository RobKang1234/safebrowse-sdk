# `safebrowse-client`

Thin Python client for the SafeBrowse localhost daemon.

## Install

```bash
pip install safebrowse-client
```

## Example

```python
from safebrowse_client import SafeBrowseClient

client = SafeBrowseClient("http://127.0.0.1:8787")
health = client.health()
print(health["status"])
```

This package is intentionally thin: policy enforcement lives in the SafeBrowse daemon.

## Model-Connected Browser Template

The release package also includes a starter template for a model-connected
browser agent that uses SafeBrowse while visiting normal external websites.

Generate a local copy:

```python
from safebrowse_client import write_model_connected_browser_agent_template

path = write_model_connected_browser_agent_template("model_connected_browser_agent.py")
print(path)
```

Or inspect the template string directly:

```python
from safebrowse_client import get_model_connected_browser_agent_template

print(get_model_connected_browser_agent_template())
```

The template is a real Python file with placeholders for:

- your model client
- Playwright browsing
- SafeBrowse observation checks
- SafeBrowse action gating before external navigation
- example public sites such as `https://arxiv.org` and `https://docs.python.org`

Repository:

- https://github.com/RobKang1234/safebrowse-sdk#readme
