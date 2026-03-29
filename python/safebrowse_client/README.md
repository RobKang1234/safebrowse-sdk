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

Repository:

- https://github.com/RobKang1234/safebrowse-sdk#readme
