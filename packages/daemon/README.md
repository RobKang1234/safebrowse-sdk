# `@safebrowse/daemon`

Localhost SafeBrowse daemon with built-in runtime assets for policy, registry, and KB loading.

## Install

```bash
npm install @safebrowse/daemon
```

## Run

```bash
npx @safebrowse/daemon --host 127.0.0.1 --port 8787
```

Environment variables:

- `SAFEBROWSE_HOST`
- `SAFEBROWSE_PORT`
- `SAFEBROWSE_ROOT_DIR`

Health endpoint:

```text
GET /health
```

See the repository README for full daemon routes and operational guidance:

- https://github.com/RobKang1234/safebrowse-sdk#readme
