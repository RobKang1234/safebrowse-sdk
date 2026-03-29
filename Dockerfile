FROM node:22-bookworm-slim AS build

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /workspace

RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.scripts.json ./
COPY packages ./packages
COPY scripts ./scripts
COPY config ./config
COPY knowledge_base ./knowledge_base
COPY policies ./policies
COPY python ./python
COPY README.md LICENSE SECURITY.md RELEASING.md ./

RUN pnpm install --frozen-lockfile
RUN pnpm build
RUN pnpm --filter @safebrowse/daemon deploy --legacy --prod /opt/safebrowse

FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV SAFEBROWSE_HOST=0.0.0.0
ENV SAFEBROWSE_PORT=8787

WORKDIR /app

COPY --from=build /opt/safebrowse/ ./

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD node --input-type=module -e "const response = await fetch('http://127.0.0.1:8787/health'); if (!response.ok) process.exit(1);"

USER node

CMD ["node", "dist/index.js"]
