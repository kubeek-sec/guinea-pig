FROM node:22-bookworm-slim AS build

WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY package.json openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    NODE_OPTIONS=--experimental-sqlite \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["node", "dist/index.js"]
