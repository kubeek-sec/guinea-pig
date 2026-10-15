FROM debian:bookworm-slim AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libmicrohttpd-dev libsqlite3-dev libssl-dev libcrypt-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make

FROM debian:bookworm-slim

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl libmicrohttpd12 libsqlite3-0 libssl3 libcrypt1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/toolshed /usr/local/bin/toolshed
COPY openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["toolshed"]
