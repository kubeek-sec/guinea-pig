FROM golang:1.22-bookworm AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/toolshed .

FROM debian:bookworm-slim

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/toolshed /usr/local/bin/toolshed
COPY openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["toolshed"]
