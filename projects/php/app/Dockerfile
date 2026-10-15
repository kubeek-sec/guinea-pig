FROM composer:2.7 AS vendor

WORKDIR /src
COPY composer.json ./
RUN composer install --no-dev --no-interaction --prefer-dist --no-scripts

FROM php:8.3-cli

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=vendor /src/vendor ./vendor
COPY src ./src
COPY public ./public
COPY composer.json openapi.yml ./

ENV TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["sh", "-c", "php -S 0.0.0.0:${PORT} -t public public/index.php"]
