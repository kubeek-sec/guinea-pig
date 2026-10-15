FROM ruby:3.3-bookworm AS build

WORKDIR /src
COPY Gemfile ./
RUN bundle config set --local path /gems \
 && bundle config set --local without development:test \
 && bundle install

FROM ruby:3.3-slim-bookworm

WORKDIR /srv/toolshed

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /gems /gems
COPY --from=build /src/Gemfile /src/Gemfile.lock ./
COPY lib ./lib
COPY config.ru openapi.yml ./

ENV BUNDLE_PATH=/gems \
    BUNDLE_WITHOUT=development:test \
    TOOLSHED_DB=/srv/toolshed/var/toolshed.db \
    TOOLSHED_UPLOADS=/srv/toolshed/var/uploads \
    PORT=8000

RUN mkdir -p /srv/toolshed/var/uploads

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["sh", "-c", "bundle exec puma -b tcp://0.0.0.0:${PORT} config.ru"]
