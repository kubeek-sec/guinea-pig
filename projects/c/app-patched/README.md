# Toolshed

Toolshed is the lending service of a neighbourhood workshop. Members browse the
rack, take a tool out for a few days, attach a photo of its condition and bring it
back. Staff members also look up member records.

## Overview

- **Stack**: C11, libmicrohttpd, SQLite, OpenSSL (HMAC-SHA256), libcrypt (bcrypt)
- **Port**: `8000`
- **Storage**: a SQLite file and an uploads directory, both under `var/`
  (created on first start and seeded with five tools and three members)

## Features

- Public catalogue, searchable and sortable
- Bearer-token sessions for members, with a staff role
- Rentals: take a tool out, list your own, bring it back
- Condition photos attached to a rental

## Build

```bash
docker build -t toolshed-c .
```

Without docker, with the development packages in place:

```bash
sudo apt-get install build-essential libmicrohttpd-dev libsqlite3-dev libssl-dev libcrypt-dev
make
```

## Run

```bash
docker run --rm -p 8000:8000 -e TOOLSHED_TOKEN_KEY=change-me toolshed-c
```

Without docker:

```bash
TOOLSHED_TOKEN_KEY=change-me ./toolshed
```

`openapi.yml` is read from the working directory, so run the binary from the
project root.

The service is ready when `http://localhost:8000/healthz` answers `200`.

## URLs

| URL | Description |
|---|---|
| `http://localhost:8000/` | catalogue page |
| `http://localhost:8000/healthz` | health check |
| `http://localhost:8000/api/tools` | the catalogue (`?sort=name\|category\|daily_rate`) |
| `http://localhost:8000/api/tools/search?q=saw` | search |
| `http://localhost:8000/api/tools/1` | one tool |
| `http://localhost:8000/api/session` | `POST` sign in, returns a bearer token |
| `http://localhost:8000/api/members/me` | the signed-in member |
| `http://localhost:8000/api/members/1` | one member (staff only) |
| `http://localhost:8000/api/rentals` | `GET` your rentals, `POST` take a tool out |
| `http://localhost:8000/api/rentals/1/return` | `POST` bring a tool back |
| `http://localhost:8000/api/photos` | `POST` attach a condition photo |
| `http://localhost:8000/api/photos/<name>` | fetch a photo |

## API documentation (OpenAPI / Swagger)

The OpenAPI document is served by the application:

- `http://localhost:8000/openapi.yml`

Import it into Swagger UI, Postman or an API client to get every endpoint, its
parameters and its responses.

```bash
curl -s http://localhost:8000/openapi.yml -o openapi.yml
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | listening port |
| `TOOLSHED_DB` | `var/toolshed.db` | SQLite file |
| `TOOLSHED_UPLOADS` | `var/uploads` | where condition photos are written |
| `TOOLSHED_TOKEN_KEY` | *(required)* | key the bearer tokens are signed with |
| `TOOLSHED_TOKEN_TTL` | `3600` | token lifetime, in seconds |

## Default accounts

| Email | Password | Role |
|---|---|---|
| `ada@toolshed.example` | `workshop-keeper` | staff |
| `jun@toolshed.example` | `sawdust-season` | member |
| `pierre@toolshed.example` | `bench-grinder` | member |

## Example session

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/session \
  -H 'Content-Type: application/json' \
  -d '{"email":"jun@toolshed.example","password":"sawdust-season"}' | jq -r .token)

curl -s http://localhost:8000/api/tools?sort=daily_rate | jq .
curl -s -X POST http://localhost:8000/api/rentals \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"tool_id":1,"days":3,"notes":"for the deck boards"}' | jq .
```
