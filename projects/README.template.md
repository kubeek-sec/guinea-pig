# <Product name>

<One paragraph: what the application is, who uses it, what it manages.>

## Overview

- **Stack**: <language / framework / database>
- **Port**: `<port>`

## Features

- <feature 1>
- <feature 2>
- <feature 3>

## Build

```bash
docker build -t <image> .
```

<Optional: native build without docker (toolchain + command).>

## Run

```bash
docker run --rm -p <port>:<port> <image>
```

The service is ready when `http://localhost:<port><health>` answers `200`.

## URLs

| URL | Description |
|---|---|
| `http://localhost:<port>/` | <home / UI> |
| `http://localhost:<port><health>` | health check |
| `http://localhost:<port>/api/...` | <API resource> |

## API documentation (OpenAPI / Swagger)

- OpenAPI document: `http://localhost:<port><openapi>`
- Swagger UI: `http://localhost:<port>/<swagger-ui path>` <if provided>

## Configuration

| Variable | Default | Description |
|---|---|---|
| `<VAR>` | `<default>` | <meaning> |

## Default accounts

| User | Password | Role |
|---|---|---|
| <user> | <password> | <role> |
