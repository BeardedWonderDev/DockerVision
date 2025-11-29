# DockerVision Agent

Local macOS agent that exposes a curated REST API for monitoring and controlling Docker containers. Designed to be consumed by the DockerVision Vision Pro client.

## Features (current)
- Health check and Docker connectivity validation.
- Engine info endpoint.
- List/inspect containers.
- Start/stop/restart containers.
- Fetch container logs with tail/follow options.
- Stream Docker events via SSE (`/events`) with optional filters.

## Planned
- Auth (bearer or mTLS) and optional TLS listener.
- Prometheus metrics.
- launchd packaging for auto-start.
- Integration tests gated by `RUN_DOCKER_TESTS=1`.

## Development
```bash
make test     # run unit tests
make run      # start server on 127.0.0.1:8364
```

Environment variables:
- `DV_LISTEN_ADDR` (default `127.0.0.1:8364`)
- `DV_LOG_LEVEL` (default `info`)
- `DV_AUTH_TOKEN` (optional)
- `DV_TLS_CERT` / `DV_TLS_KEY` (optional TLS)
- `DOCKER_HOST` (override socket)

## Security Note
The agent refuses to bind to a public address unless auth or TLS is configured. Keep it on loopback for local-only use.
