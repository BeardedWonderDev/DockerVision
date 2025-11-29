# DockerVision Agent

Local macOS agent that exposes a curated REST API for monitoring and controlling Docker containers. Designed to be consumed by the DockerVision Vision Pro client.

## Features (current)
- Health check and Docker connectivity validation.
- Engine info endpoint.
- List/inspect containers.
- Start/stop/restart containers.
- Fetch container logs with tail/follow options.
- Stream Docker events via SSE (`/events`) with optional filters.
- WebSocket (`/ws`) bidirectional control: lifecycle commands plus streaming logs/events over a single socket.
- Exec over WebSocket with stdin/stdout and resize support.
- Optional TLS and mTLS (provide cert/key and client CA).
- Prometheus metrics at `/metrics`; optional OpenTelemetry tracing via OTLP/HTTP.
- launchd installer for macOS user agents.
- `dvctl` CLI for local debugging (health, info, list, logs, start/stop/restart).

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
- `DV_TLS_CLIENT_CA` (if set, require client certs)
- `DOCKER_HOST` (override socket)
- `DV_AUTH_TOKEN` (if set, all protected routes and /ws require `Authorization: Bearer <token>`)
- `DV_OTEL_ENDPOINT` (OTLP/HTTP tracing endpoint; optional)
- `DV_OTEL_INSECURE=true` to disable TLS for OTLP
- `DV_TLS_CLIENT_CA` (require client certs for mTLS)

## Metrics & Tracing
- `/metrics` exposes Prometheus metrics (request counts, latencies). Protected by bearer token if configured.
- Tracing: set `DV_OTEL_ENDPOINT` to enable OTLP/HTTP exporter; spans wrap HTTP handlers.

## launchd install
```bash
make install   # builds binary to ~/Library/Application\ Support/DockerVision and loads plist
make uninstall # unloads and removes plist/binary
```

## dvctl CLI
```bash
go run ./cmd/dvctl health
go run ./cmd/dvctl list
go run ./cmd/dvctl logs -id <container> -n 100
DV_AUTH_TOKEN=token go run ./cmd/dvctl start -id <container>
```

## Swift SDK
Swift Package Manager package lives at `sdk/swift/DockerVisionSDK`.

Add dependency:
```swift
.package(path: "sdk/swift/DockerVisionSDK")
```

Basic usage:
```swift
import DockerVisionSDK

let client = DockerVisionClient(config: .init(baseURL: URL(string: "http://127.0.0.1:8364")!,
                                              token: "your-token"))
let containers = try await client.listContainers()
```
## Security Note
The agent refuses to bind to a public address unless auth or TLS is configured. Keep it on loopback for local-only use.
