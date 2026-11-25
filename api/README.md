# API Server & Control Plane Service

Exposes REST API endpoints and serves the Web Dashboard.

## Endpoints
- `GET /`: Serves the interactive web dashboard (`web/index.html`).
- `GET /health`, `GET /api/status`: Reports compiler status, active state, and audit log head.
- `POST /api/compile`: Submits source code (`mode=zero-trust` or `mode=legacy-fast`).
- `GET /api/audit`: Returns the cryptographically hash-chained audit log records.
- `POST /api/safe_stop`: Global emergency kill switch triggering immediate domain halt.

Supports dual runtimes: Zero-dependency native HTTP server (`python -m api.server 8000`) and FastAPI.
