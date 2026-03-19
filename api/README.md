# Centaur‑Jarvis Web API

FastAPI backend for the Centaur‑Jarvis web UI dashboard.

## Features

- RESTful API for managing scans, findings, and statistics
- Real‑time WebSocket updates for live scan progress
- SQLite database for persistent storage of scans and findings
- Redis integration for reading results and status from the core system
- Automatic OpenAPI documentation at `/api/docs`

## Installation

1. Ensure Python 3.10+ is installed.
2. Install dependencies:

```bash
pip install -r requirements-api.txt
```

3. Configure environment variables (copy `.env.example` to `.env` and adjust).

4. Start Redis (if not already running):

```bash
redis-server
```

## Running the API

```bash
uvicorn api.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

## API Endpoints

- `GET /api/health` – health check
- `GET /api/stats` – global statistics
- `POST /api/scans` – start a new scan
- `GET /api/scans` – list scans
- `GET /api/scans/{scan_id}` – scan details
- `DELETE /api/scans/{scan_id}` – delete scan
- `GET /api/scans/{scan_id}/findings` – findings for a scan
- `GET /api/results/findings` – all findings with filters
- `GET /api/results/stats` – findings statistics
- WebSocket `ws://localhost:8000/ws/{scan_id}` – live updates

## Database

SQLite database is automatically created at `./centaur.db`. Tables:
- `scans` – scan metadata
- `findings` – vulnerability findings

## Integration with Core

The API calls the CLI via subprocess to start scans:

```bash
python -m cli.main --target <target> --profile <profile> --manual
```

Results are consumed from Redis `results:incoming` queue and stored in the database.

## Error Handling

- Redis connection failures are logged; API returns 503.
- Database errors are caught and logged.
- WebSocket disconnections are handled with automatic reconnection.

## Development

- Use `DEBUG=true` for detailed logs.
- The frontend is served from `./frontend/dist` (built with `npm run build`).
