# Centaur‑Jarvis Web UI – Architecture & Post‑Mortem

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Dashboard │  │ Scan Details│  │      Reports        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│           │               │                     │            │
│           └───────────────┼─────────────────────┘            │
│                     │ API Client (Axios) │                   │
│                     │ WebSocket Client   │                   │
└─────────────────────────────┬────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────┐
│                    Backend (FastAPI)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Routes    │  │   Models    │  │   Dependencies      │  │
│  │  • scans    │  │  • Scan     │  │  • Redis client     │  │
│  │  • results  │  │  • Finding  │  │  • DB session       │  │
│  │  • status   │  │             │  │  • Config           │  │
│  │  • websocket│  └─────────────┘  └─────────────────────┘  │
│  └─────────────┘                                             │
│           │               │                     │            │
│           ▼               ▼                     ▼            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Redis     │  │   SQLite    │  │   CLI Subprocess    │  │
│  │ • results   │  │ • scans     │  │  (python -m cli)    │  │
│  │ • task:status│ │ • findings  │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────┐
│                    Existing Core System                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Orchestrator│  │   Workers   │  │   Modules           │  │
│  │             │  │ (recon,     │  │ (nuclei, fuzzer,    │  │
│  │             │  │  dirbust,   │  │  idor, etc.)        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│           │                                                    │
│           ▼                                                    │
│  ┌─────────────┐                                               │
│  │   Redis     │                                               │
│  │ (queues)    │                                               │
│  └─────────────┘                                               │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

1. **Separation of Concerns**: API layer isolates web UI from core system; frontend communicates only via REST/WebSocket.
2. **Async FastAPI**: Leverages async/await for non‑blocking Redis and DB operations.
3. **SQLite for Persistence**: Lightweight, file‑based storage for scans and findings; easy to backup and inspect.
4. **WebSocket for Real‑time**: Live updates pushed from backend as scan progresses.
5. **Graceful Degradation**: UI shows appropriate error messages when Redis/DB/backend is unavailable.
6. **Modular Frontend**: React components are reusable and independently testable.
7. **Theme Support**: Dark/light toggle using daisyUI’s theme system.

## Edge Cases Mitigated

| Scenario | Mitigation |
|----------|------------|
| Redis connection lost | API logs error, returns 503; frontend shows "Backend offline" |
| Scan start fails (CLI error) | API returns 400 with error details; frontend displays alert |
| WebSocket disconnects | Frontend automatically reconnects with exponential backoff |
| No findings yet | UI shows empty state with friendly message |
| Large number of findings | Pagination in API and frontend table |
| Database write error | Log error, fallback to in‑memory (findings may be lost) |
| Duplicate scan start | Reject with 409 if scan already running for same target |
| Frontend tries to connect to non‑existent scan | WebSocket closes with 404; frontend shows error |
| API server not running | Frontend shows connection error with retry button |
| Malformed data from Redis | Log, skip, continue processing |

## Remaining Loopholes & Future Improvements

1. **Task Queue**: Currently scans are started via subprocess; better to push tasks to Redis queue and let orchestrator handle them.
2. **Authentication**: No user authentication; anyone on localhost can start scans. Add API keys or basic auth.
3. **Multi‑user Support**: Database currently single‑tenant; add user‑scoped scans.
4. **Report Generation**: Integrate with existing reporting module to produce HTML/PDF reports.
5. **Performance**: SQLite may become a bottleneck with high scan volume; consider PostgreSQL.
6. **WebSocket Scalability**: Current implementation broadcasts to all connected clients; fine for localhost but not for many users.
7. **Frontend State Management**: Use Redux or Zustand for complex state.
8. **Testing**: Add unit/integration tests for API and frontend components.
9. **Deployment**: Dockerize the whole stack for easy deployment.

## Performance Considerations

- **Redis**: All reads/writes are non‑blocking; connection pooling used.
- **SQLite**: Use indexes on `scan_id` and `severity` columns.
- **WebSocket**: Each scan has its own WebSocket connection; limit connections per client.
- **Frontend**: Chart.js may slow down with thousands of data points; virtualize tables.

## Testing Results

- Basic smoke test passes: API starts, frontend builds, WebSocket connects.
- Redis unavailable: API returns degraded health status.
- Database creation: tables created automatically on startup.
- Scan start: CLI subprocess invoked (requires Redis and core workers).

## Conclusion

The web UI provides a professional Nessus‑like interface for Centaur‑Jarvis, integrating seamlessly with the existing core while adhering to the 360‑degree edge‑case handling principle. It is modular, extensible, and ready for localhost deployment.
