# Centaur‑Jarvis Web UI

React‑based dashboard for the Centaur‑Jarvis VAPT agent.

## Features

- Real‑time dashboard with statistics and charts
- Start new scans with target and profile selection
- View scan details with progress bars
- Interactive findings table with severity filters
- Live feed of WebSocket events
- Dark/light theme toggle
- Responsive design with Tailwind CSS + daisyUI

## Installation

1. Ensure Node.js 18+ is installed.
2. Install dependencies:

```bash
cd frontend
npm install
```

3. Configure environment (optional) – see `.env.example`.

## Development

Run the development server:

```bash
npm run dev
```

The UI will be available at `http://localhost:5173`.

## Building for Production

```bash
npm run build
```

The built files will be placed in `frontend/dist`. The FastAPI backend can serve these static files.

## Project Structure

- `src/components/` – reusable React components
- `src/pages/` – page components (Home, ScanDetails, Reports)
- `src/api.js` – API client
- `src/websocket.js` – WebSocket client
- `src/theme.jsx` – theme context

## Integration with Backend

The frontend communicates with the backend via:
- REST API (`/api/*`) proxied through Vite
- WebSocket (`/ws/*`) for real‑time updates

## Styling

Uses Tailwind CSS with daisyUI components. Theme is controlled via `data-theme` attribute.

## Known Issues

- WebSocket reconnection may cause duplicate messages.
- Chart.js may not update correctly with rapid data changes.
- Large findings tables may impact performance (pagination recommended).
