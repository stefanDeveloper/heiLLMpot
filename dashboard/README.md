# Dashboard

The dashboard is a Dockerized Next.js app for live orchestrator telemetry.

## Structure

```text
src/app/                 Next.js App Router pages and API route handlers
src/app/api/snapshot/    JSON snapshot endpoint used by the UI
src/app/health/          container health endpoint
src/components/          Reusable dashboard UI components
src/lib/                 environment, database, formatting, and query helpers
```

The browser only talks to the Next.js API routes. Server-side route handlers read
PostgreSQL directly inside the Docker Compose network.

## Local Development

```bash
npm ci
npm run dev
```

The dev server listens on `http://localhost:8090`.

## Production Container

```bash
docker compose up -d --build dashboard
```

The dashboard binds to `127.0.0.1:${DASHBOARD_PORT:-8090}`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `DASHBOARD_PORT` | `8090` | Host port in Docker Compose |
| `DASHBOARD_REFRESH_MS` | `4000` | Browser refresh interval |
| `DASHBOARD_ROW_LIMIT` | `80` | Rows returned per live table |
| `DASHBOARD_REDACT_SECRETS` | `true` | Masks captured passwords in the UI/API |

Keep `DASHBOARD_REDACT_SECRETS=true` for demos and public screenshots.
