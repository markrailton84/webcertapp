# CertManager

[![Docker Build](https://github.com/markrailton84/webcertapp/actions/workflows/docker-build.yml/badge.svg)](https://github.com/markrailton84/webcertapp/actions/workflows/docker-build.yml)
[![CodeQL](https://github.com/markrailton84/webcertapp/actions/workflows/codeql.yml/badge.svg)](https://github.com/markrailton84/webcertapp/actions/workflows/codeql.yml)

A team certificate management web app built with Python/Flask. Track TLS/SSL certificates across your systems, get notified before they expire via Email and Microsoft Teams, and integrate programmatically via the REST API.

## Features

- **Dashboard** — view all certificates with expiry status (OK, Warning, Critical, Expired)
- **3 ways to add certificates** — manual entry, file upload, or auto-fetch from a hostname
- **Supported file formats** — `.pem`, `.crt`, `.cer`, `.der`, `.p7b`
- **Notifications** — Email (SMTP) and Microsoft Teams (Adaptive Cards) alerts
- **Configurable thresholds** — alert at 90, 60, 30, 14, 7 days (or any custom values)
- **Multi-user** — admin and user roles, managed via the UI
- **REST API** — query, add, bulk-import, and fetch certificates programmatically
- **Docker** — runs as a single container with persistent SQLite storage

---

## Quick Start

```bash
git clone <repo-url>
cd certmanager
cp .env.example .env   # edit with your settings
docker compose up -d
```

Open [http://localhost:5000](http://localhost:5000).

Default login: `admin` / `changeme` — **change this immediately** via Settings > Users.

---

## Configuration

Copy `.env.example` to `.env` and set the following:

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session secret (use a random string) | `change-me` |
| `ADMIN_USERNAME` | Initial admin username | `admin` |
| `ADMIN_PASSWORD` | Initial admin password | `changeme` |
| `ADMIN_EMAIL` | Initial admin email | `admin@example.com` |
| `SMTP_HOST` | SMTP server hostname | — |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | — |
| `SMTP_PASSWORD` | SMTP password | — |
| `SMTP_FROM` | From address for alert emails | — |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams Incoming Webhook URL | — |

Email and Teams settings can also be configured in the UI under **Settings**.

---

## Project Structure

```
certmanager/
├── app/
│   ├── __init__.py          # Flask app factory, auto-creates admin user
│   ├── models.py            # Certificate, User, Settings, AlertLog models
│   ├── routes/
│   │   ├── api.py           # REST API — /api/v1/*
│   │   ├── auth.py          # Login, logout, user management
│   │   ├── certs.py         # Dashboard, add/edit/delete, upload, fetch
│   │   └── settings.py      # SMTP + Teams config, test buttons, API key
│   ├── services/
│   │   ├── cert_parser.py   # Parse PEM/DER/P7B certificate files
│   │   ├── cert_fetcher.py  # TLS handshake auto-fetch from hostname
│   │   ├── notifier.py      # Email + Teams Adaptive Card alerts
│   │   └── scheduler.py     # Daily 08:00 expiry check background job
│   └── templates/           # Bootstrap 5 Jinja2 templates
├── data/                    # SQLite database (Docker volume)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Pages

| Route | Description |
|---|---|
| `/` | Dashboard — certificate list with status badges |
| `/certs/add` | Manual certificate entry form |
| `/certs/upload` | Upload a certificate file |
| `/certs/fetch` | Auto-fetch certificate from a hostname via TLS |
| `/certs/<id>` | Certificate detail view with alert history |
| `/settings` | Notification, threshold, and API key configuration (admin) |
| `/users` | User management (admin) |

---

## REST API

The REST API allows other teams and tools to query and manage certificates programmatically.

### Authentication

All API endpoints (except `/api/v1/health`) require an `X-API-Key` header.

Find or regenerate the API key at **Settings > REST API Key** (admin only).

```bash
curl -H "X-API-Key: <your-key>" http://localhost:5000/api/v1/certs
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check (no auth required) |
| `GET` | `/api/v1/certs` | List / query certificates |
| `GET` | `/api/v1/certs/<id>` | Get a single certificate |
| `POST` | `/api/v1/certs` | Add a single certificate |
| `POST` | `/api/v1/certs/bulk` | Bulk-add up to 500 certificates |
| `POST` | `/api/v1/certs/fetch` | Fetch from a live hostname and save |
| `DELETE` | `/api/v1/certs/<id>` | Delete a certificate |

---

### Query certificates

```
GET /api/v1/certs
```

Optional query parameters:

| Parameter | Description |
|---|---|
| `status` | Filter by `ok`, `warning`, `critical`, or `expired` |
| `tag` | Filter by tag substring |
| `search` | Search common_name, hostname, notes |
| `page` | Page number (default `1`) |
| `per_page` | Results per page (default `50`, max `200`) |

**Example — list expiring certs:**
```bash
curl -H "X-API-Key: <key>" \
  "http://localhost:5000/api/v1/certs?status=critical&per_page=100"
```

**Response:**
```json
{
  "total": 2,
  "page": 1,
  "per_page": 100,
  "certs": [
    {
      "id": 5,
      "common_name": "api.example.com",
      "not_after": "2025-04-10T00:00:00",
      "days_remaining": 12,
      "status": "critical",
      "hostname": "api.example.com",
      "sans": ["DNS:api.example.com"],
      "tags": "prod,api",
      ...
    }
  ]
}
```

---

### Add a single certificate

```
POST /api/v1/certs
Content-Type: application/json
```

**Required fields:** `common_name`, `not_after`

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/certs \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "example.com",
    "not_after": "2026-01-01T00:00:00Z",
    "not_before": "2025-01-01T00:00:00Z",
    "issuer": "CN=My CA",
    "hostname": "webserver01",
    "tags": "prod,web",
    "sans": ["DNS:example.com", "DNS:www.example.com"]
  }'
```

Returns `201 Created` with the certificate JSON.

---

### Bulk-add certificates

```
POST /api/v1/certs/bulk
Content-Type: application/json
```

Send a JSON array of certificate objects (same fields as single add). Up to 500 per request.

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/certs/bulk \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '[
    {"common_name": "a.example.com", "not_after": "2026-03-01T00:00:00Z"},
    {"common_name": "b.example.com", "not_after": "2026-06-01T00:00:00Z"}
  ]'
```

**Response** (`201` if all succeeded, `207` if partial errors):
```json
{
  "created": 2,
  "errors": 0,
  "ids": [12, 13],
  "error_details": []
}
```

---

### Fetch certificate from a hostname

```
POST /api/v1/certs/fetch
Content-Type: application/json
```

Connects to the given hostname over TLS, retrieves the certificate, and saves it.

| Field | Type | Description |
|---|---|---|
| `hostname` | string (required) | Domain or `host:port` |
| `port` | integer | Override port (default `443`) |
| `save` | boolean | `false` to preview without saving (default `true`) |
| `tags` | string | Tags to apply to the saved cert |
| `notes` | string | Notes to apply to the saved cert |

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/certs/fetch \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "example.com", "tags": "prod,auto-fetched"}'
```

Returns `201 Created` with the saved certificate, or the fetched data preview if `save=false`.

---

### Delete a certificate

```
DELETE /api/v1/certs/<id>
```

```bash
curl -X DELETE http://localhost:5000/api/v1/certs/5 \
  -H "X-API-Key: <key>"
```

Returns `200` with `{"deleted": 5}`.

---

## Alerts

The scheduler runs daily at **08:00** and sends alerts when a certificate crosses a configured threshold (e.g. 90, 60, 30, 14, 7 days). Each alert fires **once per threshold** to avoid repeated notifications.

Teams alerts use Adaptive Cards with colour-coded severity.

---

## Docker

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down

# Data is persisted in a named Docker volume: certmanager_data
```
