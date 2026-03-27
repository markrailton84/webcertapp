# CertManager

A team certificate management web app built with Python/Flask. Track TLS/SSL certificates across your systems, get notified before they expire via Email and Microsoft Teams.

## Features

- **Dashboard** — view all certificates with expiry status (OK, Warning, Critical, Expired)
- **3 ways to add certificates** — manual entry, file upload, or auto-fetch from a hostname
- **Supported file formats** — `.pem`, `.crt`, `.cer`, `.der`, `.p7b`
- **Notifications** — Email (SMTP) and Microsoft Teams (Adaptive Cards) alerts
- **Configurable thresholds** — alert at 90, 60, 30, 14, 7 days (or any custom values)
- **Multi-user** — admin and user roles, managed via the UI
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
│   │   ├── auth.py          # Login, logout, user management
│   │   ├── certs.py         # Dashboard, add/edit/delete, upload, fetch
│   │   └── settings.py      # SMTP + Teams config, test buttons
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
| `/settings` | Notification and threshold configuration (admin) |
| `/users` | User management (admin) |

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
