# Tests

This directory contains the pytest test suite for webcertapp. Tests cover
models, services, and all HTTP routes using an in-memory SQLite database —
no running server or external services required.

---

## Structure

```
tests/
├── conftest.py                  # Shared fixtures (app, DB, users, certs, PEM factory)
├── test_models.py               # Certificate status logic, User auth, Settings, AlertLog
├── test_cert_parser.py          # PEM/DER/P7B parsing, field extraction
├── test_cert_fetcher.py         # TLS hostname fetching (mocked sockets)
├── test_notifier.py             # Email and Teams alert sending (mocked SMTP/HTTP)
├── test_routes_auth.py          # Login, logout, user management routes
├── test_routes_certs.py         # Dashboard, add, edit, delete, upload, fetch routes
├── test_routes_settings.py      # Settings save, test email, test Teams routes
└── test_routes_api.py           # REST API — auth, query, add, bulk, fetch, delete
```

---

## Setup

Install dev dependencies (separate from the app's runtime requirements):

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run with verbose output
```bash
pytest tests/ -v
```

### Run a specific file
```bash
pytest tests/test_models.py -v
```

### Run a specific test class or test
```bash
pytest tests/test_models.py::TestCertificateStatus -v
pytest tests/test_models.py::TestCertificateStatus::test_expired_status -v
```

### Run with short traceback on failure
```bash
pytest tests/ --tb=short
```

### Run and show coverage
```bash
pytest tests/ --cov=app --cov-report=term-missing
```

---

## Linting

```bash
ruff check app/ tests/
```

To auto-fix lint issues:
```bash
ruff check app/ tests/ --fix
```

---

## What Each Test File Covers

### `test_models.py`
- `Certificate.status` — ok / warning / critical / expired thresholds
- `Certificate.days_remaining` — positive and negative values
- `Certificate.sans` — JSON serialisation roundtrip
- `User.check_password` — correct and incorrect passwords
- `User.is_admin` — role check
- `Settings.get()` — singleton creation and defaults
- `AlertLog` — creation and certificate relationship

### `test_cert_parser.py`
- `parse_cert_pem` — extracts CN, SANs, serial, thumbprint, validity dates
- `parse_cert_der` — DER format support
- `parse_cert_file` — auto-detects PEM vs DER, handles `.pem`, `.crt`, `.cer`, `.der`
- Error cases — invalid data raises `ValueError`

### `test_cert_fetcher.py`
- `fetch_cert_from_host` — mocked TLS socket, returns parsed cert data
- URL normalisation — strips `https://`, paths, and embedded port numbers
- Custom port handling
- Connection errors propagate correctly

### `test_notifier.py`
- `send_expiry_email` — sends when enabled, skips when disabled/unconfigured
- STARTTLS vs SMTP_SSL selection
- Subject line contains certificate common name
- `send_expiry_teams` — posts Adaptive Card to webhook
- Both functions skip gracefully when not configured
- `send_test_email` / `send_test_teams` — raises on missing config

### `test_routes_auth.py`
- Login page loads, valid login redirects, invalid credentials rejected
- Unauthenticated access redirects to `/login`
- Logout clears session
- User management (add/delete) admin-only enforcement

### `test_routes_certs.py`
- Dashboard loads and shows certificates
- Certificate detail page — shows all fields, 404 on missing
- Manual add — creates cert, validates required fields
- Edit — updates cert, resets alert sent days
- Delete — removes cert
- Upload — accepts valid PEM, rejects missing/invalid files
- Fetch — displays result with mocked socket, shows error on failure

### `test_routes_settings.py`
- Settings page admin-only
- Save alert days, email config, Teams config
- Password not overwritten when left blank on re-save
- Test email / Teams endpoints — success and failure paths
- Non-admin users receive 403 on test endpoints
- API key displayed, regenerate rotates it

### `test_routes_api.py`
- `GET /api/v1/health` — returns 200 without authentication
- `GET /api/v1/certs` — requires valid `X-API-Key`, returns paginated list
- Filtering by `status`, `tag`, and `search` query parameters
- `GET /api/v1/certs/<id>` — returns certificate JSON, 404 on missing
- `POST /api/v1/certs` — creates a certificate, validates required fields
- `POST /api/v1/certs/bulk` — creates multiple certs, partial-error `207` response
- `POST /api/v1/certs/fetch` — mocked TLS fetch, saves and returns cert; `save=false` preview
- `DELETE /api/v1/certs/<id>` — removes cert, returns deleted ID
- Missing/invalid API key returns `401`

---

## CI / Scheduled Runs

Tests run automatically via GitHub Actions:

| Trigger | When |
|---|---|
| Push to `main` / `master` | On every commit |
| Pull request | Before merge |
| Scheduled | Every Monday at 08:00 UTC |
| Manual | Via GitHub Actions → Run workflow |

Test results are uploaded as artifacts for each run and can be downloaded
from the Actions tab in GitHub.
