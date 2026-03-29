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
├── test_routes_api.py           # REST API — auth, query, add, bulk, fetch, delete
└── test_routes_teams.py         # Team management, member permissions, notifications
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
- `Certificate.team_id` — team assignment
- `User.check_password` — correct and incorrect passwords
- `User.is_admin` — role check
- `Settings.get()` — singleton creation and defaults
- `Team` — creation, `is_owner()`, `get_member()`, alert_days/email_recipients properties
- `TeamMember` — permission flags (can_view, can_add, can_edit, can_delete)
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
### `test_routes_teams.py`
- Team list and create (admin only)
- Team detail accessible to owner and admin, blocked for others
- Team deletion (admin only)
- Add/edit/remove members with permission flags
- Team notification settings save (alert days, SMTP, Teams webhook)
- Per-team API key — auto-generated, regenerate rotates it, non-owner denied
- Certificates visible in team detail view
- Non-owner access returns redirect with flash message

### `test_routes_api.py`
- `GET /api/v1/health` — returns 200 without authentication
- `GET /api/v1/certs` — per-team API key scopes results to team's certificates
- Filtering by `status`, `tag`, and `search` query parameters
- `GET /api/v1/certs/<id>` — returns certificate JSON, 403 if cert belongs to another team
- `POST /api/v1/certs` — creates a certificate assigned to the API key's team
- `POST /api/v1/certs/bulk` — creates multiple certs for the team, partial-error `207` response
- `POST /api/v1/certs/fetch` — mocked TLS fetch, saves cert to the team; `save=false` preview
- `DELETE /api/v1/certs/<id>` — removes cert, 403 if cert belongs to another team
- Missing/invalid API key returns `401`

---

## Running Locally

Tests use an in-memory SQLite database — no Docker, server, or external services required.
Run the full suite with:

```bash
pytest tests/ -v
```
