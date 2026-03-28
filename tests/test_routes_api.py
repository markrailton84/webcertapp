"""Tests for the REST API blueprint — /api/v1/."""

import datetime
import json
from unittest.mock import patch

import pytest

from app.models import Certificate, Settings, db as _db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_key(app):
    with app.app_context():
        return Settings.get().api_key


def _headers(app):
    return {"X-API-Key": _api_key(app)}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_no_auth(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestApiKeyAuth:
    def test_missing_key_returns_401(self, client):
        resp = client.get("/api/v1/certs")
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, client):
        resp = client.get("/api/v1/certs", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == 401

    def test_valid_key_returns_200(self, client, app, db):
        resp = client.get("/api/v1/certs", headers=_headers(app))
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/v1/certs
# ---------------------------------------------------------------------------

class TestListCerts:
    def test_empty_list(self, client, app, db):
        resp = client.get("/api/v1/certs", headers=_headers(app))
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["total"] == 0
        assert data["certs"] == []

    def test_returns_cert(self, client, app, db, sample_cert):
        resp = client.get("/api/v1/certs", headers=_headers(app))
        data = resp.get_json()
        assert data["total"] == 1
        assert data["certs"][0]["common_name"] == "example.com"

    def test_filter_by_status(self, client, app, db, sample_cert, expired_cert):
        resp = client.get("/api/v1/certs?status=expired", headers=_headers(app))
        data = resp.get_json()
        assert all(c["status"] == "expired" for c in data["certs"])

    def test_filter_by_tag(self, client, app, db, sample_cert):
        resp = client.get("/api/v1/certs?tag=prod", headers=_headers(app))
        data = resp.get_json()
        assert data["total"] >= 1

    def test_search(self, client, app, db, sample_cert):
        resp = client.get("/api/v1/certs?search=example.com", headers=_headers(app))
        data = resp.get_json()
        assert data["total"] >= 1

    def test_pagination(self, client, app, db, admin_user):
        now = datetime.datetime.now(datetime.timezone.utc)
        for i in range(5):
            c = Certificate(
                common_name=f"page{i}.example.com",
                not_after=now + datetime.timedelta(days=365),
                source="manual",
                added_by_id=admin_user.id,
            )
            _db.session.add(c)
        _db.session.commit()

        resp = client.get("/api/v1/certs?per_page=2&page=1", headers=_headers(app))
        data = resp.get_json()
        assert len(data["certs"]) == 2
        assert data["per_page"] == 2

    def test_cert_fields_present(self, client, app, db, sample_cert):
        resp = client.get("/api/v1/certs", headers=_headers(app))
        cert = resp.get_json()["certs"][0]
        for field in ("id", "common_name", "not_after", "days_remaining", "status", "sans"):
            assert field in cert


# ---------------------------------------------------------------------------
# GET /api/v1/certs/<id>
# ---------------------------------------------------------------------------

class TestGetCert:
    def test_get_existing_cert(self, client, app, db, sample_cert):
        resp = client.get(f"/api/v1/certs/{sample_cert.id}", headers=_headers(app))
        assert resp.status_code == 200
        assert resp.get_json()["common_name"] == "example.com"

    def test_get_missing_cert_returns_404(self, client, app, db):
        resp = client.get("/api/v1/certs/99999", headers=_headers(app))
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/certs
# ---------------------------------------------------------------------------

class TestAddCert:
    def test_add_cert(self, client, app, db):
        resp = client.post(
            "/api/v1/certs",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({
                "common_name": "new.example.com",
                "not_after": "2027-01-01T00:00:00Z",
                "tags": "test",
                "sans": ["DNS:new.example.com"],
            }),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["common_name"] == "new.example.com"
        assert data["id"] is not None

    def test_add_cert_missing_common_name(self, client, app, db):
        resp = client.post(
            "/api/v1/certs",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({"not_after": "2027-01-01T00:00:00Z"}),
        )
        assert resp.status_code == 422

    def test_add_cert_missing_not_after(self, client, app, db):
        resp = client.post(
            "/api/v1/certs",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({"common_name": "missing.example.com"}),
        )
        assert resp.status_code == 422

    def test_add_cert_invalid_date(self, client, app, db):
        resp = client.post(
            "/api/v1/certs",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({
                "common_name": "bad.example.com",
                "not_after": "not-a-date",
            }),
        )
        assert resp.status_code == 422

    def test_add_cert_non_json_body(self, client, app, db):
        resp = client.post(
            "/api/v1/certs",
            headers={**_headers(app), "Content-Type": "application/json"},
            data="not json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/v1/certs/bulk
# ---------------------------------------------------------------------------

class TestBulkAddCerts:
    def test_bulk_add_success(self, client, app, db):
        payload = [
            {"common_name": f"bulk{i}.example.com", "not_after": "2027-01-01T00:00:00Z"}
            for i in range(3)
        ]
        resp = client.post(
            "/api/v1/certs/bulk",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps(payload),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["created"] == 3
        assert data["errors"] == 0
        assert len(data["ids"]) == 3

    def test_bulk_partial_errors_returns_207(self, client, app, db):
        payload = [
            {"common_name": "good.example.com", "not_after": "2027-01-01T00:00:00Z"},
            {"common_name": "bad.example.com"},  # missing not_after
        ]
        resp = client.post(
            "/api/v1/certs/bulk",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps(payload),
        )
        assert resp.status_code == 207
        data = resp.get_json()
        assert data["created"] == 1
        assert data["errors"] == 1

    def test_bulk_empty_array(self, client, app, db):
        resp = client.post(
            "/api/v1/certs/bulk",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps([]),
        )
        assert resp.status_code == 400

    def test_bulk_not_array(self, client, app, db):
        resp = client.post(
            "/api/v1/certs/bulk",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({"common_name": "x"}),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/v1/certs/fetch
# ---------------------------------------------------------------------------

class TestFetchCert:
    def _mock_cert_data(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            "common_name": "fetched.example.com",
            "issuer": "CN=Test CA",
            "subject": "CN=fetched.example.com",
            "serial_number": "AABB",
            "thumbprint": "DEADBEEF",
            "not_before": now,
            "not_after": now + datetime.timedelta(days=365),
            "sans": ["DNS:fetched.example.com"],
        }

    def test_fetch_and_save(self, client, app, db):
        with patch("app.routes.api.fetch_cert_from_host", return_value=self._mock_cert_data()):
            resp = client.post(
                "/api/v1/certs/fetch",
                headers={**_headers(app), "Content-Type": "application/json"},
                data=json.dumps({"hostname": "fetched.example.com"}),
            )
        assert resp.status_code == 201
        assert resp.get_json()["common_name"] == "fetched.example.com"

    def test_fetch_preview_no_save(self, client, app, db):
        with patch("app.routes.api.fetch_cert_from_host", return_value=self._mock_cert_data()):
            resp = client.post(
                "/api/v1/certs/fetch",
                headers={**_headers(app), "Content-Type": "application/json"},
                data=json.dumps({"hostname": "fetched.example.com", "save": False}),
            )
        assert resp.status_code == 200
        assert "fetched" in resp.get_json()

    def test_fetch_missing_hostname(self, client, app, db):
        resp = client.post(
            "/api/v1/certs/fetch",
            headers={**_headers(app), "Content-Type": "application/json"},
            data=json.dumps({}),
        )
        assert resp.status_code == 400

    def test_fetch_connection_error_returns_502(self, client, app, db):
        with patch("app.routes.api.fetch_cert_from_host", side_effect=ConnectionError("refused")):
            resp = client.post(
                "/api/v1/certs/fetch",
                headers={**_headers(app), "Content-Type": "application/json"},
                data=json.dumps({"hostname": "bad.host.example.com"}),
            )
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# DELETE /api/v1/certs/<id>
# ---------------------------------------------------------------------------

class TestDeleteCert:
    def test_delete_cert(self, client, app, db, sample_cert):
        cert_id = sample_cert.id
        resp = client.delete(f"/api/v1/certs/{cert_id}", headers=_headers(app))
        assert resp.status_code == 200
        assert resp.get_json()["deleted"] == cert_id

        # Confirm it's gone
        resp2 = client.get(f"/api/v1/certs/{cert_id}", headers=_headers(app))
        assert resp2.status_code == 404

    def test_delete_missing_cert(self, client, app, db):
        resp = client.delete("/api/v1/certs/99999", headers=_headers(app))
        assert resp.status_code == 404
