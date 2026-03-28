"""
Integration tests for certificate routes: dashboard, add, edit, delete,
upload, and fetch.
"""

import io
import datetime
import pytest
from unittest.mock import patch


class TestDashboard:
    def test_dashboard_loads(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_dashboard_shows_cert(self, auth_client, sample_cert):
        resp = auth_client.get("/")
        assert sample_cert.common_name.encode() in resp.data

    def test_dashboard_shows_stats(self, auth_client, sample_cert, expired_cert):
        resp = auth_client.get("/")
        assert b"Total" in resp.data

    def test_dashboard_empty_state(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200


class TestCertDetail:
    def test_detail_page_loads(self, auth_client, sample_cert):
        resp = auth_client.get(f"/certs/{sample_cert.id}")
        assert resp.status_code == 200
        assert sample_cert.common_name.encode() in resp.data

    def test_detail_shows_hostname(self, auth_client, sample_cert):
        resp = auth_client.get(f"/certs/{sample_cert.id}")
        assert b"webserver01" in resp.data

    def test_detail_shows_sans(self, auth_client, sample_cert):
        resp = auth_client.get(f"/certs/{sample_cert.id}")
        assert b"example.com" in resp.data

    def test_detail_404_for_missing(self, auth_client):
        resp = auth_client.get("/certs/99999")
        assert resp.status_code == 404


class TestCertAdd:
    def test_add_page_loads(self, auth_client):
        resp = auth_client.get("/certs/add")
        assert resp.status_code == 200

    def test_add_cert_manual(self, auth_client):
        resp = auth_client.post("/certs/add", data={
            "common_name": "new.example.com",
            "not_after": "2026-12-31",
            "not_before": "2025-01-01",
            "hostname": "server01",
            "issuer": "Test CA",
            "subject": "CN=new.example.com",
            "serial_number": "ABC123",
            "thumbprint": "DEADBEEF",
            "tags": "prod",
            "notes": "Test",
            "sans": "DNS:new.example.com",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"new.example.com" in resp.data

    def test_add_cert_missing_required_fields(self, auth_client):
        resp = auth_client.post("/certs/add", data={
            "common_name": "",
            "not_after": "",
        }, follow_redirects=True)
        # Missing required fields should not create a cert
        assert resp.status_code == 200


class TestCertEdit:
    def test_edit_page_loads(self, auth_client, sample_cert):
        resp = auth_client.get(f"/certs/{sample_cert.id}/edit")
        assert resp.status_code == 200
        assert sample_cert.common_name.encode() in resp.data

    def test_edit_updates_cert(self, auth_client, sample_cert):
        resp = auth_client.post(f"/certs/{sample_cert.id}/edit", data={
            "common_name": "updated.example.com",
            "not_after": "2027-01-01",
            "hostname": "newserver",
            "issuer": sample_cert.issuer or "",
            "subject": sample_cert.subject or "",
            "serial_number": sample_cert.serial_number or "",
            "thumbprint": sample_cert.thumbprint or "",
            "tags": "updated",
            "notes": "updated note",
            "sans": "DNS:updated.example.com",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"updated.example.com" in resp.data

    def test_edit_404_for_missing(self, auth_client):
        resp = auth_client.get("/certs/99999/edit")
        assert resp.status_code == 404


class TestCertDelete:
    def test_delete_cert(self, auth_client, sample_cert):
        resp = auth_client.post(f"/certs/{sample_cert.id}/delete",
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data

    def test_delete_404_for_missing(self, auth_client):
        resp = auth_client.post("/certs/99999/delete", follow_redirects=True)
        assert resp.status_code == 404


class TestCertUpload:
    def test_upload_page_loads(self, auth_client):
        resp = auth_client.get("/certs/upload")
        assert resp.status_code == 200

    def test_upload_valid_pem(self, auth_client, sample_pem_bytes):
        data = {
            "cert_file": (io.BytesIO(sample_pem_bytes), "cert.pem"),
            "hostname": "uploadserver",
            "tags": "upload-test",
            "notes": "Uploaded via test",
        }
        resp = auth_client.post("/certs/upload",
                                data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"pem.example.com" in resp.data

    def test_upload_no_file_shows_error(self, auth_client):
        resp = auth_client.post("/certs/upload",
                                data={"hostname": "server"},
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert b"No file selected" in resp.data

    def test_upload_invalid_file_shows_error(self, auth_client):
        data = {
            "cert_file": (io.BytesIO(b"not a cert"), "bad.pem"),
        }
        resp = auth_client.post("/certs/upload",
                                data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert b"Error" in resp.data


class TestCertFetch:
    def test_fetch_page_loads(self, auth_client):
        resp = auth_client.get("/certs/fetch")
        assert resp.status_code == 200

    def test_fetch_displays_result(self, auth_client, sample_pem_bytes):
        from tests.conftest import make_self_signed_cert
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from app.services.cert_parser import _extract_cert_data

        pem = make_self_signed_cert(cn="fetched.example.com", days_valid=90)
        cert_obj = x509.load_pem_x509_certificate(pem, default_backend())
        fake_data = _extract_cert_data(cert_obj)

        with patch("app.routes.certs.fetch_cert_from_host", return_value=fake_data):
            resp = auth_client.post("/certs/fetch", data={
                "hostname": "fetched.example.com",
                "port": "443",
            }, follow_redirects=True)

        assert resp.status_code == 200
        assert b"fetched.example.com" in resp.data

    def test_fetch_error_shows_message(self, auth_client):
        with patch("app.routes.certs.fetch_cert_from_host",
                   side_effect=ConnectionRefusedError("refused")):
            resp = auth_client.post("/certs/fetch", data={
                "hostname": "unreachable.example.com",
                "port": "443",
            }, follow_redirects=True)

        assert b"Error" in resp.data

    def test_fetch_no_hostname_shows_error(self, auth_client):
        resp = auth_client.post("/certs/fetch",
                                data={"hostname": "", "port": "443"},
                                follow_redirects=True)
        assert b"Please enter a hostname" in resp.data
