"""
Tests for app/services/cert_fetcher.py

Uses unittest.mock to patch socket connections so no real network
calls are made during testing.
"""

import datetime
import pytest
from unittest.mock import patch, MagicMock

from app.services.cert_fetcher import fetch_cert_from_host
from tests.conftest import make_self_signed_cert


def _pem_to_der(pem_bytes: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def _make_mock_socket(der_bytes: bytes):
    """Build a mock SSL socket that returns the given DER cert."""
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = der_bytes
    mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
    mock_ssock.__exit__ = MagicMock(return_value=False)

    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    return mock_sock, mock_ssock


@pytest.fixture(scope="module")
def der_bytes():
    pem = make_self_signed_cert(cn="fetch.example.com", days_valid=90)
    return _pem_to_der(pem)


class TestFetchCertFromHost:
    def _patch_socket(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        return (
            patch("app.services.cert_fetcher.socket.create_connection", return_value=mock_sock),
            patch("app.services.cert_fetcher.ssl.SSLContext.wrap_socket", return_value=mock_ssock),
        )

    def test_returns_dict(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        with patch("app.services.cert_fetcher.socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            result = fetch_cert_from_host("fetch.example.com")
        assert isinstance(result, dict)
        assert result["common_name"] == "fetch.example.com"

    def test_strips_https_prefix(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        with patch("app.services.cert_fetcher.socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            result = fetch_cert_from_host("https://fetch.example.com")
        assert result["common_name"] == "fetch.example.com"

    def test_strips_path(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        with patch("app.services.cert_fetcher.socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            result = fetch_cert_from_host("https://fetch.example.com/some/path")
        assert result["common_name"] == "fetch.example.com"

    def test_uses_custom_port(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        captured = {}

        def fake_connect(address, timeout):
            captured["address"] = address
            return mock_sock

        with patch("app.services.cert_fetcher.socket.create_connection", side_effect=fake_connect), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            fetch_cert_from_host("fetch.example.com", port=8443)

        assert captured["address"][1] == 8443

    def test_port_in_hostname_parsed(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        captured = {}

        def fake_connect(address, timeout):
            captured["address"] = address
            return mock_sock

        with patch("app.services.cert_fetcher.socket.create_connection", side_effect=fake_connect), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            fetch_cert_from_host("fetch.example.com:9443")

        assert captured["address"][1] == 9443

    def test_not_after_in_future(self, der_bytes):
        mock_sock, mock_ssock = _make_mock_socket(der_bytes)
        with patch("app.services.cert_fetcher.socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            result = fetch_cert_from_host("fetch.example.com")
        assert result["not_after"] > datetime.datetime.now(datetime.timezone.utc)

    def test_connection_error_propagates(self):
        with patch("app.services.cert_fetcher.socket.create_connection",
                   side_effect=ConnectionRefusedError("refused")):
            with pytest.raises(ConnectionRefusedError):
                fetch_cert_from_host("unreachable.example.com")
