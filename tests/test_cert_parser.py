"""
Tests for app/services/cert_parser.py

Covers PEM parsing, DER parsing, field extraction (CN, SANs, serial,
thumbprint, validity dates), and error handling for invalid input.
"""

import io
import datetime
import pytest
from unittest.mock import MagicMock

from app.services.cert_parser import parse_cert_pem, parse_cert_der, parse_cert_file
from tests.conftest import make_self_signed_cert


class TestParseCertPem:
    def test_returns_dict(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert isinstance(result, dict)

    def test_common_name_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["common_name"] == "pem.example.com"

    def test_sans_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert "DNS:pem.example.com" in result["sans"]
        assert "DNS:www.pem.example.com" in result["sans"]

    def test_not_after_is_datetime(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert isinstance(result["not_after"], datetime.datetime)

    def test_not_before_is_datetime(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert isinstance(result["not_before"], datetime.datetime)

    def test_not_after_in_future(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["not_after"] > datetime.datetime.now(datetime.timezone.utc)

    def test_serial_number_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["serial_number"]
        assert len(result["serial_number"]) > 0

    def test_thumbprint_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["thumbprint"]
        assert len(result["thumbprint"]) == 64  # SHA256 hex = 64 chars

    def test_thumbprint_uppercase(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["thumbprint"] == result["thumbprint"].upper()

    def test_issuer_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["issuer"]

    def test_subject_extracted(self, sample_pem_bytes):
        result = parse_cert_pem(sample_pem_bytes)
        assert result["subject"]

    def test_expiring_cert_has_short_validity(self, expiring_pem_bytes):
        result = parse_cert_pem(expiring_pem_bytes)
        now = datetime.datetime.now(datetime.timezone.utc)
        days = (result["not_after"] - now).days
        assert days <= 10

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            parse_cert_pem(b"not a certificate")


class TestParseCertDer:
    def test_parses_der_bytes(self, sample_pem_bytes):
        # Convert PEM to DER for testing
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_pem_x509_certificate(sample_pem_bytes, default_backend())
        from cryptography.hazmat.primitives import serialization
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        result = parse_cert_der(der_bytes)
        assert result["common_name"] == "pem.example.com"

    def test_invalid_der_raises(self):
        with pytest.raises(Exception):
            parse_cert_der(b"\x00\x01\x02\x03")


class TestParseCertFile:
    def test_pem_file_detected(self, sample_pem_bytes):
        mock_file = MagicMock()
        mock_file.read.return_value = sample_pem_bytes
        mock_file.filename = "cert.pem"
        result = parse_cert_file(mock_file)
        assert result["common_name"] == "pem.example.com"

    def test_crt_extension_works(self, sample_pem_bytes):
        mock_file = MagicMock()
        mock_file.read.return_value = sample_pem_bytes
        mock_file.filename = "cert.crt"
        result = parse_cert_file(mock_file)
        assert result["common_name"] == "pem.example.com"

    def test_der_file_detected(self, sample_pem_bytes):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_pem_x509_certificate(sample_pem_bytes, default_backend())
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_file = MagicMock()
        mock_file.read.return_value = der_bytes
        mock_file.filename = "cert.der"
        result = parse_cert_file(mock_file)
        assert result["common_name"] == "pem.example.com"

    def test_invalid_file_raises_value_error(self):
        mock_file = MagicMock()
        mock_file.read.return_value = b"garbage data that is not a cert"
        mock_file.filename = "cert.cer"
        with pytest.raises(ValueError, match="Unable to parse"):
            parse_cert_file(mock_file)

    def test_multiple_certs_uses_first(self):
        pem1 = make_self_signed_cert(cn="first.example.com")
        pem2 = make_self_signed_cert(cn="second.example.com")
        combined = pem1 + pem2

        mock_file = MagicMock()
        mock_file.read.return_value = combined
        mock_file.filename = "chain.pem"
        result = parse_cert_file(mock_file)
        assert result["common_name"] == "first.example.com"
