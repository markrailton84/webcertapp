import hashlib
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID


def _extract_cert_data(cert: x509.Certificate) -> dict:
    cn = ""
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        cn = cert.subject.rfc4514_string()

    issuer = ""
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        pass

    subject = ""
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        pass

    serial = format(cert.serial_number, "x").upper()

    thumbprint = hashlib.sha256(cert.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
    )).hexdigest().upper()

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                sans.append(f"EMAIL:{name.value}")
    except x509.ExtensionNotFound:
        pass

    return {
        "common_name": cn,
        "issuer": issuer,
        "subject": subject,
        "serial_number": serial,
        "thumbprint": thumbprint,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
    }


def parse_cert_pem(pem_data: bytes) -> dict:
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return _extract_cert_data(cert)


def parse_cert_der(der_data: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    return _extract_cert_data(cert)


def parse_cert_file(file_storage) -> dict:
    data = file_storage.read()
    filename = file_storage.filename.lower()

    # Try PEM first
    if b"-----BEGIN" in data:
        return parse_cert_pem(data)

    # Try DER
    try:
        return parse_cert_der(data)
    except Exception:
        pass

    # Try P7B (PKCS#7) - extract first cert
    if filename.endswith(".p7b") or filename.endswith(".p7c"):
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = pkcs7.load_der_pkcs7_certificates(data)
        if not certs:
            # Try PEM encoded P7B
            certs = pkcs7.load_pem_pkcs7_certificates(data)
        if certs:
            return _extract_cert_data(certs[0])

    raise ValueError("Unable to parse certificate file. Supported formats: PEM, DER, CRT, CER, P7B.")
