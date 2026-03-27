import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .cert_parser import _extract_cert_data


def fetch_cert_from_host(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    hostname = hostname.strip().lower()
    # Strip protocol if provided
    if "://" in hostname:
        hostname = hostname.split("://", 1)[1]
    # Strip path
    hostname = hostname.split("/")[0]
    # Strip port from hostname if included
    if ":" in hostname:
        hostname, port_str = hostname.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            pass

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    return _extract_cert_data(cert)
