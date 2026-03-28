"""
Shared pytest fixtures for webcertapp tests.

Provides:
  - app / client / db  — in-memory Flask test environment
  - admin_user / regular_user — pre-created user records
  - auth_client / user_client — logged-in test clients
  - sample_cert — a Certificate row in the DB
  - sample_pem_bytes — a self-signed PEM cert generated at test time
"""

import datetime
import io
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import create_app
from app.models import db as _db, User, Certificate, Settings


# ---------------------------------------------------------------------------
# Self-signed certificate factory (used across parser / upload tests)
# ---------------------------------------------------------------------------

def make_self_signed_cert(
    cn: str = "test.example.com",
    days_valid: int = 365,
    sans: list[str] | None = None,
) -> bytes:
    """Generate a self-signed PEM certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )

    san_list = [x509.DNSName(cn)]
    for s in (sans or []):
        san_list.append(x509.DNSName(s))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_list), critical=False
    )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# App / DB fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app():
    """Create a Flask app configured for testing with an in-memory SQLite DB."""
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret",
        "LOGIN_DISABLED": False,
    })

    with test_app.app_context():
        _db.create_all()
        yield test_app
        _db.drop_all()


@pytest.fixture(scope="function")
def db(app):
    """Provide a clean DB for each test (rolls back after each test)."""
    with app.app_context():
        yield _db
        _db.session.rollback()
        # Clean tables between tests
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()


@pytest.fixture(scope="function")
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# User fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def admin_user(db):
    user = User(username="admin", email="admin@test.com", role="admin")
    user.set_password("adminpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def regular_user(db):
    user = User(username="user1", email="user1@test.com", role="user")
    user.set_password("userpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def auth_client(client, admin_user):
    """Test client logged in as admin."""
    client.post("/login", data={"username": "admin", "password": "adminpass"})
    return client


@pytest.fixture(scope="function")
def user_client(client, regular_user):
    """Test client logged in as a regular user."""
    client.post("/login", data={"username": "user1", "password": "userpass"})
    return client


# ---------------------------------------------------------------------------
# Certificate fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def sample_cert(db, admin_user):
    """A Certificate row in the DB, valid for 365 days."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = Certificate(
        common_name="example.com",
        issuer="CN=Test CA",
        subject="CN=example.com",
        serial_number="AABBCC",
        thumbprint="DEADBEEF",
        not_before=now,
        not_after=now + datetime.timedelta(days=365),
        hostname="webserver01",
        notes="Test cert",
        tags="prod,web",
        source="manual",
        added_by_id=admin_user.id,
    )
    cert.sans = ["DNS:example.com", "DNS:www.example.com"]
    db.session.add(cert)
    db.session.commit()
    return cert


@pytest.fixture(scope="function")
def expiring_cert(db, admin_user):
    """A Certificate expiring in 10 days (critical status)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = Certificate(
        common_name="expiring.example.com",
        not_after=now + datetime.timedelta(days=10),
        source="manual",
        added_by_id=admin_user.id,
    )
    db.session.add(cert)
    db.session.commit()
    return cert


@pytest.fixture(scope="function")
def expired_cert(db, admin_user):
    """A Certificate that expired yesterday."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = Certificate(
        common_name="expired.example.com",
        not_after=now - datetime.timedelta(days=1),
        source="manual",
        added_by_id=admin_user.id,
    )
    db.session.add(cert)
    db.session.commit()
    return cert


# ---------------------------------------------------------------------------
# PEM bytes fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sample_pem_bytes():
    """A self-signed PEM cert valid for 365 days."""
    return make_self_signed_cert(
        cn="pem.example.com",
        days_valid=365,
        sans=["www.pem.example.com"],
    )


@pytest.fixture(scope="session")
def expiring_pem_bytes():
    """A self-signed PEM cert valid for only 10 days."""
    return make_self_signed_cert(cn="expiring.pem.example.com", days_valid=10)


@pytest.fixture(scope="function")
def pem_file(sample_pem_bytes):
    """A FileStorage-like object wrapping PEM bytes, for upload tests."""
    return io.BytesIO(sample_pem_bytes)
