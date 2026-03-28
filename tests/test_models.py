"""
Tests for SQLAlchemy models — Certificate status logic, User auth,
Settings defaults, and AlertLog relationships.
"""

import datetime
import pytest
from app.models import Certificate, User, Settings, AlertLog


class TestCertificateStatus:
    def test_ok_status(self, sample_cert):
        assert sample_cert.status == "ok"
        assert sample_cert.status_badge == "success"

    def test_warning_status(self, db, admin_user):
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = Certificate(
            common_name="warn.example.com",
            not_after=now + datetime.timedelta(days=60),
            source="manual",
            added_by_id=admin_user.id,
        )
        db.session.add(cert)
        db.session.commit()
        assert cert.status == "warning"
        assert cert.status_badge == "warning"

    def test_critical_status(self, expiring_cert):
        assert expiring_cert.status == "critical"
        assert expiring_cert.status_badge == "danger"

    def test_expired_status(self, expired_cert):
        assert expired_cert.status == "expired"
        assert expired_cert.status_badge == "danger"
        assert expired_cert.days_remaining < 0

    def test_days_remaining_positive(self, sample_cert):
        assert sample_cert.days_remaining > 300

    def test_days_remaining_negative_when_expired(self, expired_cert):
        assert expired_cert.days_remaining < 0


class TestCertificateSans:
    def test_sans_roundtrip(self, sample_cert):
        assert "DNS:example.com" in sample_cert.sans
        assert "DNS:www.example.com" in sample_cert.sans

    def test_sans_empty_by_default(self, db, admin_user):
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = Certificate(
            common_name="nosans.example.com",
            not_after=now + datetime.timedelta(days=100),
            source="manual",
            added_by_id=admin_user.id,
        )
        db.session.add(cert)
        db.session.commit()
        assert cert.sans == []

    def test_sans_set_and_get(self, db, admin_user):
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = Certificate(
            common_name="multi.example.com",
            not_after=now + datetime.timedelta(days=100),
            source="manual",
            added_by_id=admin_user.id,
        )
        cert.sans = ["DNS:a.com", "DNS:b.com", "IP:10.0.0.1"]
        db.session.add(cert)
        db.session.commit()
        assert cert.sans == ["DNS:a.com", "DNS:b.com", "IP:10.0.0.1"]


class TestUserModel:
    def test_password_hashing(self, admin_user):
        assert admin_user.check_password("adminpass") is True

    def test_wrong_password_rejected(self, admin_user):
        assert admin_user.check_password("wrongpass") is False

    def test_admin_role(self, admin_user):
        assert admin_user.is_admin is True

    def test_regular_user_not_admin(self, regular_user):
        assert regular_user.is_admin is False

    def test_username_unique(self, db, admin_user):
        duplicate = User(username="admin", email="other@test.com", role="user")
        duplicate.set_password("pass")
        db.session.add(duplicate)
        with pytest.raises(Exception):
            db.session.commit()


class TestSettingsModel:
    def test_get_creates_default_row(self, db):
        settings = Settings.get()
        assert settings is not None
        assert settings.id is not None

    def test_get_returns_same_row(self, db):
        s1 = Settings.get()
        s2 = Settings.get()
        assert s1.id == s2.id

    def test_default_alert_days(self, db):
        settings = Settings.get()
        assert isinstance(settings.alert_days, list)
        assert len(settings.alert_days) > 0

    def test_alert_days_roundtrip(self, db):
        settings = Settings.get()
        settings.alert_days = [90, 30, 7]
        db.session.commit()
        refreshed = Settings.query.first()
        assert set(refreshed.alert_days) == {90, 30, 7}

    def test_email_recipients_roundtrip(self, db):
        settings = Settings.get()
        settings.email_recipients = ["a@test.com", "b@test.com"]
        db.session.commit()
        refreshed = Settings.query.first()
        assert "a@test.com" in refreshed.email_recipients

    def test_defaults_disabled(self, db):
        settings = Settings.get()
        assert settings.email_enabled is False
        assert settings.teams_enabled is False


class TestAlertLog:
    def test_alert_log_creation(self, db, sample_cert):
        log = AlertLog(
            certificate_id=sample_cert.id,
            days_threshold=30,
            channel="email",
        )
        db.session.add(log)
        db.session.commit()
        assert log.id is not None
        assert log.sent_at is not None

    def test_alert_log_relationship(self, db, sample_cert):
        log = AlertLog(
            certificate_id=sample_cert.id,
            days_threshold=7,
            channel="teams",
        )
        db.session.add(log)
        db.session.commit()
        assert log.certificate.common_name == sample_cert.common_name
