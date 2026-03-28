import json
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user")  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificates = db.relationship("Certificate", backref="added_by_user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(256), nullable=False)
    _sans = db.Column("sans", db.Text, default="[]")
    issuer = db.Column(db.String(512))
    subject = db.Column(db.String(512))
    serial_number = db.Column(db.String(128))
    thumbprint = db.Column(db.String(128))
    not_before = db.Column(db.DateTime)
    not_after = db.Column(db.DateTime, nullable=False)
    hostname = db.Column(db.String(256))
    notes = db.Column(db.Text)
    tags = db.Column(db.String(512))
    source = db.Column(db.String(20), default="manual")  # manual, upload, fetch
    added_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    _alert_sent_days = db.Column("alert_sent_days", db.Text, default="[]")

    @property
    def sans(self):
        return json.loads(self._sans or "[]")

    @sans.setter
    def sans(self, value):
        self._sans = json.dumps(value if isinstance(value, list) else [])

    @property
    def alert_sent_days(self):
        return json.loads(self._alert_sent_days or "[]")

    @alert_sent_days.setter
    def alert_sent_days(self, value):
        self._alert_sent_days = json.dumps(value)

    @property
    def days_remaining(self):
        now = datetime.now(timezone.utc)
        expiry = self.not_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - now
        return delta.days

    @property
    def status(self):
        days = self.days_remaining
        if days < 0:
            return "expired"
        elif days <= 30:
            return "critical"
        elif days <= 90:
            return "warning"
        return "ok"

    @property
    def status_badge(self):
        return {
            "expired": "danger",
            "critical": "danger",
            "warning": "warning",
            "ok": "success",
        }.get(self.status, "secondary")


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    _alert_days = db.Column("alert_days", db.Text, default="[90, 60, 30, 14, 7]")

    email_enabled = db.Column(db.Boolean, default=False)
    smtp_host = db.Column(db.String(256))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_user = db.Column(db.String(256))
    smtp_password = db.Column(db.String(256))
    smtp_from = db.Column(db.String(256))
    smtp_tls = db.Column(db.Boolean, default=True)
    _email_recipients = db.Column("email_recipients", db.Text, default="[]")

    teams_enabled = db.Column(db.Boolean, default=False)
    teams_webhook_url = db.Column(db.Text)

    @property
    def alert_days(self):
        return sorted(json.loads(self._alert_days or "[90,60,30,14,7]"), reverse=True)

    @alert_days.setter
    def alert_days(self, value):
        self._alert_days = json.dumps(value)

    @property
    def email_recipients(self):
        return json.loads(self._email_recipients or "[]")

    @email_recipients.setter
    def email_recipients(self, value):
        self._email_recipients = json.dumps(value)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if not settings:
            settings = cls()
            db.session.add(settings)
            db.session.commit()
        return settings


class AlertLog(db.Model):
    __tablename__ = "alert_logs"

    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=False)
    days_threshold = db.Column(db.Integer, nullable=False)
    channel = db.Column(db.String(20))  # 'email' or 'teams'
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificate = db.relationship("Certificate", backref="alert_logs")
