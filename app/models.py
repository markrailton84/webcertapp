import json
import secrets
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

    @property
    def is_global_admin(self):
        return self.role == "global_admin"

    @property
    def can_see_all(self):
        """True for roles that have visibility across all teams."""
        return self.role in ("admin", "global_admin")

    @property
    def is_manager(self):
        """True for roles that can manage teams, users, and invites."""
        return self.role in ("admin", "global_admin")


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
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
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

    api_key = db.Column(db.String(64), default=lambda: secrets.token_hex(32))

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

    def regenerate_api_key(self):
        self.api_key = secrets.token_hex(32)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if not settings:
            settings = cls()
            db.session.add(settings)
            db.session.commit()
        return settings


class Team(db.Model):
    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Per-team alert thresholds
    _alert_days = db.Column("team_alert_days", db.Text, default="[90, 60, 30, 14, 7]")

    # Per-team email settings
    email_enabled = db.Column(db.Boolean, default=False)
    smtp_host = db.Column(db.String(256))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_user = db.Column(db.String(256))
    smtp_password = db.Column(db.String(256))
    smtp_from = db.Column(db.String(256))
    smtp_tls = db.Column(db.Boolean, default=True)
    _email_recipients = db.Column("team_email_recipients", db.Text, default="[]")

    # Per-team Teams webhook
    teams_enabled = db.Column(db.Boolean, default=False)
    teams_webhook_url = db.Column(db.Text)

    # Per-team API key
    api_key = db.Column(db.String(64), default=lambda: secrets.token_hex(32))

    owner = db.relationship("User", foreign_keys=[owner_id], backref="owned_teams")
    members = db.relationship("TeamMember", backref="team", lazy=True, cascade="all, delete-orphan")
    certificates = db.relationship("Certificate", backref="team", lazy=True)

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

    def get_member(self, user):
        return TeamMember.query.filter_by(team_id=self.id, user_id=user.id).first()

    def is_owner(self, user):
        return self.owner_id == user.id

    def regenerate_api_key(self):
        self.api_key = secrets.token_hex(32)


class TeamMember(db.Model):
    __tablename__ = "team_members"

    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    can_view = db.Column(db.Boolean, default=True)
    can_add = db.Column(db.Boolean, default=False)
    can_edit = db.Column(db.Boolean, default=False)
    can_delete = db.Column(db.Boolean, default=False)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", backref="team_memberships")


class AlertLog(db.Model):
    __tablename__ = "alert_logs"

    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=False)
    days_threshold = db.Column(db.Integer, nullable=False)
    channel = db.Column(db.String(20))  # 'email' or 'teams'
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificate = db.relationship("Certificate", backref="alert_logs")


class Invite(db.Model):
    __tablename__ = "invites"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False,
                      default=lambda: secrets.token_urlsafe(32))
    team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=False)
    can_view = db.Column(db.Boolean, default=True)
    can_add = db.Column(db.Boolean, default=False)
    can_edit = db.Column(db.Boolean, default=False)
    can_delete = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    team = db.relationship("Team", backref="invites")
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    @property
    def is_expired(self):
        now = datetime.now(timezone.utc)
        exp = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        return now > exp

    @property
    def is_used(self):
        return self.used_at is not None

    @property
    def status(self):
        if self.is_used:
            return "used"
        if self.is_expired:
            return "expired"
        return "pending"

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
