import os

from flask import Flask
from flask_login import LoginManager

from .models import db, User
from .services.scheduler import init_scheduler


login_manager = LoginManager()


def create_app(test_config=None):
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:////app/data/certmanager.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB upload limit

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .routes.api import api_bp
    from .routes.auth import auth_bp
    from .routes.certs import certs_bp
    from .routes.settings import settings_bp
    from .routes.teams import teams_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(certs_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(teams_bp)

    with app.app_context():
        db.create_all()
        _migrate_db()
        _ensure_admin()
        init_scheduler(app)

    return app


def _migrate_db():
    """Apply any column additions that db.create_all() won't add to existing tables."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # Add api_key to settings if missing
    settings_cols = {c["name"] for c in inspector.get_columns("settings")}
    if "api_key" not in settings_cols:
        import secrets
        new_key = secrets.token_hex(32)
        db.session.execute(
            text(f"ALTER TABLE settings ADD COLUMN api_key VARCHAR(64) DEFAULT '{new_key}'")
        )
        db.session.commit()

    # Add team_id to certificates if missing
    if inspector.has_table("certificates"):
        cert_cols = {c["name"] for c in inspector.get_columns("certificates")}
        if "team_id" not in cert_cols:
            db.session.execute(text("ALTER TABLE certificates ADD COLUMN team_id INTEGER REFERENCES teams(id)"))
            db.session.commit()


def _ensure_admin():
    from .models import User
    if not User.query.filter_by(role="admin").first():
        admin = User(
            username=os.environ.get("ADMIN_USERNAME", "admin"),
            email=os.environ.get("ADMIN_EMAIL", "admin@example.com"),
            role="admin",
        )
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "changeme"))
        db.session.add(admin)
        db.session.commit()
