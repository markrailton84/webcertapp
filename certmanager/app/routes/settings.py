from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from ..models import db, Settings

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    s = Settings.get()

    if request.method == "POST":
        # Alert thresholds
        days_raw = request.form.get("alert_days", "").strip()
        try:
            days = [int(d.strip()) for d in days_raw.split(",") if d.strip().isdigit()]
            s.alert_days = days
        except ValueError:
            flash("Invalid alert days format.", "danger")
            return render_template("settings.html", settings=s)

        # Email
        s.email_enabled = bool(request.form.get("email_enabled"))
        s.smtp_host = request.form.get("smtp_host", "").strip()
        s.smtp_port = int(request.form.get("smtp_port", 587) or 587)
        s.smtp_user = request.form.get("smtp_user", "").strip()
        s.smtp_from = request.form.get("smtp_from", "").strip()
        s.smtp_tls = bool(request.form.get("smtp_tls"))

        smtp_password = request.form.get("smtp_password", "").strip()
        if smtp_password:
            s.smtp_password = smtp_password

        recipients_raw = request.form.get("email_recipients", "").strip()
        s.email_recipients = [r.strip() for r in recipients_raw.splitlines() if r.strip()]

        # Teams
        s.teams_enabled = bool(request.form.get("teams_enabled"))
        s.teams_webhook_url = request.form.get("teams_webhook_url", "").strip()

        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("settings.settings"))

    return render_template("settings.html", settings=s)


@settings_bp.route("/settings/test-email", methods=["POST"])
@login_required
def test_email():
    if not current_user.is_admin:
        return {"error": "Forbidden"}, 403

    from ..services.notifier import send_test_email
    s = Settings.get()
    try:
        send_test_email(s)
        flash("Test email sent successfully.", "success")
    except Exception as e:
        flash(f"Email test failed: {e}", "danger")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/settings/test-teams", methods=["POST"])
@login_required
def test_teams():
    if not current_user.is_admin:
        return {"error": "Forbidden"}, 403

    from ..services.notifier import send_test_teams
    s = Settings.get()
    try:
        send_test_teams(s)
        flash("Teams test message sent successfully.", "success")
    except Exception as e:
        flash(f"Teams test failed: {e}", "danger")
    return redirect(url_for("settings.settings"))
