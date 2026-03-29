import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)
_scheduler = None


def init_scheduler(app):
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func=lambda: _run_expiry_check(app),
        trigger=CronTrigger(hour=8, minute=0),
        id="expiry_check",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Certificate expiry scheduler started (daily at 08:00).")


def _alert_for_cert(cert, settings_obj, alert_days, db, AlertLog, send_email_fn, send_teams_fn):
    """Send alerts for a single cert using the provided settings object."""
    days = cert.days_remaining
    for threshold in alert_days:
        if days <= threshold:
            already_sent = AlertLog.query.filter_by(
                certificate_id=cert.id,
                days_threshold=threshold,
            ).first()
            if already_sent:
                break

            try:
                if settings_obj.email_enabled:
                    send_email_fn(settings_obj, cert)
                    db.session.add(AlertLog(
                        certificate_id=cert.id,
                        days_threshold=threshold,
                        channel="email",
                    ))
            except Exception as e:
                logger.error(f"Email alert failed for cert {cert.id}: {e}")

            try:
                if settings_obj.teams_enabled:
                    send_teams_fn(settings_obj, cert)
                    db.session.add(AlertLog(
                        certificate_id=cert.id,
                        days_threshold=threshold,
                        channel="teams",
                    ))
            except Exception as e:
                logger.error(f"Teams alert failed for cert {cert.id}: {e}")

            db.session.commit()
            break  # Only alert on the highest triggered threshold per run


def _run_expiry_check(app):
    with app.app_context():
        from ..models import AlertLog, Certificate, Settings, Team, db
        from .notifier import send_expiry_email, send_expiry_teams

        # --- Global settings: certs with no team assigned ---
        global_settings = Settings.get()
        unowned_certs = Certificate.query.filter(Certificate.team_id.is_(None)).all()
        if global_settings.email_enabled or global_settings.teams_enabled:
            for cert in unowned_certs:
                _alert_for_cert(
                    cert, global_settings, global_settings.alert_days,
                    db, AlertLog, send_expiry_email, send_expiry_teams,
                )

        # --- Per-team settings: certs belonging to a team ---
        for team in Team.query.all():
            if not team.email_enabled and not team.teams_enabled:
                continue
            team_certs = Certificate.query.filter_by(team_id=team.id).all()
            for cert in team_certs:
                _alert_for_cert(
                    cert, team, team.alert_days,
                    db, AlertLog, send_expiry_email, send_expiry_teams,
                )
