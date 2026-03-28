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
        trigger=CronTrigger(hour=8, minute=0),  # runs at 08:00 daily
        id="expiry_check",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Certificate expiry scheduler started (daily at 08:00).")


def _run_expiry_check(app):
    with app.app_context():
        from ..models import AlertLog, Certificate, Settings, db
        from .notifier import send_expiry_email, send_expiry_teams

        settings = Settings.get()
        if not settings.email_enabled and not settings.teams_enabled:
            return

        alert_days = settings.alert_days
        certs = Certificate.query.all()

        for cert in certs:
            days = cert.days_remaining
            for threshold in alert_days:
                if days <= threshold:
                    # Check if we already sent this alert
                    already_sent = AlertLog.query.filter_by(
                        certificate_id=cert.id,
                        days_threshold=threshold,
                    ).first()
                    if already_sent:
                        continue

                    try:
                        if settings.email_enabled:
                            send_expiry_email(settings, cert)
                            db.session.add(AlertLog(
                                certificate_id=cert.id,
                                days_threshold=threshold,
                                channel="email",
                            ))
                    except Exception as e:
                        logger.error(f"Email alert failed for cert {cert.id}: {e}")

                    try:
                        if settings.teams_enabled:
                            send_expiry_teams(settings, cert)
                            db.session.add(AlertLog(
                                certificate_id=cert.id,
                                days_threshold=threshold,
                                channel="teams",
                            ))
                    except Exception as e:
                        logger.error(f"Teams alert failed for cert {cert.id}: {e}")

                    db.session.commit()
                    break  # Only alert on the highest triggered threshold per run
