import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests


def _days_label(days: int) -> str:
    if days < 0:
        return "EXPIRED"
    return f"{days} day{'s' if days != 1 else ''}"


def send_expiry_email(settings, cert) -> None:
    if not settings.email_enabled or not settings.smtp_host:
        return
    if not settings.email_recipients:
        return

    days = cert.days_remaining
    subject = f"[CertManager] Certificate expiry alert: {cert.common_name} ({_days_label(days)})"

    body_html = f"""
    <h2>Certificate Expiry Alert</h2>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
      <tr><th>Common Name</th><td>{cert.common_name}</td></tr>
      <tr><th>Hostname</th><td>{cert.hostname or '—'}</td></tr>
      <tr><th>Expiry Date</th><td>{cert.not_after.strftime('%Y-%m-%d')}</td></tr>
      <tr><th>Days Remaining</th><td>{_days_label(days)}</td></tr>
      <tr><th>Issuer</th><td>{cert.issuer or '—'}</td></tr>
      <tr><th>Serial</th><td>{cert.serial_number or '—'}</td></tr>
    </table>
    <p>Please renew this certificate before it expires.</p>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(settings.email_recipients)
    msg.attach(MIMEText(body_html, "html"))

    _smtp_send(settings, msg)


def send_test_email(settings) -> None:
    if not settings.smtp_host:
        raise ValueError("SMTP host is not configured.")
    if not settings.email_recipients:
        raise ValueError("No email recipients configured.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[CertManager] Test Email"
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(settings.email_recipients)
    msg.attach(MIMEText("<h2>CertManager test email — it works!</h2>", "html"))
    _smtp_send(settings, msg)


def _smtp_send(settings, msg) -> None:
    if settings.smtp_tls:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
        server.starttls()
    else:
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10)

    if settings.smtp_user and settings.smtp_password:
        server.login(settings.smtp_user, settings.smtp_password)

    server.sendmail(
        settings.smtp_from or settings.smtp_user,
        settings.email_recipients,
        msg.as_string(),
    )
    server.quit()


def send_expiry_teams(settings, cert) -> None:
    if not settings.teams_enabled or not settings.teams_webhook_url:
        return

    days = cert.days_remaining
    color = "attention" if days <= 30 else "warning" if days <= 90 else "good"

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": "Certificate Expiry Alert",
                            "color": color,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Common Name", "value": cert.common_name},
                                {"title": "Hostname", "value": cert.hostname or "—"},
                                {"title": "Expiry Date", "value": cert.not_after.strftime("%Y-%m-%d")},
                                {"title": "Days Remaining", "value": _days_label(days)},
                                {"title": "Issuer", "value": cert.issuer or "—"},
                            ],
                        },
                    ],
                },
            }
        ],
    }

    resp = requests.post(
        settings.teams_webhook_url,
        json=payload,
        timeout=10,
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()


def send_test_teams(settings) -> None:
    if not settings.teams_webhook_url:
        raise ValueError("Teams webhook URL is not configured.")

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": "CertManager Test Message — it works!",
                            "color": "good",
                        }
                    ],
                },
            }
        ],
    }

    resp = requests.post(
        settings.teams_webhook_url,
        json=payload,
        timeout=10,
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
