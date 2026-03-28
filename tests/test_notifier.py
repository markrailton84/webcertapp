"""
Tests for app/services/notifier.py

All SMTP and HTTP calls are mocked — no real emails or Teams messages sent.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services.notifier import (
    _days_label,
    send_expiry_email,
    send_test_email,
    send_expiry_teams,
    send_test_teams,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_settings(
    email_enabled=True,
    smtp_host="smtp.test.com",
    smtp_port=587,
    smtp_user="user@test.com",
    smtp_password="pass",
    smtp_from="CertManager <alerts@test.com>",
    smtp_tls=True,
    email_recipients=None,
    teams_enabled=True,
    teams_webhook_url="https://teams.webhook.example/hook",
):
    s = MagicMock()
    s.email_enabled = email_enabled
    s.smtp_host = smtp_host
    s.smtp_port = smtp_port
    s.smtp_user = smtp_user
    s.smtp_password = smtp_password
    s.smtp_from = smtp_from
    s.smtp_tls = smtp_tls
    s.email_recipients = email_recipients or ["recipient@test.com"]
    s.teams_enabled = teams_enabled
    s.teams_webhook_url = teams_webhook_url
    return s


# ---------------------------------------------------------------------------
# _days_label
# ---------------------------------------------------------------------------

class TestDaysLabel:
    def test_positive_days(self):
        assert _days_label(30) == "30 days"

    def test_one_day(self):
        assert _days_label(1) == "1 day"

    def test_zero_days(self):
        assert _days_label(0) == "0 days"

    def test_negative_days(self):
        assert _days_label(-5) == "EXPIRED"


# ---------------------------------------------------------------------------
# send_expiry_email
# ---------------------------------------------------------------------------

class TestSendExpiryEmail:
    def test_sends_when_enabled(self, sample_cert):
        settings = make_settings()
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            send_expiry_email(settings, sample_cert)
            mock_server.sendmail.assert_called_once()

    def test_skips_when_disabled(self, sample_cert):
        settings = make_settings(email_enabled=False)
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            send_expiry_email(settings, sample_cert)
            mock_smtp.assert_not_called()

    def test_skips_when_no_host(self, sample_cert):
        settings = make_settings(smtp_host="")
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            send_expiry_email(settings, sample_cert)
            mock_smtp.assert_not_called()

    def test_skips_when_no_recipients(self, sample_cert):
        settings = make_settings(email_recipients=[])
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            send_expiry_email(settings, sample_cert)
            mock_smtp.assert_not_called()

    def test_subject_contains_common_name(self, sample_cert):
        settings = make_settings()
        captured = {}
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server

            def capture_sendmail(from_addr, to_addrs, msg_str):
                captured["msg"] = msg_str

            mock_server.sendmail.side_effect = capture_sendmail
            send_expiry_email(settings, sample_cert)

        assert sample_cert.common_name in captured["msg"]

    def test_uses_starttls_when_tls_true(self, sample_cert):
        settings = make_settings(smtp_tls=True)
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            send_expiry_email(settings, sample_cert)
            mock_server.starttls.assert_called_once()

    def test_uses_smtp_ssl_when_tls_false(self, sample_cert):
        settings = make_settings(smtp_tls=False)
        with patch("app.services.notifier.smtplib.SMTP_SSL") as mock_smtp_ssl:
            mock_server = MagicMock()
            mock_smtp_ssl.return_value = mock_server
            send_expiry_email(settings, sample_cert)
            mock_smtp_ssl.assert_called_once()


# ---------------------------------------------------------------------------
# send_test_email
# ---------------------------------------------------------------------------

class TestSendTestEmail:
    def test_sends_test_email(self):
        settings = make_settings()
        with patch("app.services.notifier.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            send_test_email(settings)
            mock_server.sendmail.assert_called_once()

    def test_raises_when_no_host(self):
        settings = make_settings(smtp_host="")
        with pytest.raises(ValueError, match="SMTP host"):
            send_test_email(settings)

    def test_raises_when_no_recipients(self):
        settings = make_settings(email_recipients=[])
        with pytest.raises(ValueError, match="recipients"):
            send_test_email(settings)


# ---------------------------------------------------------------------------
# send_expiry_teams
# ---------------------------------------------------------------------------

class TestSendExpiryTeams:
    def test_posts_to_webhook(self, sample_cert):
        settings = make_settings()
        with patch("app.services.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            send_expiry_teams(settings, sample_cert)
            mock_post.assert_called_once()
            assert settings.teams_webhook_url in mock_post.call_args[0]

    def test_skips_when_disabled(self, sample_cert):
        settings = make_settings(teams_enabled=False)
        with patch("app.services.notifier.requests.post") as mock_post:
            send_expiry_teams(settings, sample_cert)
            mock_post.assert_not_called()

    def test_skips_when_no_webhook_url(self, sample_cert):
        settings = make_settings(teams_webhook_url="")
        with patch("app.services.notifier.requests.post") as mock_post:
            send_expiry_teams(settings, sample_cert)
            mock_post.assert_not_called()

    def test_payload_contains_common_name(self, sample_cert):
        settings = make_settings()
        captured = {}
        with patch("app.services.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())

            def capture(**kwargs):
                captured["json"] = str(kwargs.get("json", ""))
                return MagicMock(raise_for_status=MagicMock())

            mock_post.side_effect = capture
            send_expiry_teams(settings, sample_cert)

        assert sample_cert.common_name in captured["json"]

    def test_raises_on_webhook_error(self, sample_cert):
        settings = make_settings()
        with patch("app.services.notifier.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.side_effect = Exception("HTTP 400")
            mock_post.return_value = mock_resp
            with pytest.raises(Exception, match="HTTP 400"):
                send_expiry_teams(settings, sample_cert)


# ---------------------------------------------------------------------------
# send_test_teams
# ---------------------------------------------------------------------------

class TestSendTestTeams:
    def test_sends_test_message(self):
        settings = make_settings()
        with patch("app.services.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            send_test_teams(settings)
            mock_post.assert_called_once()

    def test_raises_when_no_webhook_url(self):
        settings = make_settings(teams_webhook_url="")
        with pytest.raises(ValueError, match="webhook URL"):
            send_test_teams(settings)
