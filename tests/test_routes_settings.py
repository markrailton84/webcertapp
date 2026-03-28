"""
Integration tests for settings routes: save config, test email, test Teams.
"""

import pytest
from unittest.mock import patch, MagicMock

from app.models import Settings


class TestSettingsPage:
    def test_settings_page_loads_for_admin(self, auth_client):
        resp = auth_client.get("/settings")
        assert resp.status_code == 200
        assert b"Settings" in resp.data

    def test_settings_page_blocked_for_regular_user(self, user_client):
        resp = user_client.get("/settings", follow_redirects=True)
        assert b"Admin access required" in resp.data


class TestSettingsSave:
    def test_save_alert_days(self, auth_client, db):
        resp = auth_client.post("/settings", data={
            "alert_days": "90, 30, 7",
            "smtp_port": "587",
            "smtp_tls": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Settings saved" in resp.data
        s = Settings.get()
        assert set(s.alert_days) == {90, 30, 7}

    def test_save_email_config(self, auth_client, db):
        resp = auth_client.post("/settings", data={
            "alert_days": "30",
            "email_enabled": "on",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_user": "user@example.com",
            "smtp_password": "secret",
            "smtp_from": "CertManager <alerts@example.com>",
            "smtp_tls": "on",
            "email_recipients": "a@test.com\nb@test.com",
        }, follow_redirects=True)
        assert resp.status_code == 200
        s = Settings.get()
        assert s.email_enabled is True
        assert s.smtp_host == "smtp.example.com"
        assert "a@test.com" in s.email_recipients

    def test_save_teams_config(self, auth_client, db):
        resp = auth_client.post("/settings", data={
            "alert_days": "30",
            "teams_enabled": "on",
            "teams_webhook_url": "https://teams.webhook.example/hook",
            "smtp_port": "587",
        }, follow_redirects=True)
        assert resp.status_code == 200
        s = Settings.get()
        assert s.teams_enabled is True
        assert s.teams_webhook_url == "https://teams.webhook.example/hook"

    def test_password_not_overwritten_when_blank(self, auth_client, db):
        # Set initial password
        auth_client.post("/settings", data={
            "alert_days": "30",
            "email_enabled": "on",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_password": "original-password",
        }, follow_redirects=True)
        # Re-save without providing password
        auth_client.post("/settings", data={
            "alert_days": "30",
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_password": "",
        }, follow_redirects=True)
        s = Settings.get()
        assert s.smtp_password == "original-password"


class TestTestEmail:
    def test_test_email_success(self, auth_client):
        with patch("app.routes.settings.send_test_email") as mock_send:
            resp = auth_client.post("/settings/test-email", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Test email sent" in resp.data
        mock_send.assert_called_once()

    def test_test_email_failure_shows_error(self, auth_client):
        with patch("app.routes.settings.send_test_email",
                   side_effect=Exception("SMTP connection refused")):
            resp = auth_client.post("/settings/test-email", follow_redirects=True)
        assert b"Email test failed" in resp.data

    def test_test_email_blocked_for_regular_user(self, user_client):
        resp = user_client.post("/settings/test-email")
        assert resp.status_code == 403


class TestTestTeams:
    def test_test_teams_success(self, auth_client):
        with patch("app.routes.settings.send_test_teams") as mock_send:
            resp = auth_client.post("/settings/test-teams", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Teams test message sent" in resp.data
        mock_send.assert_called_once()

    def test_test_teams_failure_shows_error(self, auth_client):
        with patch("app.routes.settings.send_test_teams",
                   side_effect=Exception("Webhook not found")):
            resp = auth_client.post("/settings/test-teams", follow_redirects=True)
        assert b"Teams test failed" in resp.data

    def test_test_teams_blocked_for_regular_user(self, user_client):
        resp = user_client.post("/settings/test-teams")
        assert resp.status_code == 403
