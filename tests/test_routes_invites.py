"""
Tests for the invite management and accept flow.

Covers:
  - Manager creates invite (list, create, revoke)
  - Non-manager access denied
  - Public invite_accept flow (valid token, invalid/expired/used)
  - Account creation + auto-login + team membership
"""

import datetime

import pytest

from app.models import Invite, TeamMember, User, db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)


# ---------------------------------------------------------------------------
# Invite list
# ---------------------------------------------------------------------------

class TestInviteList:
    def test_admin_can_view_invite_list(self, auth_client, db):
        resp = auth_client.get("/invites")
        assert resp.status_code == 200

    def test_global_admin_can_view_invite_list(self, global_admin_client, db):
        resp = global_admin_client.get("/invites")
        assert resp.status_code == 200

    def test_regular_user_denied(self, user_client, db):
        resp = user_client.get("/invites", follow_redirects=True)
        assert b"Access denied" in resp.data

    def test_unauthenticated_redirected(self, client, db):
        resp = client.get("/invites")
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Invite create
# ---------------------------------------------------------------------------

class TestInviteCreate:
    def test_get_create_form(self, auth_client, db):
        resp = auth_client.get("/invites/create")
        assert resp.status_code == 200
        assert b"Generate Invite Link" in resp.data

    def test_create_invite(self, auth_client, db, team):
        resp = auth_client.post("/invites/create", data={
            "email": "newperson@example.com",
            "team_id": team.id,
            "can_view": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invite Created" in resp.data
        invite = Invite.query.filter_by(email="newperson@example.com").first()
        assert invite is not None
        assert invite.can_view is True
        assert invite.can_add is False

    def test_create_requires_email(self, auth_client, db, team):
        resp = auth_client.post("/invites/create", data={
            "email": "",
            "team_id": team.id,
        }, follow_redirects=True)
        assert b"Email address is required" in resp.data

    def test_create_requires_team(self, auth_client, db):
        resp = auth_client.post("/invites/create", data={
            "email": "someone@example.com",
            "team_id": "",
        }, follow_redirects=True)
        assert b"valid team" in resp.data

    def test_create_warns_if_user_exists(self, auth_client, db, team, regular_user):
        resp = auth_client.post("/invites/create", data={
            "email": regular_user.email,
            "team_id": team.id,
        }, follow_redirects=True)
        assert b"already has an account" in resp.data

    def test_revokes_existing_pending_invite(self, auth_client, db, team, pending_invite):
        old_token = pending_invite.token
        resp = auth_client.post("/invites/create", data={
            "email": pending_invite.email,
            "team_id": team.id,
            "can_view": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Old invite should be gone
        assert Invite.query.filter_by(token=old_token).first() is None
        # New invite exists
        assert Invite.query.filter_by(email=pending_invite.email).first() is not None

    def test_regular_user_cannot_create_invite(self, user_client, db, team):
        resp = user_client.post("/invites/create", data={
            "email": "x@example.com",
            "team_id": team.id,
        }, follow_redirects=True)
        assert b"Access denied" in resp.data


# ---------------------------------------------------------------------------
# Invite revoke
# ---------------------------------------------------------------------------

class TestInviteRevoke:
    def test_revoke_pending_invite(self, auth_client, db, pending_invite):
        resp = auth_client.post(f"/invites/{pending_invite.id}/revoke",
                                follow_redirects=True)
        assert resp.status_code == 200
        assert Invite.query.get(pending_invite.id) is None

    def test_cannot_revoke_used_invite(self, auth_client, db, pending_invite):
        pending_invite.used_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()
        resp = auth_client.post(f"/invites/{pending_invite.id}/revoke",
                                follow_redirects=True)
        assert b"already been used" in resp.data
        assert Invite.query.get(pending_invite.id) is not None

    def test_regular_user_cannot_revoke(self, user_client, db, pending_invite):
        resp = user_client.post(f"/invites/{pending_invite.id}/revoke",
                                follow_redirects=True)
        assert b"Access denied" in resp.data


# ---------------------------------------------------------------------------
# Invite accept — public flow
# ---------------------------------------------------------------------------

class TestInviteAccept:
    def test_get_accept_page(self, client, db, pending_invite):
        resp = client.get(f"/invite/{pending_invite.token}")
        assert resp.status_code == 200
        assert b"Create your account" in resp.data

    def test_invalid_token_shows_not_found(self, client, db):
        resp = client.get("/invite/doesnotexist")
        assert resp.status_code == 200
        assert b"Not Found" in resp.data or b"not_found" in resp.data or b"invalid" in resp.data.lower()

    def test_expired_invite_shows_expired(self, client, db, pending_invite):
        pending_invite.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        db.session.commit()
        resp = client.get(f"/invite/{pending_invite.token}")
        assert resp.status_code == 200
        assert b"Expired" in resp.data or b"expired" in resp.data

    def test_used_invite_shows_used(self, client, db, pending_invite):
        pending_invite.used_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()
        resp = client.get(f"/invite/{pending_invite.token}")
        assert resp.status_code == 200
        assert b"Used" in resp.data or b"used" in resp.data

    def test_accept_creates_user_and_membership(self, client, db, pending_invite):
        resp = client.post(f"/invite/{pending_invite.token}", data={
            "username": "newjohnny",
            "password": "securepass",
            "confirm_password": "securepass",
        }, follow_redirects=True)
        assert resp.status_code == 200

        user = User.query.filter_by(email=pending_invite.email).first()
        assert user is not None
        assert user.username == "newjohnny"

        membership = TeamMember.query.filter_by(
            user_id=user.id, team_id=pending_invite.team_id
        ).first()
        assert membership is not None
        assert membership.can_view is True

        invite = Invite.query.get(pending_invite.id)
        assert invite.used_at is not None

    def test_accept_auto_logs_in(self, client, db, pending_invite):
        client.post(f"/invite/{pending_invite.token}", data={
            "username": "autologinuser",
            "password": "securepass",
            "confirm_password": "securepass",
        }, follow_redirects=True)
        # Should be logged in — dashboard accessible
        resp = client.get("/", follow_redirects=True)
        assert resp.status_code == 200

    def test_accept_password_too_short(self, client, db, pending_invite):
        resp = client.post(f"/invite/{pending_invite.token}", data={
            "username": "newuser",
            "password": "short",
            "confirm_password": "short",
        }, follow_redirects=True)
        assert b"at least 8 characters" in resp.data

    def test_accept_password_mismatch(self, client, db, pending_invite):
        resp = client.post(f"/invite/{pending_invite.token}", data={
            "username": "newuser",
            "password": "securepass",
            "confirm_password": "different",
        }, follow_redirects=True)
        assert b"do not match" in resp.data

    def test_accept_duplicate_username_rejected(self, client, db, pending_invite, regular_user):
        resp = client.post(f"/invite/{pending_invite.token}", data={
            "username": regular_user.username,
            "password": "securepass",
            "confirm_password": "securepass",
        }, follow_redirects=True)
        assert b"already taken" in resp.data

    def test_accept_requires_username(self, client, db, pending_invite):
        resp = client.post(f"/invite/{pending_invite.token}", data={
            "username": "",
            "password": "securepass",
            "confirm_password": "securepass",
        }, follow_redirects=True)
        assert b"display name is required" in resp.data
