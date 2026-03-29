"""Tests for the teams blueprint — team CRUD, members, permissions, settings."""

import pytest

from app.models import Team, TeamMember, User, db as _db


# ---------------------------------------------------------------------------
# Team list (admin only)
# ---------------------------------------------------------------------------

class TestTeamsList:
    def test_admin_can_view_teams(self, auth_client, db):
        resp = auth_client.get("/teams")
        assert resp.status_code == 200

    def test_non_admin_redirected(self, client, db, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.get("/teams", follow_redirects=True)
        assert b"Admin access required" in resp.data


# ---------------------------------------------------------------------------
# Team creation (admin only)
# ---------------------------------------------------------------------------

class TestTeamCreate:
    def test_admin_can_create_team(self, auth_client, db, admin_user):
        resp = auth_client.post("/teams/new", data={
            "name": "New Team",
            "description": "A test team",
            "owner_id": admin_user.id,
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert Team.query.filter_by(name="New Team").first() is not None

    def test_duplicate_name_rejected(self, auth_client, db, team, admin_user):
        resp = auth_client.post("/teams/new", data={
            "name": "Platform Team",
            "description": "duplicate",
            "owner_id": admin_user.id,
        }, follow_redirects=True)
        assert b"already exists" in resp.data

    def test_missing_name_rejected(self, auth_client, db, admin_user):
        resp = auth_client.post("/teams/new", data={
            "name": "",
            "owner_id": admin_user.id,
        }, follow_redirects=True)
        assert b"required" in resp.data

    def test_missing_owner_rejected(self, auth_client, db):
        resp = auth_client.post("/teams/new", data={
            "name": "Orphan Team",
        }, follow_redirects=True)
        assert b"valid team owner" in resp.data

    def test_non_admin_cannot_create(self, client, db, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.get("/teams/new", follow_redirects=True)
        assert b"Admin access required" in resp.data


# ---------------------------------------------------------------------------
# Team detail (owner or admin)
# ---------------------------------------------------------------------------

class TestTeamDetail:
    def test_admin_can_view_team(self, auth_client, db, team):
        resp = auth_client.get(f"/teams/{team.id}")
        assert resp.status_code == 200
        assert b"Platform Team" in resp.data

    def test_owner_can_view_team(self, client, db, team, admin_user):
        # Admin is the owner in fixtures
        client.post("/login", data={"username": "admin", "password": "adminpass"})
        resp = client.get(f"/teams/{team.id}")
        assert resp.status_code == 200

    def test_non_owner_non_admin_denied(self, client, db, team, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.get(f"/teams/{team.id}", follow_redirects=True)
        assert b"Team owner access required" in resp.data

    def test_nonexistent_team_404(self, auth_client, db):
        resp = auth_client.get("/teams/99999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Team deletion (admin only)
# ---------------------------------------------------------------------------

class TestTeamDelete:
    def test_admin_can_delete_team(self, auth_client, db, team):
        resp = auth_client.post(f"/teams/{team.id}/delete", follow_redirects=True)
        assert resp.status_code == 200
        assert Team.query.get(team.id) is None

    def test_non_admin_cannot_delete(self, client, db, team, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.post(f"/teams/{team.id}/delete", follow_redirects=True)
        assert b"Admin access required" in resp.data
        assert Team.query.get(team.id) is not None


# ---------------------------------------------------------------------------
# Member add
# ---------------------------------------------------------------------------

class TestMemberAdd:
    def test_owner_can_add_member(self, auth_client, db, team, regular_user):
        resp = auth_client.post(f"/teams/{team.id}/members/add", data={
            "user_id": regular_user.id,
            "can_view": "on",
            "can_add": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        member = TeamMember.query.filter_by(team_id=team.id, user_id=regular_user.id).first()
        assert member is not None
        assert member.can_view is True
        assert member.can_add is True
        assert member.can_edit is False
        assert member.can_delete is False

    def test_non_owner_cannot_add_member(self, client, db, team, regular_user, team_member_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.post(f"/teams/{team.id}/members/add", data={
            "user_id": team_member_user.id,
            "can_view": "on",
        }, follow_redirects=True)
        assert b"Team owner access required" in resp.data

    def test_invalid_user_rejected(self, auth_client, db, team):
        resp = auth_client.post(f"/teams/{team.id}/members/add", data={
            "user_id": 99999,
            "can_view": "on",
        }, follow_redirects=True)
        assert b"valid user" in resp.data


# ---------------------------------------------------------------------------
# Member edit
# ---------------------------------------------------------------------------

class TestMemberEdit:
    def test_owner_can_edit_permissions(self, auth_client, db, team, team_membership):
        resp = auth_client.post(
            f"/teams/{team.id}/members/{team_membership.id}/edit",
            data={
                "can_view": "on",
                "can_add": "on",
                "can_edit": "on",
                "can_delete": "on",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        _db.session.refresh(team_membership)
        assert team_membership.can_edit is True
        assert team_membership.can_delete is True

    def test_non_owner_cannot_edit(self, client, db, team, team_membership, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.post(
            f"/teams/{team.id}/members/{team_membership.id}/edit",
            data={"can_view": "on"},
            follow_redirects=True,
        )
        assert b"Team owner access required" in resp.data


# ---------------------------------------------------------------------------
# Member remove
# ---------------------------------------------------------------------------

class TestMemberRemove:
    def test_owner_can_remove_member(self, auth_client, db, team, team_membership):
        member_id = team_membership.id
        resp = auth_client.post(
            f"/teams/{team.id}/members/{member_id}/remove",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert TeamMember.query.get(member_id) is None

    def test_non_owner_cannot_remove(self, client, db, team, team_membership, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.post(
            f"/teams/{team.id}/members/{team_membership.id}/remove",
            follow_redirects=True,
        )
        assert b"Team owner access required" in resp.data


# ---------------------------------------------------------------------------
# Team notification settings
# ---------------------------------------------------------------------------

class TestTeamSettings:
    def test_owner_can_view_settings(self, auth_client, db, team):
        resp = auth_client.get(f"/teams/{team.id}/settings")
        assert resp.status_code == 200

    def test_owner_can_save_settings(self, auth_client, db, team):
        resp = auth_client.post(f"/teams/{team.id}/settings", data={
            "alert_days": "90, 30, 7",
            "email_enabled": "on",
            "smtp_host": "smtp.test.com",
            "smtp_port": "587",
            "smtp_user": "testuser",
            "smtp_from": "alerts@test.com",
            "smtp_tls": "on",
            "email_recipients": "a@test.com\nb@test.com",
            "teams_enabled": "on",
            "teams_webhook_url": "https://webhook.test.com/hook",
        }, follow_redirects=True)
        assert resp.status_code == 200

        _db.session.refresh(team)
        assert team.email_enabled is True
        assert team.smtp_host == "smtp.test.com"
        assert team.alert_days == [90, 30, 7]
        assert team.email_recipients == ["a@test.com", "b@test.com"]
        assert team.teams_enabled is True
        assert team.teams_webhook_url == "https://webhook.test.com/hook"

    def test_non_owner_cannot_save_settings(self, client, db, team, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        resp = client.post(f"/teams/{team.id}/settings", data={
            "alert_days": "90",
        }, follow_redirects=True)
        assert b"Team owner access required" in resp.data


# ---------------------------------------------------------------------------
# Team certificates visibility
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Team API key
# ---------------------------------------------------------------------------

class TestTeamApiKey:
    def test_team_has_api_key(self, db, team):
        assert team.api_key is not None
        assert len(team.api_key) == 64  # hex(32) = 64 chars

    def test_regenerate_api_key(self, auth_client, db, team):
        old_key = team.api_key
        resp = auth_client.post(f"/teams/{team.id}/regenerate-api-key", follow_redirects=True)
        assert resp.status_code == 200
        _db.session.refresh(team)
        assert team.api_key != old_key
        assert len(team.api_key) == 64

    def test_non_owner_cannot_regenerate(self, client, db, team, regular_user):
        client.post("/login", data={"username": "user1", "password": "userpass"})
        old_key = team.api_key
        resp = client.post(f"/teams/{team.id}/regenerate-api-key", follow_redirects=True)
        assert b"Team owner access required" in resp.data
        _db.session.refresh(team)
        assert team.api_key == old_key


# ---------------------------------------------------------------------------
# Team certificates visibility
# ---------------------------------------------------------------------------

class TestTeamCertVisibility:
    def test_team_detail_shows_certs(self, auth_client, db, team, team_cert):
        resp = auth_client.get(f"/teams/{team.id}")
        assert b"team.example.com" in resp.data

    def test_dashboard_shows_team_column(self, auth_client, db, team, team_cert):
        resp = auth_client.get("/")
        assert b"Platform Team" in resp.data
