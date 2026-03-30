"""
Integration tests for auth routes: login, logout, user management.
Uses Flask test client with an in-memory DB.
"""


class TestLogin:
    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"My Cert Manager" in resp.data

    def test_valid_login_redirects(self, client, admin_user):
        resp = client.post("/login", data={
            "username": "admin",
            "password": "adminpass",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_invalid_password_rejected(self, client, admin_user):
        resp = client.post("/login", data={
            "username": "admin",
            "password": "wrongpass",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_unknown_user_rejected(self, client):
        resp = client.post("/login", data={
            "username": "nobody",
            "password": "pass",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestLogout:
    def test_logout_redirects_to_login(self, auth_client):
        resp = auth_client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200
        assert b"logged out" in resp.data

    def test_after_logout_dashboard_requires_login(self, auth_client):
        auth_client.get("/logout")
        resp = auth_client.get("/", follow_redirects=False)
        assert resp.status_code == 302


class TestUserManagement:
    def test_users_page_accessible_to_admin(self, auth_client):
        resp = auth_client.get("/users")
        assert resp.status_code == 200
        assert b"Users" in resp.data

    def test_users_page_blocked_for_regular_user(self, user_client):
        resp = user_client.get("/users", follow_redirects=True)
        assert b"Admin access required" in resp.data

    def test_add_user_requires_team(self, auth_client):
        """Submitting a User role without a team_id must be rejected."""
        resp = auth_client.post("/users/add", data={
            "username": "noteamuser",
            "email": "noteam@test.com",
            "password": "newpass123",
            "role": "user",
        }, follow_redirects=True)
        assert b"team must be selected" in resp.data

    def test_add_global_admin_without_team(self, auth_client):
        """Global admin role does not require a team."""
        from app.models import User
        resp = auth_client.post("/users/add", data={
            "username": "gadmin",
            "email": "gadmin@test.com",
            "password": "gadminpass",
            "role": "global_admin",
        }, follow_redirects=True)
        assert resp.status_code == 200
        user = User.query.filter_by(username="gadmin").first()
        assert user is not None
        assert user.role == "global_admin"
        assert user.is_global_admin is True

    def test_add_user_with_team(self, auth_client, team):
        """User created with a team is added as a team member."""
        from app.models import TeamMember, User
        resp = auth_client.post("/users/add", data={
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "newpass123",
            "role": "user",
            "team_id": str(team.id),
            "can_view": "on",
            "can_add": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"newuser" in resp.data
        user = User.query.filter_by(username="newuser").first()
        assert user is not None
        membership = TeamMember.query.filter_by(user_id=user.id, team_id=team.id).first()
        assert membership is not None
        assert membership.can_view is True
        assert membership.can_add is True
        assert membership.can_edit is False

    def test_add_duplicate_username_rejected(self, auth_client, admin_user, team):
        resp = auth_client.post("/users/add", data={
            "username": "admin",
            "email": "other@test.com",
            "password": "pass",
            "role": "user",
            "team_id": str(team.id),
            "can_view": "on",
        }, follow_redirects=True)
        assert b"already exists" in resp.data

    def test_add_user_blocked_for_regular_user(self, user_client):
        resp = user_client.post("/users/add", data={
            "username": "hacker",
            "email": "hacker@test.com",
            "password": "pass",
            "role": "admin",
        }, follow_redirects=True)
        assert b"Admin access required" in resp.data

    def test_delete_user_as_admin(self, auth_client, regular_user):
        resp = auth_client.post(f"/users/{regular_user.id}/delete",
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data

    def test_cannot_delete_own_account(self, auth_client, admin_user):
        resp = auth_client.post(f"/users/{admin_user.id}/delete",
                                follow_redirects=True)
        assert b"Cannot delete your own account" in resp.data
