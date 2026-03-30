"""
Invite management blueprint.

Managers (admin / global_admin) create one-time invite links and assign
team membership + permissions before the user has even signed up.

The invite flow:
  1. Manager creates invite → one-time URL generated
  2. Manager shares the URL out-of-band (Teams, Slack, email, etc.)
  3. User opens URL → sets a password → auto-logged in → lands on dashboard
"""

import datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user

from ..models import Invite, Team, TeamMember, User, db

invites_bp = Blueprint("invites", __name__)

_INVITE_EXPIRY_HOURS = 48


# ---------------------------------------------------------------------------
# Manager views
# ---------------------------------------------------------------------------

@invites_bp.route("/invites")
@login_required
def invite_list():
    if not current_user.is_manager:
        flash("Access denied.", "danger")
        return redirect(url_for("certs.dashboard"))

    invites = (
        Invite.query
        .order_by(Invite.created_at.desc())
        .all()
    )
    return render_template("invites.html", invites=invites)


@invites_bp.route("/invites/create", methods=["GET", "POST"])
@login_required
def invite_create():
    if not current_user.is_manager:
        flash("Access denied.", "danger")
        return redirect(url_for("certs.dashboard"))

    teams = Team.query.order_by(Team.name).all()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        team_id = request.form.get("team_id", type=int)

        if not email:
            flash("Email address is required.", "danger")
            return render_template("invite_create.html", teams=teams)

        if not team_id or not Team.query.get(team_id):
            flash("Please select a valid team.", "danger")
            return render_template("invite_create.html", teams=teams)

        # Warn if user already exists — they should be added via team membership instead
        if User.query.filter_by(email=email).first():
            flash(f"{email} already has an account. Add them via team membership instead.", "warning")
            return render_template("invite_create.html", teams=teams)

        # Revoke any existing pending invite for this email + team
        existing = Invite.query.filter_by(email=email, team_id=team_id, used_at=None).first()
        if existing and existing.is_valid:
            db.session.delete(existing)

        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=_INVITE_EXPIRY_HOURS)
        invite = Invite(
            email=email,
            team_id=team_id,
            can_view=bool(request.form.get("can_view")),
            can_add=bool(request.form.get("can_add")),
            can_edit=bool(request.form.get("can_edit")),
            can_delete=bool(request.form.get("can_delete")),
            created_by_id=current_user.id,
            expires_at=expires_at,
        )
        db.session.add(invite)
        db.session.commit()

        invite_url = url_for("invites.invite_accept", token=invite.token, _external=True)
        flash("Invite created successfully.", "success")
        return render_template("invite_created.html", invite=invite, invite_url=invite_url)

    return render_template("invite_create.html", teams=teams)


@invites_bp.route("/invites/<int:invite_id>/revoke", methods=["POST"])
@login_required
def invite_revoke(invite_id):
    if not current_user.is_manager:
        flash("Access denied.", "danger")
        return redirect(url_for("certs.dashboard"))

    invite = Invite.query.get_or_404(invite_id)
    if invite.is_used:
        flash("Cannot revoke an invite that has already been used.", "warning")
    else:
        db.session.delete(invite)
        db.session.commit()
        flash(f"Invite for {invite.email} revoked.", "success")

    return redirect(url_for("invites.invite_list"))


# ---------------------------------------------------------------------------
# Public accept flow (no login required)
# ---------------------------------------------------------------------------

@invites_bp.route("/invite/<token>", methods=["GET", "POST"])
def invite_accept(token):
    invite = Invite.query.filter_by(token=token).first()

    if not invite:
        return render_template("invite_invalid.html", reason="not_found")
    if invite.is_used:
        return render_template("invite_invalid.html", reason="used")
    if invite.is_expired:
        return render_template("invite_invalid.html", reason="expired")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username:
            errors.append("A display name is required.")
        elif User.query.filter_by(username=username).first():
            errors.append("That display name is already taken — please choose another.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            return render_template("invite_accept.html", invite=invite, errors=errors,
                                   username=username)

        # Create the user
        user = User(username=username, email=invite.email, role="user")
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        # Add team membership with the permissions set on the invite
        membership = TeamMember(
            team_id=invite.team_id,
            user_id=user.id,
            can_view=invite.can_view,
            can_add=invite.can_add,
            can_edit=invite.can_edit,
            can_delete=invite.can_delete,
        )
        db.session.add(membership)

        # Mark invite as used
        invite.used_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()

        # Auto-login
        login_user(user)
        flash(f"Welcome to My Cert Manager, {user.username}! You've joined {invite.team.name}.", "success")
        return redirect(url_for("certs.dashboard"))

    return render_template("invite_accept.html", invite=invite, errors=[], username="")
