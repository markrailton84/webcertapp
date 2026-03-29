from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..models import Team, TeamMember, User, db

teams_bp = Blueprint("teams", __name__)


def _require_team_owner(team):
    """Return a redirect if the current user is not admin or team owner, else None."""
    if current_user.is_admin or team.is_owner(current_user):
        return None
    flash("Team owner access required.", "danger")
    return redirect(url_for("certs.dashboard"))


# ---------------------------------------------------------------------------
# Team list (admin only)
# ---------------------------------------------------------------------------

@teams_bp.route("/teams")
@login_required
def teams_list():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))
    teams = Team.query.order_by(Team.name).all()
    return render_template("teams.html", teams=teams)


@teams_bp.route("/teams/new", methods=["GET", "POST"])
@login_required
def team_new():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    users = User.query.order_by(User.username).all()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        owner_id = request.form.get("owner_id", type=int)

        if not name:
            flash("Team name is required.", "danger")
            return render_template("team_form.html", users=users)

        if Team.query.filter_by(name=name).first():
            flash(f"A team named '{name}' already exists.", "danger")
            return render_template("team_form.html", users=users)

        owner = User.query.get(owner_id) if owner_id else None
        if not owner:
            flash("A valid team owner is required.", "danger")
            return render_template("team_form.html", users=users)

        team = Team(name=name, description=description, owner_id=owner.id)
        db.session.add(team)
        db.session.commit()
        flash(f"Team '{name}' created.", "success")
        return redirect(url_for("teams.team_detail", team_id=team.id))

    return render_template("team_form.html", users=users, team=None)


@teams_bp.route("/teams/<int:team_id>/delete", methods=["POST"])
@login_required
def team_delete(team_id):
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    team = Team.query.get_or_404(team_id)
    name = team.name
    db.session.delete(team)
    db.session.commit()
    flash(f"Team '{name}' deleted.", "success")
    return redirect(url_for("teams.teams_list"))


# ---------------------------------------------------------------------------
# Team detail (owner or admin)
# ---------------------------------------------------------------------------

@teams_bp.route("/teams/<int:team_id>")
@login_required
def team_detail(team_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied
    return render_template("team_detail.html", team=team)


# ---------------------------------------------------------------------------
# Member management (owner or admin)
# ---------------------------------------------------------------------------

@teams_bp.route("/teams/<int:team_id>/members/add", methods=["GET", "POST"])
@login_required
def team_member_add(team_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied

    existing_ids = {m.user_id for m in team.members} | {team.owner_id}
    available_users = User.query.filter(~User.id.in_(existing_ids)).order_by(User.username).all()

    if request.method == "POST":
        user_id = request.form.get("user_id", type=int)
        user = User.query.get(user_id) if user_id else None
        if not user:
            flash("Select a valid user.", "danger")
            return render_template("team_member_form.html", team=team, users=available_users, member=None)

        member = TeamMember(
            team_id=team.id,
            user_id=user.id,
            can_view=bool(request.form.get("can_view")),
            can_add=bool(request.form.get("can_add")),
            can_edit=bool(request.form.get("can_edit")),
            can_delete=bool(request.form.get("can_delete")),
        )
        db.session.add(member)
        db.session.commit()
        flash(f"'{user.username}' added to team.", "success")
        return redirect(url_for("teams.team_detail", team_id=team.id))

    return render_template("team_member_form.html", team=team, users=available_users, member=None)


@teams_bp.route("/teams/<int:team_id>/members/<int:member_id>/edit", methods=["GET", "POST"])
@login_required
def team_member_edit(team_id, member_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied

    member = TeamMember.query.get_or_404(member_id)

    if request.method == "POST":
        member.can_view = bool(request.form.get("can_view"))
        member.can_add = bool(request.form.get("can_add"))
        member.can_edit = bool(request.form.get("can_edit"))
        member.can_delete = bool(request.form.get("can_delete"))
        db.session.commit()
        flash("Member permissions updated.", "success")
        return redirect(url_for("teams.team_detail", team_id=team.id))

    return render_template("team_member_form.html", team=team, users=[], member=member)


@teams_bp.route("/teams/<int:team_id>/members/<int:member_id>/remove", methods=["POST"])
@login_required
def team_member_remove(team_id, member_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied

    member = TeamMember.query.get_or_404(member_id)
    username = member.user.username
    db.session.delete(member)
    db.session.commit()
    flash(f"'{username}' removed from team.", "success")
    return redirect(url_for("teams.team_detail", team_id=team.id))


# ---------------------------------------------------------------------------
# Team notification settings (owner or admin)
# ---------------------------------------------------------------------------

@teams_bp.route("/teams/<int:team_id>/settings", methods=["GET", "POST"])
@login_required
def team_settings(team_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied

    if request.method == "POST":
        days_raw = request.form.get("alert_days", "").strip()
        try:
            days = [int(d.strip()) for d in days_raw.split(",") if d.strip().isdigit()]
            team.alert_days = days
        except ValueError:
            flash("Invalid alert days format.", "danger")
            return render_template("team_settings.html", team=team)

        team.email_enabled = bool(request.form.get("email_enabled"))
        team.smtp_host = request.form.get("smtp_host", "").strip()
        team.smtp_port = int(request.form.get("smtp_port", 587) or 587)
        team.smtp_user = request.form.get("smtp_user", "").strip()
        team.smtp_from = request.form.get("smtp_from", "").strip()
        team.smtp_tls = bool(request.form.get("smtp_tls"))

        smtp_password = request.form.get("smtp_password", "").strip()
        if smtp_password:
            team.smtp_password = smtp_password

        recipients_raw = request.form.get("email_recipients", "").strip()
        team.email_recipients = [r.strip() for r in recipients_raw.splitlines() if r.strip()]

        team.teams_enabled = bool(request.form.get("teams_enabled"))
        team.teams_webhook_url = request.form.get("teams_webhook_url", "").strip()

        db.session.commit()
        flash("Team notification settings saved.", "success")
        return redirect(url_for("teams.team_settings", team_id=team.id))

    return render_template("team_settings.html", team=team)


@teams_bp.route("/teams/<int:team_id>/regenerate-api-key", methods=["POST"])
@login_required
def regenerate_api_key(team_id):
    team = Team.query.get_or_404(team_id)
    denied = _require_team_owner(team)
    if denied:
        return denied

    team.regenerate_api_key()
    db.session.commit()
    flash("API key regenerated.", "success")
    return redirect(url_for("teams.team_settings", team_id=team.id))
