from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ..models import Team, TeamMember, User, db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("certs.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get("next")
            if next_page:
                parsed = urlparse(next_page)
                if parsed.netloc or parsed.scheme:
                    next_page = None
            return redirect(next_page or url_for("certs.dashboard"))
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/users")
@login_required
def users():
    if not current_user.is_manager:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))
    all_users = User.query.order_by(User.created_at.desc()).all()

    # Build a map of user_id -> list of (team, membership) for display
    memberships = TeamMember.query.all()
    owned_teams = Team.query.all()

    user_teams = {}
    for team in owned_teams:
        user_teams.setdefault(team.owner_id, []).append({"team": team, "role": "owner"})
    for m in memberships:
        user_teams.setdefault(m.user_id, []).append({"team": m.team, "role": "member", "member": m})

    return render_template("users.html", users=all_users, user_teams=user_teams)


@auth_bp.route("/users/add", methods=["GET", "POST"])
@login_required
def add_user():
    if not current_user.is_manager:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    teams = Team.query.order_by(Team.name).all()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        team_id = request.form.get("team_id", type=int) or None

        requires_team = role == "user"
        if requires_team and not team_id:
            flash("A team must be selected for User role.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
        else:
            team = Team.query.get(team_id)
            if not team:
                flash("Selected team does not exist.", "danger")
            else:
                user = User(username=username, email=email, role=role)
                user.set_password(password)
                db.session.add(user)
                db.session.flush()  # get user.id before commit

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
                flash(f"User '{username}' created and added to '{team.name}'.", "success")
                return redirect(url_for("auth.users"))

    return render_template("user_form.html", action="Add", teams=teams)


@auth_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_manager:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot delete your own account.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' deleted.", "success")
    return redirect(url_for("auth.users"))
