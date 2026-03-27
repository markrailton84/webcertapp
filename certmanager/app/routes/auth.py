from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from ..models import db, User

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
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=all_users)


@auth_bp.route("/users/add", methods=["GET", "POST"])
@login_required
def add_user():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("certs.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
        else:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f"User '{username}' created.", "success")
            return redirect(url_for("auth.users"))

    return render_template("user_form.html", action="Add")


@auth_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
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
