from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..models import Certificate, Team, TeamMember, db
from ..services.cert_fetcher import fetch_cert_from_host
from ..services.cert_parser import parse_cert_file

certs_bp = Blueprint("certs", __name__)


# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------

def _user_teams_with_perm(perm):
    """Return teams where current_user has a given permission (or is owner/admin)."""
    if current_user.is_admin:
        return Team.query.all()
    owned = Team.query.filter_by(owner_id=current_user.id).all()
    memberships = TeamMember.query.filter_by(user_id=current_user.id).all()
    member_teams = [
        m.team for m in memberships if getattr(m, perm, False)
    ]
    seen = {t.id for t in owned}
    result = list(owned)
    for t in member_teams:
        if t.id not in seen:
            result.append(t)
            seen.add(t.id)
    return result


def _can_act_on_cert(cert, perm):
    """Check if current_user has a permission on a specific cert's team."""
    if current_user.is_admin:
        return True
    if current_user.is_global_admin:
        # Global admins are read-only across all teams
        return False
    if cert.team_id is None:
        # Unowned certs: only admins and the original adder can modify
        return cert.added_by_id == current_user.id
    team = cert.team
    if team.is_owner(current_user):
        return True
    member = team.get_member(current_user)
    return member is not None and getattr(member, perm, False)


def _visible_certs():
    """Return certs visible to the current user.

    Admins and global_admins see everything.
    All other users see only their team's certificates.
    """
    if current_user.can_see_all:
        return Certificate.query.order_by(Certificate.not_after.asc()).all()

    team_ids = set()
    for t in Team.query.filter_by(owner_id=current_user.id).all():
        team_ids.add(t.id)
    for m in TeamMember.query.filter_by(user_id=current_user.id).all():
        if m.can_view:
            team_ids.add(m.team_id)

    if not team_ids:
        return []

    return Certificate.query.filter(
        Certificate.team_id.in_(team_ids)
    ).order_by(Certificate.not_after.asc()).all()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@certs_bp.route("/")
@login_required
def dashboard():
    certs = _visible_certs()
    stats = {
        "total": len(certs),
        "expired": sum(1 for c in certs if c.status == "expired"),
        "critical": sum(1 for c in certs if c.status == "critical"),
        "warning": sum(1 for c in certs if c.status == "warning"),
        "ok": sum(1 for c in certs if c.status == "ok"),
    }
    return render_template("dashboard.html", certs=certs, stats=stats)


# ---------------------------------------------------------------------------
# Cert detail
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/<int:cert_id>")
@login_required
def cert_detail(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    can_edit = _can_act_on_cert(cert, "can_edit")
    can_delete = _can_act_on_cert(cert, "can_delete")
    return render_template("cert_detail.html", cert=cert, can_edit=can_edit, can_delete=can_delete)


# ---------------------------------------------------------------------------
# Add cert
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/add", methods=["GET", "POST"])
@login_required
def cert_add():
    if current_user.is_global_admin:
        flash("Global admins have read-only access.", "warning")
        return redirect(url_for("certs.dashboard"))
    addable_teams = _user_teams_with_perm("can_add")

    if request.method == "POST":
        try:
            not_after = datetime.strptime(request.form["not_after"], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            not_before_str = request.form.get("not_before", "").strip()
            not_before = None
            if not_before_str:
                not_before = datetime.strptime(not_before_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )

            sans_raw = request.form.get("sans", "").strip()
            sans_list = [s.strip() for s in sans_raw.splitlines() if s.strip()]

            team_id = request.form.get("team_id", type=int) or None
            if team_id is None and not current_user.is_admin:
                # Auto-assign to the user's only addable team
                if len(addable_teams) == 1:
                    team_id = addable_teams[0].id
                elif len(addable_teams) > 1:
                    flash("Please select a team.", "danger")
                    return render_template("cert_add.html", addable_teams=addable_teams)
                else:
                    flash("You do not have permission to add certificates to any team.", "danger")
                    return render_template("cert_add.html", addable_teams=addable_teams)

            cert = Certificate(
                common_name=request.form["common_name"].strip(),
                issuer=request.form.get("issuer", "").strip(),
                subject=request.form.get("subject", "").strip(),
                serial_number=request.form.get("serial_number", "").strip(),
                thumbprint=request.form.get("thumbprint", "").strip(),
                not_before=not_before,
                not_after=not_after,
                hostname=request.form.get("hostname", "").strip(),
                notes=request.form.get("notes", "").strip(),
                tags=request.form.get("tags", "").strip(),
                source="manual",
                team_id=team_id,
                added_by_id=current_user.id,
            )
            cert.sans = sans_list
            db.session.add(cert)
            db.session.commit()
            flash(f"Certificate '{cert.common_name}' added.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error adding certificate: {e}", "danger")

    return render_template("cert_add.html", addable_teams=addable_teams)


# ---------------------------------------------------------------------------
# Upload cert
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/upload", methods=["GET", "POST"])
@login_required
def cert_upload():
    if current_user.is_global_admin:
        flash("Global admins have read-only access.", "warning")
        return redirect(url_for("certs.dashboard"))
    addable_teams = _user_teams_with_perm("can_add")

    if request.method == "POST":
        file = request.files.get("cert_file")
        if not file or not file.filename:
            flash("No file selected.", "danger")
            return render_template("cert_upload.html", addable_teams=addable_teams)

        hostname = request.form.get("hostname", "").strip()
        notes = request.form.get("notes", "").strip()
        tags = request.form.get("tags", "").strip()
        team_id = request.form.get("team_id", type=int) or None
        if team_id is None and not current_user.is_admin:
            if len(addable_teams) == 1:
                team_id = addable_teams[0].id
            elif len(addable_teams) > 1:
                flash("Please select a team.", "danger")
                return render_template("cert_upload.html", addable_teams=addable_teams)
            else:
                flash("You do not have permission to add certificates to any team.", "danger")
                return render_template("cert_upload.html", addable_teams=addable_teams)

        try:
            cert_data = parse_cert_file(file)
            cert = Certificate(
                common_name=cert_data["common_name"],
                issuer=cert_data.get("issuer", ""),
                subject=cert_data.get("subject", ""),
                serial_number=cert_data.get("serial_number", ""),
                thumbprint=cert_data.get("thumbprint", ""),
                not_before=cert_data.get("not_before"),
                not_after=cert_data["not_after"],
                hostname=hostname or cert_data.get("hostname", ""),
                notes=notes,
                tags=tags,
                source="upload",
                team_id=team_id,
                added_by_id=current_user.id,
            )
            cert.sans = cert_data.get("sans", [])
            db.session.add(cert)
            db.session.commit()
            flash(f"Certificate '{cert.common_name}' imported.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error parsing certificate: {e}", "danger")

    return render_template("cert_upload.html", addable_teams=addable_teams)


# ---------------------------------------------------------------------------
# Fetch cert
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/fetch", methods=["GET", "POST"])
@login_required
def cert_fetch():
    if current_user.is_global_admin:
        flash("Global admins have read-only access.", "warning")
        return redirect(url_for("certs.dashboard"))
    addable_teams = _user_teams_with_perm("can_add")
    fetched = None

    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        port = int(request.form.get("port", 443) or 443)

        if not hostname:
            flash("Please enter a hostname.", "danger")
            return render_template("cert_fetch.html", fetched=None, addable_teams=addable_teams)

        try:
            cert_data = fetch_cert_from_host(hostname, port)
            fetched = cert_data
            fetched["hostname"] = hostname
            fetched["port"] = port

            if request.form.get("save"):
                notes = request.form.get("notes", "").strip()
                tags = request.form.get("tags", "").strip()
                team_id = request.form.get("team_id", type=int) or None
                if team_id is None and not current_user.is_admin:
                    if len(addable_teams) == 1:
                        team_id = addable_teams[0].id
                    elif len(addable_teams) > 1:
                        flash("Please select a team.", "danger")
                        return render_template("cert_fetch.html", fetched=fetched, addable_teams=addable_teams)
                    else:
                        flash("You do not have permission to add certificates to any team.", "danger")
                        return render_template("cert_fetch.html", fetched=fetched, addable_teams=addable_teams)
                cert = Certificate(
                    common_name=cert_data["common_name"],
                    issuer=cert_data.get("issuer", ""),
                    subject=cert_data.get("subject", ""),
                    serial_number=cert_data.get("serial_number", ""),
                    thumbprint=cert_data.get("thumbprint", ""),
                    not_before=cert_data.get("not_before"),
                    not_after=cert_data["not_after"],
                    hostname=hostname,
                    notes=notes,
                    tags=tags,
                    source="fetch",
                    team_id=team_id,
                    added_by_id=current_user.id,
                )
                cert.sans = cert_data.get("sans", [])
                db.session.add(cert)
                db.session.commit()
                flash(f"Certificate for '{hostname}' saved.", "success")
                return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error fetching certificate from '{hostname}': {e}", "danger")

    return render_template("cert_fetch.html", fetched=fetched, addable_teams=addable_teams)


# ---------------------------------------------------------------------------
# Edit cert
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/<int:cert_id>/edit", methods=["GET", "POST"])
@login_required
def cert_edit(cert_id):
    cert = Certificate.query.get_or_404(cert_id)

    if not _can_act_on_cert(cert, "can_edit"):
        flash("You do not have permission to edit this certificate.", "danger")
        return redirect(url_for("certs.cert_detail", cert_id=cert_id))

    if request.method == "POST":
        try:
            cert.common_name = request.form["common_name"].strip()
            cert.issuer = request.form.get("issuer", "").strip()
            cert.subject = request.form.get("subject", "").strip()
            cert.serial_number = request.form.get("serial_number", "").strip()
            cert.thumbprint = request.form.get("thumbprint", "").strip()
            cert.hostname = request.form.get("hostname", "").strip()
            cert.notes = request.form.get("notes", "").strip()
            cert.tags = request.form.get("tags", "").strip()

            not_after = datetime.strptime(request.form["not_after"], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            cert.not_after = not_after

            not_before_str = request.form.get("not_before", "").strip()
            if not_before_str:
                cert.not_before = datetime.strptime(not_before_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )

            sans_raw = request.form.get("sans", "").strip()
            cert.sans = [s.strip() for s in sans_raw.splitlines() if s.strip()]
            cert.alert_sent_days = []

            db.session.commit()
            flash("Certificate updated.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error updating certificate: {e}", "danger")

    return render_template("cert_edit.html", cert=cert)


# ---------------------------------------------------------------------------
# Delete cert
# ---------------------------------------------------------------------------

@certs_bp.route("/certs/<int:cert_id>/delete", methods=["POST"])
@login_required
def cert_delete(cert_id):
    cert = Certificate.query.get_or_404(cert_id)

    if not _can_act_on_cert(cert, "can_delete"):
        flash("You do not have permission to delete this certificate.", "danger")
        return redirect(url_for("certs.cert_detail", cert_id=cert_id))

    name = cert.common_name
    db.session.delete(cert)
    db.session.commit()
    flash(f"Certificate '{name}' deleted.", "success")
    return redirect(url_for("certs.dashboard"))
