from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..models import Certificate, db
from ..services.cert_fetcher import fetch_cert_from_host
from ..services.cert_parser import parse_cert_file

certs_bp = Blueprint("certs", __name__)


@certs_bp.route("/")
@login_required
def dashboard():
    certs = Certificate.query.order_by(Certificate.not_after.asc()).all()
    stats = {
        "total": len(certs),
        "expired": sum(1 for c in certs if c.status == "expired"),
        "critical": sum(1 for c in certs if c.status == "critical"),
        "warning": sum(1 for c in certs if c.status == "warning"),
        "ok": sum(1 for c in certs if c.status == "ok"),
    }
    return render_template("dashboard.html", certs=certs, stats=stats)


@certs_bp.route("/certs/<int:cert_id>")
@login_required
def cert_detail(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    return render_template("cert_detail.html", cert=cert)


@certs_bp.route("/certs/add", methods=["GET", "POST"])
@login_required
def cert_add():
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
                added_by_id=current_user.id,
            )
            cert.sans = sans_list
            db.session.add(cert)
            db.session.commit()
            flash(f"Certificate '{cert.common_name}' added.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error adding certificate: {e}", "danger")

    return render_template("cert_add.html")


@certs_bp.route("/certs/upload", methods=["GET", "POST"])
@login_required
def cert_upload():
    if request.method == "POST":
        file = request.files.get("cert_file")
        if not file or not file.filename:
            flash("No file selected.", "danger")
            return render_template("cert_upload.html")

        hostname = request.form.get("hostname", "").strip()
        notes = request.form.get("notes", "").strip()
        tags = request.form.get("tags", "").strip()

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
                added_by_id=current_user.id,
            )
            cert.sans = cert_data.get("sans", [])
            db.session.add(cert)
            db.session.commit()
            flash(f"Certificate '{cert.common_name}' imported.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error parsing certificate: {e}", "danger")

    return render_template("cert_upload.html")


@certs_bp.route("/certs/fetch", methods=["GET", "POST"])
@login_required
def cert_fetch():
    fetched = None
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        port = int(request.form.get("port", 443) or 443)

        if not hostname:
            flash("Please enter a hostname.", "danger")
            return render_template("cert_fetch.html")

        try:
            cert_data = fetch_cert_from_host(hostname, port)
            fetched = cert_data
            fetched["hostname"] = hostname
            fetched["port"] = port

            if request.form.get("save"):
                notes = request.form.get("notes", "").strip()
                tags = request.form.get("tags", "").strip()
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
                    added_by_id=current_user.id,
                )
                cert.sans = cert_data.get("sans", [])
                db.session.add(cert)
                db.session.commit()
                flash(f"Certificate for '{hostname}' saved.", "success")
                return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error fetching certificate from '{hostname}': {e}", "danger")

    return render_template("cert_fetch.html", fetched=fetched)


@certs_bp.route("/certs/<int:cert_id>/edit", methods=["GET", "POST"])
@login_required
def cert_edit(cert_id):
    cert = Certificate.query.get_or_404(cert_id)

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

            # Reset alert sent days so re-alerts can fire if thresholds are crossed again
            cert.alert_sent_days = []

            db.session.commit()
            flash("Certificate updated.", "success")
            return redirect(url_for("certs.cert_detail", cert_id=cert.id))
        except Exception as e:
            flash(f"Error updating certificate: {e}", "danger")

    return render_template("cert_edit.html", cert=cert)


@certs_bp.route("/certs/<int:cert_id>/delete", methods=["POST"])
@login_required
def cert_delete(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    name = cert.common_name
    db.session.delete(cert)
    db.session.commit()
    flash(f"Certificate '{name}' deleted.", "success")
    return redirect(url_for("certs.dashboard"))
