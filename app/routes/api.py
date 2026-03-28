"""
REST API blueprint — /api/v1/

Authentication: include the API key in the X-API-Key request header.
The key is generated automatically and shown in Settings (admin only).
"""

import datetime

from flask import Blueprint, jsonify, request

from ..models import Certificate, Settings, db
from ..services.cert_fetcher import fetch_cert_from_host

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _check_api_key():
    """Return None if the request carries a valid API key, else a 401 response."""
    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        return jsonify({"error": "Missing X-API-Key header"}), 401
    settings = Settings.get()
    if key != settings.api_key:
        return jsonify({"error": "Invalid API key"}), 401
    return None


def _cert_to_dict(cert):
    return {
        "id": cert.id,
        "common_name": cert.common_name,
        "issuer": cert.issuer,
        "subject": cert.subject,
        "serial_number": cert.serial_number,
        "thumbprint": cert.thumbprint,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
        "days_remaining": cert.days_remaining,
        "status": cert.status,
        "hostname": cert.hostname,
        "sans": cert.sans,
        "tags": cert.tags,
        "notes": cert.notes,
        "source": cert.source,
        "created_at": cert.created_at.isoformat() if cert.created_at else None,
        "updated_at": cert.updated_at.isoformat() if cert.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Health check (no auth required)
# ---------------------------------------------------------------------------

@api_bp.route("/health")
def health():
    """Public health check endpoint."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Certificate queries
# ---------------------------------------------------------------------------

@api_bp.route("/certs")
def list_certs():
    """
    GET /api/v1/certs

    Query parameters:
      status   — filter by status: ok | warning | critical | expired
      tag      — filter by tag substring
      search   — search in common_name, hostname, notes
      page     — page number (default 1)
      per_page — results per page (default 50, max 200)
    """
    denied = _check_api_key()
    if denied:
        return denied

    query = Certificate.query

    status_filter = request.args.get("status")
    tag_filter = request.args.get("tag")
    search = request.args.get("search")

    if tag_filter:
        query = query.filter(Certificate.tags.ilike(f"%{tag_filter}%"))
    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(
                Certificate.common_name.ilike(like),
                Certificate.hostname.ilike(like),
                Certificate.notes.ilike(like),
            )
        )

    certs = query.order_by(Certificate.not_after.asc()).all()

    # Status filter applied in Python because status is a computed property
    if status_filter:
        certs = [c for c in certs if c.status == status_filter]

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        return jsonify({"error": "page and per_page must be integers"}), 400

    total = len(certs)
    start = (page - 1) * per_page
    certs_page = certs[start:start + per_page]

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "certs": [_cert_to_dict(c) for c in certs_page],
    })


@api_bp.route("/certs/<int:cert_id>")
def get_cert(cert_id):
    """GET /api/v1/certs/<id> — retrieve a single certificate."""
    denied = _check_api_key()
    if denied:
        return denied

    cert = db.get_or_404(Certificate, cert_id)
    return jsonify(_cert_to_dict(cert))


# ---------------------------------------------------------------------------
# Add / bulk-add certificates
# ---------------------------------------------------------------------------

def _build_cert_from_dict(data, source="api"):
    """Build a Certificate instance from a JSON dict. Returns (cert, error_str)."""
    not_after_raw = data.get("not_after")
    if not not_after_raw:
        return None, "not_after is required"

    try:
        not_after = datetime.datetime.fromisoformat(not_after_raw.replace("Z", "+00:00"))
    except ValueError:
        return None, f"not_after must be an ISO 8601 datetime, got: {not_after_raw!r}"

    common_name = data.get("common_name", "").strip()
    if not common_name:
        return None, "common_name is required"

    not_before_raw = data.get("not_before")
    not_before = None
    if not_before_raw:
        try:
            not_before = datetime.datetime.fromisoformat(not_before_raw.replace("Z", "+00:00"))
        except ValueError:
            return None, f"not_before must be ISO 8601, got: {not_before_raw!r}"

    cert = Certificate(
        common_name=common_name,
        issuer=data.get("issuer", "").strip() or None,
        subject=data.get("subject", "").strip() or None,
        serial_number=data.get("serial_number", "").strip() or None,
        thumbprint=data.get("thumbprint", "").strip() or None,
        not_before=not_before,
        not_after=not_after,
        hostname=data.get("hostname", "").strip() or None,
        notes=data.get("notes", "").strip() or None,
        tags=data.get("tags", "").strip() or None,
        source=source,
    )
    sans = data.get("sans")
    if isinstance(sans, list):
        cert.sans = sans

    return cert, None


@api_bp.route("/certs", methods=["POST"])
def add_cert():
    """
    POST /api/v1/certs

    Add a single certificate.

    JSON body fields:
      common_name  (required)
      not_after    (required, ISO 8601 datetime)
      not_before   (optional, ISO 8601 datetime)
      issuer, subject, serial_number, thumbprint
      hostname, notes, tags  (strings)
      sans         (array of strings, e.g. ["DNS:example.com"])
    """
    denied = _check_api_key()
    if denied:
        return denied

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    cert, err = _build_cert_from_dict(data)
    if err:
        return jsonify({"error": err}), 422

    db.session.add(cert)
    db.session.commit()
    return jsonify(_cert_to_dict(cert)), 201


@api_bp.route("/certs/bulk", methods=["POST"])
def bulk_add_certs():
    """
    POST /api/v1/certs/bulk

    Add multiple certificates in one request.

    JSON body: array of certificate objects (same fields as POST /certs).

    Returns a summary with created IDs and any per-item errors.
    """
    denied = _check_api_key()
    if denied:
        return denied

    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Request body must be a JSON array"}), 400
    if not data:
        return jsonify({"error": "Array must not be empty"}), 400
    if len(data) > 500:
        return jsonify({"error": "Maximum 500 certificates per bulk request"}), 400

    created = []
    errors = []

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append({"index": idx, "error": "Item must be a JSON object"})
            continue
        cert, err = _build_cert_from_dict(item)
        if err:
            errors.append({"index": idx, "common_name": item.get("common_name"), "error": err})
            continue
        db.session.add(cert)
        created.append(cert)

    if created:
        db.session.commit()

    return jsonify({
        "created": len(created),
        "errors": len(errors),
        "ids": [c.id for c in created],
        "error_details": errors,
    }), 207 if errors else 201


# ---------------------------------------------------------------------------
# Fetch certificate from hostname
# ---------------------------------------------------------------------------

@api_bp.route("/certs/fetch", methods=["POST"])
def fetch_cert():
    """
    POST /api/v1/certs/fetch

    Fetch a certificate from a live hostname via TLS and save it.

    JSON body:
      hostname  (required) — e.g. "example.com" or "example.com:8443"
      port      (optional, default 443)
      save      (optional bool, default true) — set false to preview without saving
      tags      (optional string)
      notes     (optional string)
    """
    denied = _check_api_key()
    if denied:
        return denied

    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "").strip()
    if not hostname:
        return jsonify({"error": "hostname is required"}), 400

    port = data.get("port", 443)
    try:
        port = int(port)
    except (TypeError, ValueError):
        return jsonify({"error": "port must be an integer"}), 400

    save = data.get("save", True)

    try:
        cert_data = fetch_cert_from_host(hostname, port=port)
    except Exception as exc:
        return jsonify({"error": f"Failed to fetch certificate: {exc}"}), 502

    if not save:
        return jsonify({"fetched": cert_data})

    cert = Certificate(
        common_name=cert_data.get("common_name", hostname),
        issuer=cert_data.get("issuer"),
        subject=cert_data.get("subject"),
        serial_number=cert_data.get("serial_number"),
        thumbprint=cert_data.get("thumbprint"),
        not_before=cert_data.get("not_before"),
        not_after=cert_data.get("not_after"),
        hostname=hostname,
        tags=data.get("tags", "").strip() or None,
        notes=data.get("notes", "").strip() or None,
        source="fetch",
    )
    sans = cert_data.get("sans")
    if isinstance(sans, list):
        cert.sans = sans

    db.session.add(cert)
    db.session.commit()
    return jsonify(_cert_to_dict(cert)), 201


# ---------------------------------------------------------------------------
# Delete certificate
# ---------------------------------------------------------------------------

@api_bp.route("/certs/<int:cert_id>", methods=["DELETE"])
def delete_cert(cert_id):
    """DELETE /api/v1/certs/<id> — remove a certificate."""
    denied = _check_api_key()
    if denied:
        return denied

    cert = db.get_or_404(Certificate, cert_id)
    db.session.delete(cert)
    db.session.commit()
    return jsonify({"deleted": cert_id}), 200
