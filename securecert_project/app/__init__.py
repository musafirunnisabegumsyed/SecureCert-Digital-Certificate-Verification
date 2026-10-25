import base64
import io
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import qrcode
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from reportlab.lib.pagesizes import landscape, letter
from reportlab.pdfgen import canvas


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_payload(data):
    """Stable UTF-8 JSON bytes used for both signing and verification."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(private_key, payload):
    return private_key.sign(
        canonical_payload(payload),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key, payload, signature_b64):
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(
            signature, canonical_payload(payload),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    secret = os.environ.get("SECURECERT_SECRET_KEY")
    if not secret and not (test_config and test_config.get("TESTING")):
        raise RuntimeError("Set the SECURECERT_SECRET_KEY environment variable first.")
    app.config.from_mapping(
        SECRET_KEY=secret or "test-only-secret-not-for-production",
        DATABASE=os.path.join(app.instance_path, "securecert.sqlite3"),
        KEY_DIR=os.path.join(app.instance_path, "keys"),
        PUBLIC_BASE_URL=os.environ.get("SECURECERT_PUBLIC_BASE_URL", "http://127.0.0.1:5000"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["KEY_DIR"]).mkdir(parents=True, exist_ok=True)

    def db():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def load_private_key():
        path = Path(app.config["KEY_DIR"]) / "issuer_private.pem"
        if not path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    def load_public_key():
        path = Path(app.config["KEY_DIR"]) / "issuer_public.pem"
        if not path.exists():
            private = load_private_key()
            path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        return serialization.load_pem_public_key(path.read_bytes())

    def init_db():
        with db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin'
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
                    signature TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL,
                    certificate_id TEXT, created_at TEXT NOT NULL, detail TEXT
                );
            """)
            username = os.environ.get("SECURECERT_ADMIN_USERNAME", "admin")
            password = os.environ.get("SECURECERT_ADMIN_PASSWORD", "ChangeMeNow!123")
            existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not existing:
                conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                             (username, generate_password_hash(password), "admin"))
        load_private_key()
        load_public_key()

    init_db()

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def audit(event, cert_id=None, detail=None):
        with db() as conn:
            conn.execute("INSERT INTO audit_logs(event,certificate_id,created_at,detail) VALUES(?,?,?,?)",
                         (event, cert_id, utcnow(), detail))

    def get_cert(cert_id):
        with db() as conn:
            row = conn.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
        return row

    def cert_status(row):
        if row is None:
            return "not_found", False
        try:
            payload = json.loads(row["payload_json"])
            valid = verify_signature(load_public_key(), payload, row["signature"])
        except (ValueError, TypeError, json.JSONDecodeError):
            valid = False
        if row["status"] == "revoked":
            return "revoked", valid
        return ("valid" if valid else "invalid"), valid

    @app.context_processor
    def inject_globals():
        return {"brand": "SecureCert"}

    @app.get("/")
    def index():
        with db() as conn:
            stats = {
                "issued": conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0],
                "active": conn.execute("SELECT COUNT(*) FROM certificates WHERE status='active'").fetchone()[0],
                "revoked": conn.execute("SELECT COUNT(*) FROM certificates WHERE status='revoked'").fetchone()[0],
            }
        return render_template("index.html", stats=stats)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            with db() as conn:
                user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        with db() as conn:
            certs = conn.execute("SELECT * FROM certificates ORDER BY created_at DESC").fetchall()
        return render_template("dashboard.html", certs=certs)

    @app.route("/issue", methods=["GET", "POST"])
    @login_required
    def issue():
        if request.method == "POST":
            recipient = request.form.get("recipient", "").strip()
            institution = request.form.get("institution", "").strip()
            title = request.form.get("title", "").strip()
            issue_date = request.form.get("issue_date", "").strip() or utcnow()[:10]
            if not all([recipient, institution, title]) or any(len(x) > 180 for x in [recipient, institution, title]):
                flash("Enter recipient, institution, and certificate title (maximum 180 characters each).", "error")
                return render_template("issue.html")
            cert_id = "SC-" + secrets.token_hex(5).upper()
            payload = {
                "certificate_id": cert_id,
                "recipient": recipient,
                "institution": institution,
                "title": title,
                "issue_date": issue_date,
                "issuer": "SecureCert Demo Issuer",
            }
            signature = base64.b64encode(sign_payload(load_private_key(), payload)).decode("ascii")
            with db() as conn:
                conn.execute("INSERT INTO certificates(id,payload_json,signature,status,created_at) VALUES(?,?,?,?,?)",
                             (cert_id, json.dumps(payload, sort_keys=True), signature, "active", utcnow()))
            audit("certificate_issued", cert_id, "Issued by " + session.get("username", "admin"))
            flash("Certificate issued and digitally signed.", "success")
            return redirect(url_for("certificate", cert_id=cert_id))
        return render_template("issue.html")

    @app.get("/certificate/<cert_id>")
    def certificate(cert_id):
        row = get_cert(cert_id)
        if row is None:
            abort(404)
        payload = json.loads(row["payload_json"])
        status, signature_valid = cert_status(row)
        return render_template("certificate.html", cert=row, payload=payload,
                               status=status, signature_valid=signature_valid)

    @app.route("/verify", methods=["GET", "POST"])
    def verify_page():
        cert_id = (request.values.get("certificate_id") or "").strip()
        result = None
        payload = None
        if cert_id:
            row = get_cert(cert_id)
            status, signature_valid = cert_status(row)
            if row:
                payload = json.loads(row["payload_json"])
            result = {"status": status, "signature_valid": signature_valid, "cert_id": cert_id}
        return render_template("verify.html", result=result, payload=payload, cert_id=cert_id)

    @app.get("/api/verify/<cert_id>")
    def api_verify(cert_id):
        row = get_cert(cert_id)
        status, signature_valid = cert_status(row)
        if row is None:
            return {"certificate_id": cert_id, "status": "not_found", "signature_valid": False}, 404
        return {
            "certificate_id": cert_id,
            "status": status,
            "signature_valid": signature_valid,
            "payload": json.loads(row["payload_json"]),
            "revoked_at": row["revoked_at"],
            "revocation_reason": row["revoke_reason"],
        }

    @app.post("/certificate/<cert_id>/revoke")
    @login_required
    def revoke(cert_id):
        reason = request.form.get("reason", "").strip()
        row = get_cert(cert_id)
        if row is None:
            abort(404)
        if not reason or len(reason) > 500:
            flash("Provide a revocation reason (maximum 500 characters).", "error")
        elif row["status"] == "revoked":
            flash("This certificate is already revoked.", "error")
        else:
            with db() as conn:
                conn.execute("UPDATE certificates SET status='revoked',revoked_at=?,revoke_reason=? WHERE id=?",
                             (utcnow(), reason, cert_id))
            audit("certificate_revoked", cert_id, reason)
            flash("Certificate revoked. Future public verification will show REVOKED.", "success")
        return redirect(url_for("certificate", cert_id=cert_id))

    @app.post("/certificate/<cert_id>/tamper-demo")
    @login_required
    def tamper_demo(cert_id):
        row = get_cert(cert_id)
        if row is None:
            abort(404)
        payload = json.loads(row["payload_json"])
        payload["recipient"] = payload.get("recipient", "") + " [TAMPERED]"
        tampered_valid = verify_signature(load_public_key(), payload, row["signature"])
        return render_template("tamper.html", cert=row, payload=payload, tampered_valid=tampered_valid)

    @app.get("/certificate/<cert_id>/qr.png")
    def qr_code(cert_id):
        if get_cert(cert_id) is None:
            abort(404)
        target = app.config["PUBLIC_BASE_URL"].rstrip("/") + url_for("verify_page", certificate_id=cert_id)
        img = qrcode.make(target)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return send_file(buffer, mimetype="image/png", download_name=f"{cert_id}-qr.png")

    @app.get("/certificate/<cert_id>/download.pdf")
    def download_pdf(cert_id):
        row = get_cert(cert_id)
        if row is None:
            abort(404)
        payload = json.loads(row["payload_json"])
        status, signature_valid = cert_status(row)
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=landscape(letter))
        width, height = landscape(letter)
        pdf.setStrokeColorRGB(0.05, 0.55, 0.72)
        pdf.setLineWidth(4)
        pdf.rect(24, 24, width-48, height-48)
        pdf.setFillColorRGB(0.05, 0.12, 0.22)
        pdf.setFont("Helvetica-Bold", 26)
        pdf.drawCentredString(width/2, height-100, "CERTIFICATE OF ACHIEVEMENT")
        pdf.setFont("Helvetica", 13)
        pdf.drawCentredString(width/2, height-145, "This certificate is presented to")
        pdf.setFont("Helvetica-Bold", 23)
        pdf.drawCentredString(width/2, height-185, payload["recipient"][:80])
        pdf.setFont("Helvetica", 13)
        pdf.drawCentredString(width/2, height-220, f'for {payload["title"][:100]}')
        pdf.drawCentredString(width/2, height-245, f'Issued by {payload["institution"][:100]}')
        pdf.setFont("Helvetica", 10)
        pdf.drawString(50, 55, f'ID: {cert_id} | Issued: {payload["issue_date"]} | Status: {status.upper()}')
        pdf.drawRightString(width-50, 55, "Verify online using the certificate ID / QR code")
        pdf.save()
        buffer.seek(0)
        return send_file(buffer, mimetype="application/pdf", as_attachment=True,
                         download_name=f"{cert_id}.pdf")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "SecureCert"}

    return app
