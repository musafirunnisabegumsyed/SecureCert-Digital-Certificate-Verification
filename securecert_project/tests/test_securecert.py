import base64
import json
from app import canonical_payload, sign_payload, verify_signature
from cryptography.hazmat.primitives.asymmetric import rsa

def test_rsa_signature_verifies_and_tampering_fails():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = {"certificate_id": "SC-TEST01", "recipient": "Asha"}
    signature = base64.b64encode(sign_payload(private, payload)).decode()
    assert verify_signature(private.public_key(), payload, signature) is True
    modified = {**payload, "recipient": "Someone Else"}
    assert verify_signature(private.public_key(), modified, signature) is False

def test_signature_rejects_wrong_key():
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = {"certificate_id": "SC-TEST02"}
    signature = base64.b64encode(sign_payload(signer, payload)).decode()
    assert verify_signature(other.public_key(), payload, signature) is False

def test_home_and_health_endpoints(client):
    assert client.get("/").status_code == 200
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"

def test_admin_routes_require_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    response = client.get("/issue")
    assert response.status_code == 302

def test_issue_and_public_verification(admin_client):
    response = admin_client.post("/issue", data={
        "recipient": "Asha Kumar",
        "institution": "Example Institute",
        "title": "Completion Certificate",
        "issue_date": "2026-10-25",
    }, follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["Location"]
    cert_id = location.rstrip("/").split("/")[-1]
    verified = admin_client.get(f"/api/verify/{cert_id}")
    assert verified.status_code == 200
    assert verified.json["status"] == "valid"
    assert verified.json["signature_valid"] is True

def test_unknown_certificate_is_not_found(client):
    response = client.get("/api/verify/SC-DOESNOTEXIST")
    assert response.status_code == 404
    assert response.json["status"] == "not_found"

def test_revoked_certificate_stays_cryptographically_signed_but_not_valid(admin_client):
    issued = admin_client.post("/issue", data={
        "recipient": "Demo User", "institution": "Demo Institute",
        "title": "Demo Award", "issue_date": "2026-10-25"
    })
    assert issued.status_code == 302
    cert_id = issued.headers["Location"].rstrip("/").split("/")[-1]
    revoked = admin_client.post(f"/certificate/{cert_id}/revoke",
                                data={"reason": "Test revocation"})
    assert revoked.status_code == 302
    result = admin_client.get(f"/api/verify/{cert_id}")
    assert result.status_code == 200
    assert result.json["status"] == "revoked"
    assert result.json["signature_valid"] is True

def test_issue_rejects_missing_fields(admin_client):
    response = admin_client.post("/issue", data={"recipient": "", "institution": "", "title": ""})
    assert response.status_code == 200
    assert b"Enter recipient" in response.data

def test_pdf_and_qr_downloads(admin_client):
    response = admin_client.post("/issue", data={
        "recipient": "Demo User", "institution": "Demo Institute",
        "title": "Demo Award", "issue_date": "2026-10-25"
    })
    cert_id = response.headers["Location"].rstrip("/").split("/")[-1]
    pdf = admin_client.get(f"/certificate/{cert_id}/download.pdf")
    qr = admin_client.get(f"/certificate/{cert_id}/qr.png")
    assert pdf.status_code == 200 and pdf.mimetype == "application/pdf"
    assert qr.status_code == 200 and qr.mimetype == "image/png"
