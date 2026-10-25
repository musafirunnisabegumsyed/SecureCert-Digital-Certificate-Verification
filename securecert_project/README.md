# SecureCert — RSA Certificate Verification

A student mini-project demonstrating RSA-PSS/SHA-256 signatures, certificate issuance, public verification, tamper detection, and revocation.

## 1. Use with your existing project

Back up your current `app` folder and `run.py` first. This starter preserves the application-factory shape: `from app import create_app` and `app = create_app()`.

## 2. Install (Windows PowerShell)

```powershell
# Activate your existing virtual environment first
.\venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt

# Generate a session secret for this PowerShell session
$env:SECURECERT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"

# Optional: configure the first admin account (recommended)
$env:SECURECERT_ADMIN_USERNAME = "admin"
$env:SECURECERT_ADMIN_PASSWORD = "ChangeThisDemoPassword!123"

python run.py
```

Open http://127.0.0.1:5000. The app creates an SQLite database and RSA issuer key pair on first run. Keep `instance/` private and do not commit it.

If no admin variables are set, first-run setup uses `admin` / `ChangeMeNow!123`. Change these immediately and never use demo credentials for deployment.

## 3. Run automated tests

```powershell
python -m pytest -v
```

Tests use a temporary database and temporary RSA key directory. They do not test the production database.

## 4. Main features

- Admin login; password hashes are stored using Werkzeug's password hashing.
- Create certificate records signed using RSA-PSS with SHA-256 and a 2048-bit RSA key.
- Public verification by certificate ID.
- Tamper demonstration that modifies a copy of the signed payload and verifies that signature validation fails.
- Admin-only revocation; a valid signature does not override a revoked status.
- QR code for each verification URL.
- PDF certificate download.
- SQLite audit events for issue/revoke operations.

## Security notes

This is an educational local prototype, not a production-ready certificate authority. Protect the private key and database, deploy only behind HTTPS, configure secure cookies and rate limiting, rotate credentials, and obtain a security review before real use. The first-run admin password is only a convenience for local demonstrations. RSA signatures prove integrity and possession of the corresponding private key; they do not encrypt certificate data.
