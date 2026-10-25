# SecureCert – Digital Certificate Verification System

SecureCert is a web-based digital certificate verification system that uses **RSA-PSS and SHA-256 digital signatures** to verify certificate authenticity and detect unauthorized modifications.

The system allows an issuer to create digital certificates, verify their signatures, demonstrate tamper detection, and manage certificate revocation.

## Features

- **Certificate Issuance:** Generate digital certificates containing recipient and institution details.
- **Digital Signature Verification:** Verify certificate signatures using RSA public-key cryptography.
- **Tamper Detection:** Detect changes to signed certificate data.
- **Certificate Revocation:** Mark certificates as revoked and check their current status.
- **QR Code Generation:** Generate QR codes for certificate verification.
- **PDF Download:** Download certificates as PDF files.
- **Admin Authentication:** Restrict certificate management to authorized administrators.
- **Audit Logging:** Maintain records of relevant system activities.
- **Automated Testing:** Test core functionality and security-related scenarios.

## Technology Stack

- **Language:** Python
- **Web Framework:** Flask
- **Database:** SQLite
- **Cryptography:** RSA-PSS, SHA-256
- **Frontend:** HTML, CSS, JavaScript
- **Additional Libraries:** QR code generation and PDF generation libraries
- **Testing:** Pytest

## Prerequisites

Install the following before running the project:

- Python 3.10 or a compatible version supported by the dependencies
- pip (Python package installer)
- Git (optional, for cloning the repository)

Check your Python installation:

```bash
python --version
python -m pip --version
```

## Installation and Setup

### 1. Clone the repository

Replace `YOUR_USERNAME` with your GitHub username.

```bash
git clone https://github.com/musafirunnisabegumsyed/SecureCert-Digital-Certificate-Verification.git
cd SecureCert-Digital-Certificate-Verification
```

Alternatively, download the repository as a ZIP file and extract it.

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use Command Prompt instead:

```bat
venv\Scripts\activate.bat
```

**macOS/Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

The application requires a secret key.

**Windows PowerShell:**

```powershell
$env:SECURECERT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:SECURECERT_ADMIN_USERNAME = "admin"
$env:SECURECERT_ADMIN_PASSWORD = "ChangeThisDemoPassword!123"
```

Replace the example administrator password with a strong password of your own.

**macOS/Linux:**

```bash
export SECURECERT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SECURECERT_ADMIN_USERNAME="admin"
export SECURECERT_ADMIN_PASSWORD="ChangeThisDemoPassword!123"
```

These environment variables apply to the current terminal session. Set them again when opening a new terminal.

### 5. Run the application

```bash
python run.py
```

Open your browser and visit:

**http://127.0.0.1:5000**

Keep the terminal running while using the application.

## Running Tests

Activate your virtual environment, ensure the dependencies are installed, and run:

```bash
python -m pytest -v
```

The test suite is intended to cover application routes, authentication, certificate issuance and verification, tampering, invalid signatures, revocation, and certificate downloads.

## How Tamper Detection Works

1. Certificate details are prepared as a payload.
2. The issuer signs the payload using an RSA private key and RSA-PSS with SHA-256.
3. During verification, the application checks the signature using the corresponding RSA public key.
4. If signed data is modified, verification should fail.
5. The application reports the invalid signature to demonstrate that tampering was detected.

The tamper demonstration modifies a copy of the certificate payload for testing. It should not modify the original stored certificate.

**Note:** Digital signatures provide integrity verification and help establish authenticity. They do not encrypt the certificate contents.

## Project Structure

```text
SecureCert-Digital-Certificate-Verification/
├── app/
│   ├── __init__.py
│   ├── templates/
│   └── static/
├── tests/
│   ├── conftest.py
│   └── test_securecert.py
├── run.py
├── requirements.txt
├── .gitignore
└── README.md
```

The exact structure may vary depending on the version of the project in your repository.

## Security Notes

- Keep private signing keys and application secrets secure.
- Do not commit passwords, secret keys, private keys, or other credentials to GitHub.
- Use a unique, strong administrator password.
- The development server is intended for local testing, not production deployment.
- Review key storage, access controls, error handling, and deployment configuration before using real certificates.

## Future Enhancements

- Deploy the application to a secure hosting platform.
- Add email notifications for certificate issuance and revocation.
- Improve key management and administrator access controls.
- Add certificate expiration and issuer management.
- Introduce additional automated security tests.

## Disclaimer

SecureCert is an educational project developed to demonstrate digital signatures, public-key cryptography, certificate verification, and tamper detection. It should not be considered a production-ready certificate authority without additional security review.

## Authors

- Syed Musafirunnisa Begum
- Parvathy Vinod Kumar
