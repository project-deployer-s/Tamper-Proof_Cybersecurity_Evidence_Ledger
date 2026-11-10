# 🔐 Tamper-Proof Cybersecurity Evidence Ledger

<h1 align="center">🔐 Tamper-Proof Cybersecurity Evidence Ledger</h1>

<p align="center">
  <strong>Secure Messaging. Digital Signatures. Verifiable Evidence.</strong>
</p>

<p align="center">
  A cybersecurity application that protects digital messages using cryptographic signatures and maintains a tamper-evident, hash-chained evidence ledger.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Framework-Flask-black?logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/Cryptography-ECDSA%20%7C%20SHA--256-green" alt="Cryptography">
  <img src="https://img.shields.io/badge/Database-PostgreSQL-blue?logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Tests-Pytest-orange?logo=pytest" alt="Pytest">
</p>

---

## 🚀 Overview

**Tamper-Proof Cybersecurity Evidence Ledger** is a secure messaging and evidence-tracking application designed to ensure that digital messages remain authentic, unchanged, and verifiable.

The application uses **ECDSA P-256 digital signatures with SHA-256 hashing** to verify message authenticity and integrity.

Every sending and verification event is recorded in an append-only, hash-chained ledger, making unauthorized modifications detectable.

Whether a message is altered, forged, replayed, expired, or signed using a revoked key, the system identifies the issue and generates an appropriate security alert.

### ✨ Key Features

- 🔑 **Digital Signatures:** Uses ECDSA P-256 to digitally sign messages.
- 🛡️ **Message Integrity:** Detects unauthorized changes to message content.
- 🔒 **Private Key Protection:** Private signing keys remain in the user's browser and never leave the device.
- ⛓️ **Tamper-Evident Ledger:** Every send and verification event is recorded in a SHA-256 hash chain.
- 🚨 **Security Alerts:** Failed verification attempts generate security alerts.
- 🔁 **Replay Attack Detection:** Identifies repeated submissions of previously processed messages.
- ⏳ **Message Expiration:** Rejects messages that exceed their validity period.
- 🚫 **Key Revocation:** Prevents verification using revoked signing keys.
- 🧪 **Attack Simulation:** Demonstrates common cybersecurity attacks.
- 🌐 **Web-Based Interface:** Provides an easy-to-use messaging and verification dashboard.

---

## ⚙️ How It Works

The application follows a secure message lifecycle.

1. **Account Creation:** Sender and receiver register and generate their signing keys.
2. **Message Signing:** The sender writes a message, which is digitally signed in the browser.
3. **Secure Transmission:** The signed message is sent to the receiver.
4. **Message Verification:** The receiver checks the digital signature, message integrity, timestamp, and key status.
5. **Ledger Recording:** Sending and verification events are added to the hash-chained ledger.
6. **Security Monitoring:** Failed verification attempts trigger alerts, while ledger verification detects unauthorized modifications.

### 🔄 System Workflow

```text
              SENDER
                 |
                 v
          Write a Message
                 |
                 v
         ECDSA P-256 Signing
                 |
                 v
          Send Signed Message
                 |
                 v
              RECEIVER
                 |
                 v
          Verify Signature
                 |
           +-----+-----+
           |           |
         Valid       Invalid
           |           |
           v           v
         Genuine     Alert Raised
           |           |
           +-----+-----+
                 |
                 v
          Record Ledger Event
                 |
                 v
          Hash Chain Verification
                 |
                 v
         Integrity Status Report
```

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Cryptography | ECDSA P-256, SHA-256 |
| Frontend | HTML, CSS, JavaScript |
| Database | PostgreSQL, SQLAlchemy |
| Database Migrations | Flask-Migrate |
| Automated Testing | Pytest |
| Deployment | Render |
| External Ledger Anchor | Supabase |
| Rate Limiting | Redis (Optional) |

---

## 📸 Application Pages

| Page | Description |
|---|---|
| `/` | Register, sign in, and create a signing key |
| `/send.html` | Sign and send secure messages |
| `/inbox.html` | Receive messages and verify authenticity |
| `/ledger.html` | View the hash chain, check integrity, and inspect alerts |
| `/demo.html` | Simulate cybersecurity attacks (Admin only) |
| `/health` | Application health check |

---

## 💻 Installation & Local Setup

Follow these steps to run the project on your local machine.

### 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd <PROJECT_FOLDER>
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate the environment:

**Windows**

```bash
.venv\Scripts\activate
```

**macOS / Linux**

```bash
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create your environment file.

**Windows**

```bash
copy .env.example .env
```

**macOS / Linux**

```bash
cp .env.example .env
```

Open `.env` and configure your `SECRET_KEY` and other required settings.

### 5. Initialize the Database

```bash
flask --app wsgi db upgrade
```

### 6. Start the Application

```bash
flask --app wsgi run
```

Open your browser and visit:

**http://127.0.0.1:5000**

### 7. Run Automated Tests

```bash
python -m pytest
```

> **Important:** Start the application using `wsgi.py`. The `app/` package contains the application. The old top-level `app.py` is not used.

---

## ☁️ Deployment on Render

The application can be deployed using [Render](https://render.com/).

Configure the following settings:

| Setting | Value |
|---|---|
| Build Command | `pip install -r requirements.txt && flask --app wsgi db upgrade` |
| Start Command | `gunicorn wsgi:app` |
| Health Check Path | `/health` |

### Environment Variables

Configure the following environment variables in your Render dashboard.

| Variable | Description |
|---|---|
| `FLASK_ENV` | Set to `production` |
| `SECRET_KEY` | Strong secret containing at least 64 random characters |
| `DATABASE_URL` | Render PostgreSQL connection URL |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_SECRET_KEY` | Supabase secret key |
| `REDIS_URL` | Optional Redis connection for shared rate limiting |

### Deployment Notes

- Supabase anchor settings are required for the ledger's external anchor verification.
- Without the Supabase settings, the **Check the Chain** operation reports a failed check.
- If Redis is not configured, rate limiting uses in-memory storage.
- Keep production secrets in Render environment variables. Never commit them to GitHub.

---

## 🧪 Security Attack Demonstration

The application includes an administrator-only attack demonstration page to showcase how the system responds to different security threats.

| Attack Scenario | Expected Result |
|---|---|
| Message Tampering | Tampered |
| Forged Digital Signature | Invalid Signature |
| Replay Attack | Replay Detected |
| Expired Message | Expired |
| Revoked Signing Key | Revoked Key |
| Ledger Modification | Chain Integrity Failure |

### 🎯 5-Minute Live Demonstration

Follow these steps to demonstrate the application's functionality.

**Step 1 – Create Users**

- Open the application.
- Register two accounts: `alice` and `bob`.
- Let both users generate their signing keys.

**Step 2 – Send a Secure Message**

- Log in as `alice`.
- Send the message: `Hello Bob`.

**Step 3 – Verify the Message**

- Log in as `bob`.
- Open the inbox.
- Check the received message.

**Expected Result:**

✅ **Genuine** – The digital signature is valid, and the message has not been altered.

**Step 4 – Demonstrate Security Attacks**

- Log in using the administrator account.
- Open the Attack Demo page.
- Run the following demonstrations:
  - Message tampering
  - Forged signature
  - Replay attack
  - Expired message
  - Revoked signing key

**Step 5 – Verify the Evidence Ledger**

- Open the Ledger page.
- Click **Check the Chain**.
- Confirm that the ledger is valid.
- Run the ledger-tampering demonstration.
- Check the chain again.
- Observe how the system identifies the first broken entry.

**Step 6 – Explain the Security Limitation**

Explain that the ledger is tamper-evident, not absolutely tamper-proof.

If an attacker can rewrite the entire database and the external anchor together, the system cannot independently detect that coordinated modification.

---

## ✅ Test Cases

The following test cases evaluate the application's security and functionality.

| # | Test Scenario | Expected Result |
|---|---|---|
| 1 | Register with a short password | Error displayed; account not created |
| 2 | Send and verify a message | Genuine; `SENT` and `VERIFIED` ledger entries |
| 3 | Modify message text after sending | Tampered; security alert generated |
| 4 | Modify text and rewrite its hash | Invalid Signature |
| 5 | Submit the same message twice | Replay Detected |
| 6 | Submit a message with an old timestamp | Expired |
| 7 | Revoke the sender's signing key | Revoked Key |
| 8 | Edit a ledger entry directly in the database | First broken entry identified |
| 9 | Send non-English text or emoji | Genuine; browser and server agree on canonical JSON |
| 10 | Send a message containing `<script>` | Displayed as text; script never executes |

### Run Tests

Execute the following command to run the automated test suite:

```bash
python -m pytest
```

---

## 🔐 Security Architecture & Limitations

The application's security is built around three main principles.

### 1. Authenticity

ECDSA P-256 digital signatures allow the receiver to verify that a message was signed using the corresponding private key.

### 2. Integrity

SHA-256 hashing and signature verification help detect unauthorized modifications to message content.

### 3. Auditability

The append-only, hash-chained ledger links recorded events together, allowing modifications to existing entries to be detected through chain verification.

### Important Security Considerations

- Private signing keys remain in the browser and are never transmitted to the server.
- Users should securely back up their private keys using the provided download option.
- Losing a private key requires the account to generate a new signing key.
- The hash chain provides tamper evidence, not absolute protection against an attacker who controls both the database and the external anchor.
- External anchoring provides an additional integrity reference but does not eliminate every possible attack.

---

## 📂 Project Structure

```text
project/
│
├── app/
│   ├── Application modules
│   ├── Routes
│   ├── Models
│   └── Templates and static assets
│
├── migrations/
│   └── Database migration files
│
├── tests/
│   └── Automated test cases
│
├── .env.example
├── requirements.txt
├── wsgi.py
└── README.md
```

*Note: This is a simplified project structure. Actual module names may differ.*

---

## 🎓 Project Purpose

This project demonstrates how cryptographic techniques can be applied to secure digital communication and maintain trustworthy digital evidence.

It combines digital signatures, message verification, attack detection, and hash-chain auditing into one practical cybersecurity application.

The project aims to demonstrate how digital communication can become more trustworthy through cryptographic verification and tamper-evident record keeping.

---

<p align="center">
  <strong>🔐 Secure Communication | Cryptographic Verification | Tamper-Evident Evidence</strong>
</p>

<p align="center">
  Built as a Cybersecurity Project.
</p>
