# Vault Auth Backend

A Flask and PostgreSQL authentication and user management API service.

---

## Features
- **Authentication**: User registration and login with secure password hashing (`werkzeug.security`).
- **Session Tokens**: Time-limited session tokens with expiry verification.
- **PostgreSQL Database**: Configured via direct parameters or connection URL (`DATABASE_URL`, e.g., Supabase).
- **OpenAPI 3.0 Documentation**: Spec served at `/openapi.json` and interactive Swagger UI at `/docs`.
- **Automated Test Suite**: 28 unit and integration tests powered by `pytest`.

---

## Getting Started

### 1. Prerequisites
- Python 3.10+
- PostgreSQL (local instance or cloud database like Supabase)

### 2. Environment Setup
Create or customize the `.env` file in the project root:

```env
# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
SERVER_DEBUG=True

# Tokens & Secrets
SECRET_KEY=your-secret-key-change-in-production
TOKEN_SECRET=your-token-secret-change-in-production
TOKEN_EXPIRATION=3600

# Database
DB_USER=postgres
DB_PASS=postgres
DB_HOST=localhost
DB_PORT=5432
DB_NAME=postgres
DB_SSLMODE=prefer

# Or provide a single connection string:
# DATABASE_URL=postgresql://user:pass@localhost:5432/postgres

# Real Gmail SMTP for OTP Delivery
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-16-char-app-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
```

### 3. Install Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Run the Server
```bash
python main.py
```
The server will start on [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## API Documentation & Swagger UI
- **Interactive Swagger UI**: [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs)
- **OpenAPI 3.0 JSON**: [http://127.0.0.1:5000/openapi.json](http://127.0.0.1:5000/openapi.json)
- **Local Specification Files**: [`openapi.json`](openapi.json) and [`openapi.yaml`](openapi.yaml)

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check endpoint returning backend status |
| `POST` | `/api/register` | Register a new user (`username`, `password`, `email`) |
| `POST` | `/api/login` | Authenticate with password and obtain session token |
| `POST` | `/api/otp/send` | Request 6-digit OTP for passwordless login (`identifier`) |
| `POST` | `/api/otp/verify` | Verify OTP code and obtain session token (`identifier`, `otp`) |
| `GET`/`POST` | `/api/verify` | Verify active session token |
| `POST` | `/api/logout` | Terminate session and clear cookies |
| `GET` | `/api/users` | List all registered users |
| `GET` | `/api/users/<uid>` | Lookup user by numeric UID |
| `GET` | `/api/users/<id>` | Lookup user by username or email |
| `GET` | `/openapi.json` | OpenAPI 3.0 specification |
| `GET` | `/docs` | Interactive Swagger UI documentation |

---

## Testing
Run the automated test suite with pytest:

```bash
pytest
```
