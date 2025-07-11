# Secure FastAPI Authentication System

A robust, production-ready authentication and user management backend built with FastAPI, featuring modern security best practices, JWT authentication, Redis-based token blocklisting, and secure password reset via email.

---

## Features

- **User Registration & Login**  
  Secure user registration and login with strong password validation and hashing.

- **JWT Authentication**  
  - Access and refresh tokens using industry-standard JWTs.
  - Tokens are signed with a strong secret and have configurable expiry.

- **Token Revocation (Logout) with Redis**  
  - On logout, tokens are blocklisted in Redis, preventing reuse until expiry.
  - No in-memory blocklist: scalable and production-ready.

- **Role-Based Access Control**  
  - User roles (`user`, `admin`) with admin-only endpoints for user management.

- **Password Reset via Email**  
  - Secure, time-limited password reset tokens.
  - Email sent via SMTP with a reset link (configurable).

- **Input Validation & Sanitization**  
  - All user input is validated and sanitized using Pydantic.
  - Strong password and username requirements.

- **Database Security**  
  - SQLAlchemy ORM with parameterized queries to prevent SQL injection.
  - Unique constraints on email and username.

- **Environment-Based Configuration**  
  - All secrets, SMTP, and Redis settings are loaded from environment variables or `.env` file.

- **CORS & Security Headers**  
  - CORS enabled for frontend integration.
  - (Optional) Security headers middleware for HTTP responses.

- **Error Handling**  
  - Custom exception handler to avoid leaking sensitive information.

---

## Security Highlights

- **Password Hashing:**  
  All passwords are hashed using `bcrypt` before storage. Plain-text passwords are never saved.

- **JWT Security:**  
  - Tokens are signed with a strong, secret key.
  - Each token has a unique identifier (`jti`) and expiry.
  - Blocklisted tokens are stored in Redis and checked on every request.

- **Token Blocklisting:**  
  - On logout, the token's `jti` is stored in Redis with an expiry matching the token's remaining lifetime.
  - Prevents reuse of tokens after logout, even if stolen.

- **Password Reset Security:**  
  - Password reset tokens are generated with a separate secret and are time-limited.
  - Reset links are sent via email, and the API never reveals if an email exists (prevents enumeration).

- **Input Validation:**  
  - Usernames must be alphanumeric.
  - Passwords must be at least 8 characters and include a special character.
  - Emails are validated for proper format.

- **Role-Based Access:**  
  - Admin-only endpoints are protected and return 403 for non-admins.

- **Environment Secrets:**  
  - All secrets and credentials are loaded from environment variables or a `.env` file, never hardcoded.

---

## Project Structure

```
app/
  ├── auth/
  │   ├── blocklist.py      # Redis-based JWT blocklist
  │   ├── routes.py         # Auth endpoints (register, login, logout, etc.)
  │   └── utils.py          # Auth utilities (hashing, token creation, etc.)
  ├── users/
  │   └── routes.py         # Admin user management endpoints
  ├── health/
  │   └── routes.py         # Health check endpoint
  ├── config.py             # Centralized configuration
  ├── database.py           # SQLAlchemy setup
  ├── models.py             # ORM models
  ├── schemas.py            # Pydantic schemas
  └── main.py               # FastAPI app entry point
requirements.txt
.env.example                 # Example environment config
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd <project-directory>
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Environment Variables

Create a `.env` file in the root directory (see `.env.example`):

```
SECRET_KEY=your_strong_jwt_secret
PASSWORD_RESET_TOKEN_SECRET=your_password_reset_secret
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_email_password
EMAIL_FROM=your_email@gmail.com
EMAIL_FROM_NAME=Secure App
```

### 4. Run Redis

Make sure you have a Redis server running locally or update the config for your environment.

### 5. Start the Application

```bash
uvicorn app.main:app --reload
```

---

## API Endpoints

- `POST /auth/register` — Register a new user
- `POST /auth/login` — Login and receive JWT tokens
- `POST /auth/logout` — Logout and revoke the current token
- `POST /auth/refresh` — Refresh access token using a refresh token
- `GET /auth/me` — Get current user info
- `POST /auth/forgot-password` — Request password reset (email sent)
- `POST /auth/reset-password` — Reset password with token
- `GET /users/` — List all users (admin only)
- `PUT /users/{user_id}/role` — Update user role (admin only)
- `DELETE /users/{user_id}` — Delete user (admin only)
- `GET /health/` — Health check

---

## License

MIT

---

## Contributing

Pull requests and issues are welcome!

---

**Questions?**  
Open an issue or contact the maintainer.
