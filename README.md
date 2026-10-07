# 🔐 Enterprise Multi-Tenant Security Gateway

**CSC337 — Advanced Web Technologies — Lab Assignment 05**
Hybrid Authentication (Local Bcrypt + Google OAuth 2.0) · JWT Access/Refresh
Rotation · Role-Based Access Control (RBAC) · OWASP Hardening

## 📦 What's inside

- **Local auth**: `/register`, `/login` with bcrypt-hashed passwords (never plain text)
- **Account protection**: IP-based rate limiting (5 attempts / 15 min) + per-account
  lockout (5 failed logins / 15 min)
- **Google OAuth 2.0**: social login via Passport.js, auto-syncs/creates user profile
- **Token architecture**:
  - Access Token — 15 min, sent via `Authorization: Bearer <token>`
  - Refresh Token — 7 days, stored in `httpOnly`, `Secure`, `SameSite=Strict` cookie
  - **Rotation**: every refresh invalidates the old token and issues a new pair
  - **Reuse detection**: a stolen/replayed old refresh token is rejected
  - **Revocation**: logout invalidates the refresh token server-side
- **RBAC**: `SuperAdmin`, `Manager`, `Employee` roles via `checkRole([...])` middleware
- **OWASP hardening**: Helmet security headers, strict CORS, XSS/NoSQL-injection
  sanitization on every request body/query/params

## 📸 Screenshots

<img width="1600" height="900" alt="Image" src="https://github.com/user-attachments/assets/79146fac-38b1-4eae-91a1-9bfdbb983809" />
<img width="1600" height="900" alt="Image" src="https://github.com/user-attachments/assets/0da5459d-a0ca-499d-a5be-55ae16950c03" />
<img width="1325" height="342" alt="Image" src="https://github.com/user-attachments/assets/668720fe-08c9-4a01-a0c1-cf62c70bbe55" />
<img width="1600" height="900" alt="Image" src="https://github.com/user-attachments/assets/e4a689f7-34ef-4170-86e8-153cc93244fc" />

## 🛠 Setup & Running Locally

```bash
# 1. Install dependencies
npm install

# 2. Copy environment file and fill in your own secrets
cp .env.example .env

# 3. Start the server
npm start
```

Server runs at: **http://localhost:3000**

### ⚙️ Environment variables (`.env`)

| Variable | Description |
|---|---|
| `PORT` | Server port (default 3000) |
| `CLIENT_ORIGIN` | Allowed CORS origin (your frontend URL) |
| `ACCESS_TOKEN_SECRET` | Secret for signing access tokens |
| `REFRESH_TOKEN_SECRET` | Secret for signing refresh tokens |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | From Google Cloud Console → OAuth credentials |
| `GOOGLE_CALLBACK_URL` | e.g. `http://localhost:3000/api/v1/auth/google/callback` |

> Get Google OAuth credentials at: https://console.cloud.google.com/apis/credentials
> (Create OAuth Client ID → Web application → add the callback URL above to
> "Authorized redirect URIs").

## 🔑 Test Credentials (seeded for viva/demo)

| Role | Email | Password |
|---|---|---|
| SuperAdmin | `superadmin@gateway.com` | `SuperAdmin@123` |
| Manager | `manager@gateway.com` | `Manager@123` |
| Employee | `employee@gateway.com` | `Employee@123` |

> ⚠️ These are demo-only credentials for assignment evaluation. In a real
> production system they would never be hardcoded in source.

## 📚 API Reference

### Auth

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Create a new Employee account |
| POST | `/api/v1/auth/login` | Login (rate-limited + lockout protected) |
| POST | `/api/v1/auth/refresh` | Rotate refresh token, get new access token |
| POST | `/api/v1/auth/logout` | Revoke refresh token |
| GET | `/api/v1/auth/google` | Start Google OAuth flow |
| GET | `/api/v1/auth/google/callback` | Google OAuth callback |

### Protected (RBAC)

| Method | Endpoint | Allowed roles |
|---|---|---|
| GET | `/api/v1/employee/profile` | Any authenticated role |
| POST | `/api/v1/payroll/approve` | Manager, SuperAdmin |
| GET | `/api/v1/users` | SuperAdmin |
| DELETE | `/api/v1/users/:id` | SuperAdmin |

### Example requests

```bash
# Login
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"superadmin@gateway.com","password":"SuperAdmin@123"}'

# Access protected route with the returned accessToken
curl http://localhost:3000/api/v1/employee/profile \
  -H "Authorization: Bearer <accessToken>"

# Refresh (uses the httpOnly cookie saved by -c/-b)
curl -X POST http://localhost:3000/api/v1/auth/refresh -b cookies.txt -c cookies.txt

# Logout
curl -X POST http://localhost:3000/api/v1/auth/logout -b cookies.txt
```

## ⚠️ Error Response Schema

```json
{
  "error_code": "FORBIDDEN_ROLE",
  "message": "Role 'Employee' is not authorized for this action. Required: Manager or SuperAdmin",
  "timestamp": "2026-10-07T04:39:51.476Z"
}
```

| Status | error_code | Meaning |
|---|---|---|
| 400 | VALIDATION_ERROR / WEAK_PASSWORD | Bad input |
| 401 | INVALID_CREDENTIALS / NO_TOKEN / TOKEN_EXPIRED | Auth failed |
| 403 | FORBIDDEN_ROLE / INVALID_TOKEN / REFRESH_TOKEN_REUSED | Access denied |
| 404 | USER_NOT_FOUND / ROUTE_NOT_FOUND | Resource missing |
| 409 | EMAIL_EXISTS | Duplicate registration |
| 423 | ACCOUNT_LOCKED | Too many failed logins on this account |
| 429 | TOO_MANY_ATTEMPTS | Too many login attempts from this IP |

## 🚀 Deployment (Render / Railway / Vercel)

1. Push this repo to a **public** GitHub repository.
2. On Render/Railway: create a new Web Service → connect the repo →
   Build command `npm install` → Start command `npm start`.
3. Add all variables from `.env.example` into the platform's Environment
   Variables settings (with real secrets, not placeholders).
4. Update `GOOGLE_CALLBACK_URL` to your live HTTPS URL, and add that same
   URL to Google Cloud Console → Authorized redirect URIs.
5. Set `CLIENT_ORIGIN` to your deployed frontend URL and `NODE_ENV=production`
   (this makes the refresh-token cookie `Secure`, requiring HTTPS).

## 📁 Project Structure

```
security-gateway-api/
├── server.js                  # App entry point, security middleware wiring
├── config/
│   └── passport.js            # Google OAuth 2.0 strategy
├── data/
│   └── users.js                # In-memory user store + lockout tracking
├── middleware/
│   ├── auth.js                 # Access token verification
│   ├── checkRole.js             # RBAC middleware
│   ├── sanitize.js              # XSS / NoSQL-injection sanitization
│   ├── rateLimiter.js           # Login rate limiting
│   └── errorHandler.js          # Standardized JSON error schema
├── routes/
│   ├── auth.routes.js            # register/login/refresh/logout/OAuth
│   ├── employee.routes.js
│   ├── payroll.routes.js
│   └── users.routes.js
└── utils/
    └── tokens.js                 # JWT generation, rotation, revocation
```
