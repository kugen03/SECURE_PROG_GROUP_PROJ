# SECR4483 Secure Programming
## Group Project – Secure Application Development
### Technical Report

**Course:** SECR4483 Secure Programming
**Session:** 2025/2026-02
**Application:** LearnHub — Secure E-Learning Platform
**Stack:** Python 3.12 / Flask · SQLite · HTML/CSS (Jinja2 templates)
**Video Demo:** [Insert YouTube link here]

---

## Table of Contents

1. [Integration Summary](#1-integration-summary)
2. [Part 1 – Authentication Module Analysis](#2-part-1--authentication-module-analysis)
3. [Part 2 – Transaction & Session Module Analysis](#3-part-2--transaction--session-module-analysis)
4. [Part 3 – Final Integrated Secure Application](#4-part-3--final-integrated-secure-application)
   - 4.1 Functional Integration
   - 4.2 Implemented Security Measures
   - 4.3 Security Testing Results
5. [Appendix](#5-appendix)

---

## 1. Integration Summary

LearnHub is a full-stack e-learning web application that integrates:

- **Part 1 (Authentication Module):** A login system with bcrypt password hashing,
  parameterized queries, CSRF protection, rate limiting, and session management.
- **Part 2 (Transaction Module):** A course purchase system with credit-based payments,
  enrollment authorization, PDF download access control, and a transaction history view.

The final application merges both modules into a single `app.py` backed by SQLite,
served via Flask with Jinja2 templates. All Part 1 and Part 2 vulnerabilities identified
in the analysis phase have been remediated in the final build.

**Seeded credentials:**

| Username | Password | Role | Credits |
|---|---|---|---|
| `jordan.reyes` | `Wint3r!2024` | student | $50.00 |
| `admin` | `Pr0d-Adm1n_7xQ2` | admin | $999.00 |


---

## 2. Part 1 – Authentication Module Analysis

### 2.1 Overview of the Vulnerable System

The original (vulnerable) LearnHub codebase shipped as an intentional lab target.
The login system used **string-concatenated SQL queries** and **plaintext password
storage**, making it trivially exploitable.

---

### 2.2 Identified Vulnerabilities

#### Vulnerability 1 — SQL Injection (Authentication Bypass)

**Location:** `app.py` → `login()` function

**Vulnerable code:**
```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
row = db.execute(query).fetchone()
```

**Impact:** User-supplied input is concatenated directly into the SQL string.
An attacker can terminate the string literal and inject arbitrary SQL logic.

**Exploit payload (Username field):**
```
' OR '1'='1' --
```

**Resulting query:**
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = ''
```

- `OR '1'='1'` is always true → the WHERE clause matches every row.
- `--` comments out the password check entirely.
- `.fetchone()` returns the first user → **authenticated with no credentials**.

**To authenticate as admin specifically:**
```
admin' --
```
→ Bypasses the password check for the admin account directly.

**Additional impact:** The login page echoed the raw SQL string in a debug `<pre>` block,
leaking the table structure and confirming payloads to the attacker.

---

#### Vulnerability 2 — Weak / Plaintext Password Storage

**Location:** `app.py` → database seed and `login()` comparison

**Issue:** User passwords were stored as **plaintext strings** in the database.
The comparison was a direct string equality check, not a cryptographic hash comparison.

**Impact:** Any database read (via SQLi, backup leak, or insider access) immediately
exposes all user credentials. No rainbow-table resistance. No salting.

---

#### Vulnerability 3 — Information Disclosure via Debug Output

**Location:** `templates/login.html`

**Vulnerable template:**
```html
<details class="debug" open>
  <summary>Debug: SQL executed</summary>
  <pre>{{ query }}</pre>
</details>
```

**Impact:** The exact SQL query (including injected payloads) was reflected back to the
user, confirming injection success and exposing the database schema to an attacker.

---

#### Vulnerability 4 — No Session Security (Hardcoded Secret Key)

**Location:** `app.py`

**Vulnerable code:**
```python
app.secret_key = "8f42c1b9e7a04d6fb3c5e21a9d7f0c84e1b2"
```

**Impact:** The Flask session cookie is an HMAC-signed JWT-like token. Knowing the
secret key allows an attacker to **forge any session** (e.g., `{"user": "admin"}`)
without ever logging in. No session timeout or regeneration was configured.


---

### 2.3 Security Implications

| Vulnerability | Severity | Implication |
|---|---|---|
| SQL Injection | Critical | Full authentication bypass; potential full DB dump |
| Plaintext passwords | High | Credential exposure on any data breach |
| Debug SQL echo | Medium | Schema leakage; confirms attack success to attacker |
| Hardcoded secret key | High | Forged session cookies → complete account takeover |

The combination of SQL injection and a hardcoded secret key means an attacker with
only network access could gain admin-level access **without any credentials**.

---

### 2.4 Recommended Improvements

**1. Parameterized queries (eliminate SQL injection):**
```python
row = db.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
).fetchone()
```

**2. bcrypt password hashing:**
```python
import bcrypt

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
```

**3. Remove debug output:** Never render SQL queries in HTML responses.

**4. Randomised secret key:**
```python
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

All four fixes are implemented in the final Part 3 application.

---

## 3. Part 2 – Transaction & Session Module Analysis

### 3.1 Overview

The original transaction module allowed authenticated users to download course content.
It contained an IDOR vulnerability (no server-side authorization on downloads), no role
separation, no session expiry, and client-side-only access control for premium content.

---

### 3.2 Identified Threats

#### Threat 1 — IDOR (Insecure Direct Object Reference) on Download Endpoint

**Location:** `app.py` → `download()` function

**Vulnerable code:**
```python
@app.route("/download/<int:course_id>")
def download(course_id):
    row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    # No enrollment check — serves any course to any authenticated user
    content = "%s\n\n%s\n\n%s\n" % (row["title"], row["summary"], row["body"])
    return Response(content, ...)
```

**Exploit:**
```
GET http://127.0.0.1:5000/download/3
GET http://127.0.0.1:5000/download/4
```

Any logged-in user could enumerate course IDs and download all premium content
regardless of enrollment or payment. The dashboard UI showed a locked padlock, but
the server enforced nothing.

**Impact:** Financial loss from premium content theft. Full catalog accessible for
free by any authenticated user.

---

#### Threat 2 — Client-Side State Manipulation

**Location:** `templates/course.html`

**Issue:** The premium gate was implemented as a Jinja2 `{% if %}` block in the
template. The server passed the full course object (including body text) to the
template context, and the template decided whether to render it. The download
endpoint had no corresponding server-side check. Disabling JavaScript or directly
requesting the download URL bypassed the UI entirely.

---

#### Threat 3 — Session Fixation / No Session Regeneration

**Location:** `app.py` → `login()`

**Issue:** On successful login, the application only set `session["user"]` without
clearing the existing session. If an attacker had previously set a known session
cookie on the victim's browser, that same cookie became authenticated after the
victim logged in — a classic session fixation attack.

**Vulnerable code:**
```python
if row:
    session["user"] = row["username"]   # old session preserved
    return redirect(url_for("dashboard"))
```

---

#### Threat 4 — Authorization Gaps (No Role Model)

**Location:** All routes in `app.py`

**Issue:** The application had no `role` field on users and no privileged endpoints.
Any authenticated user had the same standing as any other. There was no admin panel,
no audit trail, and no way to restrict operations by privilege level.

---

### 3.3 Risk Summary

| Threat | Risk Level | Impact |
|---|---|---|
| IDOR on download | High | Full premium content theft by any authenticated user |
| Client-side access control | High | Bypassed with a single direct URL request |
| Session fixation | High | Account takeover without credential theft |
| No RBAC | Medium | No privilege separation; no blast radius containment |


### 3.4 Suggested Countermeasures

**1. Server-side authorization on every endpoint:**
```python
@app.route("/download/<int:course_id>")
@login_required
def download(course_id):
    row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if row is None:
        abort(404)
    if row["premium"] and not is_enrolled(session["user"], course_id):
        abort(403)   # Forbidden — enforce on server, not just template
    # ... serve content
```

**2. Session regeneration on login:**
```python
session.clear()   # destroy old session ID
session["user"] = row["username"]
session["role"] = row["role"]
session["last_active"] = time.time()
```

**3. Role-based access control:**
```python
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated
```

All countermeasures are implemented in the Part 3 final application.

---

## 4. Part 3 – Final Integrated Secure Application

### 4.1 Functional Integration

The final application (`app.py`) fully integrates both modules:

**Authentication flow:**
1. User submits login form → CSRF token validated by Flask-WTF
2. Username validated with regex (`^[a-zA-Z0-9._]{3,80}$`)
3. Parameterized SQL query fetches user record
4. bcrypt hash comparison verifies password (timing-safe)
5. Session cleared and regenerated on success
6. Rate limiter blocks > 5 POST attempts/minute per IP

**Transaction flow:**
1. Authenticated user browses course catalog (dashboard)
2. Free courses: one-click enroll, no charge
3. Premium courses: credit balance checked server-side before purchase
4. On successful purchase: credits deducted, enrollment created, transaction recorded
5. Transaction history visible at `/transactions`
6. PDF download enforces enrollment authorization on every request

**Admin flow (role-gated):**
1. Admin logs in → `role = "admin"` stored in session
2. Admin panel at `/admin` — accessible only with `@admin_required` decorator
3. Admin can add credits to any user account
4. Admin can enroll any user in any course
5. Recent transactions visible across all users

---

### 4.2 Implemented Security Measures

#### Security Element 1 — Input Validation and Output Sanitization

**Input validation** is applied at every entry point:

```python
def validate_username(username: str) -> bool:
    """Alphanumeric, dots, underscores only. Length 3–80."""
    return bool(re.match(r'^[a-zA-Z0-9._]{3,80}$', username))

def validate_amount(amount_str: str) -> float:
    """Amount must be numeric and between 0 and 10,000."""
    amount = float(amount_str)
    if amount <= 0 or amount > 10000:
        raise ValueError("Amount must be between 0 and 10000")
    return round(amount, 2)
```

HTML form fields enforce `maxlength` and `type` constraints:
```html
<input type="text"     name="username" maxlength="80"  required>
<input type="password" name="password" maxlength="128" required>
<input type="number"   name="amount"   min="0.01" max="10000" step="0.01">
```

**Output sanitization:** Jinja2 auto-escaping is active on all templates (the default).
All user-controlled values such as `{{ user }}`, `{{ message }}`, `{{ t['description'] }}`
are HTML-escaped before rendering, preventing reflected XSS.

All database queries use parameterized placeholders — no string interpolation:
```python
row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
```


#### Security Element 2 — Role-Based Access Control (RBAC)

Two decorators enforce privilege separation across all routes:

```python
def login_required(f):
    """Reject unauthenticated requests and enforce session timeout."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        last_active = session.get("last_active", 0)
        if time.time() - last_active > app.config["PERMANENT_SESSION_LIFETIME"]:
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        session["last_active"] = time.time()
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Reject non-admin users with 403."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated
```

**Route protection matrix:**

| Route | `@login_required` | `@admin_required` | Enrollment check |
|---|---|---|---|
| `/dashboard` | ✅ | — | — |
| `/course/<id>` | ✅ | — | ✅ (premium gate) |
| `/download/<id>` | ✅ | — | ✅ (premium gate) |
| `/buy/<id>` | ✅ | — | — |
| `/transactions` | ✅ | — | — |
| `/admin` | ✅ | ✅ | — |
| `/admin/enroll` | ✅ | ✅ | — |
| `/admin/credit` | ✅ | ✅ | — |

Premium content authorization is enforced server-side on **both** the view and download
endpoints, eliminating the IDOR that existed in Part 2:

```python
@app.route("/download/<int:course_id>")
@login_required
def download(course_id):
    row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if row is None:
        abort(404)
    if row["premium"] and not is_enrolled(session["user"], course_id):
        abort(403)   # Server-side — cannot be bypassed by direct URL
    pdf = _course_pdf(row)
    return Response(pdf, ...)
```


#### Security Element 3 — Secure Session Management

Session security is configured at four levels:

**a) Cookie flags:**
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",  # Mitigates CSRF at cookie level
    PERMANENT_SESSION_LIFETIME=1800, # 30-minute absolute timeout
)
```

**b) Session regeneration on login (prevents fixation):**
```python
session.clear()               # Invalidate any pre-existing session
session["user"] = row["username"]
session["role"] = row["role"]
session["user_id"] = row["id"]
session["last_active"] = time.time()
session.permanent = True
```

**c) Inactivity timeout enforced per request:**
```python
last_active = session.get("last_active", 0)
if time.time() - last_active > app.config["PERMANENT_SESSION_LIFETIME"]:
    session.clear()
    flash("Session expired. Please log in again.", "error")
    return redirect(url_for("login"))
session["last_active"] = time.time()  # Rolling update
```

**d) Explicit logout clears the session:**
```python
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))
```

**e) Randomised secret key** — the session signing key is generated fresh at startup:
```python
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```
This eliminates the hardcoded key vulnerability from Part 2.

---

#### Security Element 4 — Encrypted Storage of Sensitive Data

All passwords are stored as bcrypt hashes with a random per-user salt:

```python
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
```

Properties of this implementation:
- **bcrypt gensalt()** generates a unique 128-bit salt for each password — identical
  passwords produce different hashes, defeating rainbow-table attacks.
- **bcrypt.checkpw** uses a constant-time comparison — prevents timing side-channel
  attacks that could be used to enumerate valid usernames.
- The work factor is bcrypt's default (12 rounds), making brute-force computationally
  expensive.
- No plaintext password is stored or logged anywhere in the codebase.

Database at rest stores only: `username`, hashed `password`, `role`, `credits`.


#### Security Element 5 — Secure Transmission (Simulated HTTPS)

The application runs on HTTP locally for development, but every response includes
production-grade security headers that enforce HTTPS when deployed behind a TLS
terminator:

```python
@app.after_request
def set_security_headers(response):
    response.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains"   # Force HTTPS for 1 year
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Cache-Control"]           = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"]                  = "no-cache"
    return response
```

**Header purposes:**
- `Strict-Transport-Security` — instructs browsers to only connect via HTTPS for one
  year. Even if a user types `http://`, the browser upgrades to HTTPS automatically.
- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing that could lead to
  script execution from non-JS responses.
- `X-Frame-Options: DENY` — blocks the site from being embedded in an iframe, preventing
  clickjacking attacks.
- `X-XSS-Protection` — activates the browser's built-in reflected XSS filter (legacy
  browsers).
- `Cache-Control: no-store` — prevents authenticated page content from being stored in
  browser cache or proxies.

In a production deployment, TLS would be terminated at a reverse proxy (nginx/Caddy),
and `SESSION_COOKIE_SECURE=True` would be added to ensure cookies are only sent over
HTTPS connections.

---

#### Security Element 6 — CSRF Protection

Flask-WTF's `CSRFProtect` validates a cryptographically random token on all state-
changing POST requests:

```python
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
```

Every form includes the token as a hidden field:
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

This prevents cross-site request forgery attacks where a malicious site tricks an
authenticated user's browser into submitting a form (e.g., buying a course or adding
credits) without their knowledge.

---

#### Security Element 7 — Brute-Force Protection (Rate Limiting)

Flask-Limiter restricts login attempts to prevent automated credential stuffing:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=[])

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    ...
```

After 5 failed POST attempts from the same IP within 60 seconds, the server returns
HTTP 429 (Too Many Requests) with the custom error page. The error message is generic
and does not reveal the rate limit details beyond what is shown in the UI hint.

---

#### Security Element 8 — Proper Error Handling with Limited Information Disclosure

Custom error handlers return generic, safe messages for all error conditions:

```python
@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           message="Access denied."), 403

@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404,
                           message="Page not found."), 404

@app.errorhandler(429)
def rate_limited(_e):
    return render_template("error.html", code=429,
                           message="Too many attempts. Please wait a minute."), 429

@app.errorhandler(500)
def internal_error(_e):
    return render_template("error.html", code=500,
                           message="An unexpected error occurred."), 500
```

Login failures return identical messages regardless of whether the username exists
or the password is wrong — preventing user enumeration:

```python
# Same message for "user not found" and "wrong password"
error = "Invalid credentials."
return render_template("login.html", error=error)
```

No stack traces, SQL errors, or internal paths are ever exposed to the client.
Flask's `DEBUG` mode is disabled in production (`app.run(debug=False)`).


---

### 4.3 Security Testing Results

#### Testing Methodology

The final application was tested using:
1. **Manual penetration testing** — replaying Part 1 and Part 2 exploit payloads against
   the secured application to confirm remediation.
2. **OWASP ZAP** (Zed Attack Proxy) — automated active scan against the running
   application at `http://127.0.0.1:5000`.
3. **Burp Suite Community** — intercepting and replaying requests to test authorization
   boundaries and CSRF protection.

---

#### Test 1 — SQL Injection (Remediated)

**Test:** Submit the Part 1 SQL injection payload in the login form username field.

**Payload:** `' OR '1'='1' --`

**Expected (vulnerable):** Login succeeds as first user.
**Actual (secured):** Login fails with "Invalid credentials." The parameterized query
treats the input as a literal string, not SQL syntax. The query becomes:
```sql
SELECT * FROM users WHERE username = ''' OR ''1''=''1'' --'
```
No user is found → authentication rejected.

**Result: ✅ PASS — SQL injection blocked.**

---

#### Test 2 — IDOR on Download Endpoint (Remediated)

**Test:** Authenticate as `jordan.reyes` (not enrolled in premium courses) and
directly request premium course downloads.

**Requests:**
```
GET /download/3  HTTP/1.1
GET /download/4  HTTP/1.1
```

**Expected (vulnerable):** Server returns course PDF.
**Actual (secured):** Server returns HTTP 403 Forbidden with the generic error page.
The `is_enrolled()` check correctly identifies that the user is not enrolled in
courses #3 and #4.

**Result: ✅ PASS — IDOR blocked.**

---

#### Test 3 — CSRF Protection

**Test:** Submit a POST request to `/buy/<id>` without a valid CSRF token
(simulating a cross-origin request from a malicious page).

**Method:** Burp Suite — intercept the buy form submission, remove the
`csrf_token` field, and forward the request.

**Expected (vulnerable):** Purchase processed.
**Actual (secured):** Flask-WTF rejects the request with HTTP 400 Bad Request.
The CSRF token is missing → the form submission is rejected before any route
handler code runs.

**Result: ✅ PASS — CSRF protection active.**

---

#### Test 4 — Brute-Force Protection

**Test:** Submit 6 consecutive POST requests to `/login` with incorrect credentials
within a 60-second window.

**Method:** Burp Suite Intruder — null payload, 6 iterations.

**Expected:** First 5 return HTTP 200 (with error message). The 6th returns HTTP 429.
**Actual:** Exactly as expected. The 6th request received HTTP 429 with the
"Too many attempts" error page.

**Result: ✅ PASS — Rate limiting enforced.**

---

#### Test 5 — Session Fixation

**Test:** Set a known session cookie before logging in, then log in and check whether
the same session ID is still active.

**Expected (vulnerable):** The pre-set cookie becomes authenticated.
**Actual (secured):** `session.clear()` is called before setting new session values
on login. The old session is invalidated. Any pre-set cookie is discarded.

**Result: ✅ PASS — Session fixation prevented.**

---

#### Test 6 — Admin Privilege Escalation

**Test:** Authenticate as `jordan.reyes` (role: student) and attempt to access
`/admin` directly.

**Result:** HTTP 403 Forbidden. The `@admin_required` decorator checks
`session.get("role") != "admin"` and aborts before any admin logic runs.

**Result: ✅ PASS — RBAC enforced.**

---

#### Test 7 — Session Timeout

**Test:** Log in, wait for the 30-minute session lifetime, then navigate to `/dashboard`.

**Simulated:** Manually set `session["last_active"]` to a timestamp 31 minutes in the
past using Flask's test client.

**Result:** The `@login_required` decorator detects the expired timestamp, clears the
session, and redirects to `/login` with "Session expired" message.

**Result: ✅ PASS — Session timeout enforced.**

---

#### OWASP ZAP Scan Summary

ZAP active scan was run against the running application. Key findings after remediation:

| Alert | Risk | Status |
|---|---|---|
| SQL Injection | High | ✅ Not found — parameterized queries |
| XSS (Reflected) | Medium | ✅ Not found — Jinja2 auto-escape active |
| Missing CSRF Token | Medium | ✅ Not found — Flask-WTF on all forms |
| X-Frame-Options missing | Low | ✅ Not found — `DENY` header present |
| Information Disclosure | Low | ✅ Not found — no stack traces exposed |
| Cookie without HttpOnly | Low | ✅ Not found — `HttpOnly` flag set |

> **Note:** Screenshots of the ZAP scan output should be inserted here in the
> submitted PDF report.


---

## 5. Appendix

### Appendix A — Part 1 Vulnerability Evidence Map

| # | Vulnerability | File | Location | Evidence |
|---|---|---|---|---|
| 1 | SQL Injection | `app.py` | `login()` | String concatenation into SQL query |
| 2 | Plaintext passwords | `app.py` | DB seed + login | Direct string comparison, no hashing |
| 3 | Debug SQL echo | `login.html` | `<pre>{{ query }}</pre>` | Raw query reflected in HTML |
| 4 | Hardcoded secret key | `app.py` | `app.secret_key = "8f42c..."` | Literal string in source code |
| 5 | No session regeneration | `app.py` | `login()` | `session["user"] = ...` without `session.clear()` |

---

### Appendix B — Part 2 Vulnerability Evidence Map

| # | Threat | File | Location | Evidence |
|---|---|---|---|---|
| 1 | IDOR | `app.py` | `download()` | No enrollment/premium check before serving content |
| 2 | Client-side access control | `course.html` | `{% if course['premium'] %}` | Authorization in template, not server |
| 3 | Session fixation | `app.py` | `login()` | No `session.clear()` before setting new session |
| 4 | No RBAC | `app.py` | All routes | No role field on users, no admin routes |
| 5 | No CSRF tokens | All forms | `*.html` | No `{{ csrf_token() }}` in any form |

---

### Appendix C — Security Element Checklist

| Security Element | Implemented | Mechanism |
|---|---|---|
| Input validation | ✅ | `validate_username()`, `validate_amount()`, HTML `maxlength`/`type` |
| Output sanitization | ✅ | Jinja2 auto-escape on all `{{ }}` expressions |
| Multi-factor authentication | Optional — not implemented | N/A |
| Role-based access control | ✅ | `@login_required`, `@admin_required`, `is_enrolled()` |
| Secure session management | ✅ | Timeout, regeneration, `HttpOnly`, `SameSite`, signed cookies |
| Encrypted storage | ✅ | bcrypt with `gensalt()` for all passwords |
| Secure transmission | ✅ | HSTS, security headers on every response |
| Proper error handling | ✅ | Custom 403/404/429/500 handlers, generic messages |
| CSRF protection | ✅ | Flask-WTF `CSRFProtect`, tokens in all forms |
| Brute-force protection | ✅ | Flask-Limiter, 5 POST/min on `/login` |

---

### Appendix D — Application File Structure

```
pu3/
├── app.py                  # Main application — all routes, DB, security logic
├── requirements.txt        # Flask, Flask-WTF, Flask-Limiter, bcrypt
├── Dockerfile              # python:3.12-slim image
├── docker-compose.yml      # Binds to 127.0.0.1:5000 only
├── templates/
│   ├── base.html           # Shared layout, navigation, flash messages
│   ├── login.html          # Login form with CSRF token
│   ├── dashboard.html      # Course catalog with enrollment status
│   ├── course.html         # Course view + buy form
│   ├── transactions.html   # Transaction history
│   ├── admin.html          # Admin panel (role-gated)
│   └── error.html          # Generic error page (403/404/429/500)
├── static/
│   └── style.css           # UI styles
├── EXPLOIT.md              # Documents the original vulnerabilities
├── PART2_REPORT.md         # Part 2 analysis report
└── TECHNICAL_REPORT.md     # This document
```

---

### Appendix E — How to Run

**Option 1 — Docker (recommended):**
```bash
docker compose up --build
# Application at http://127.0.0.1:5000
```

**Option 2 — Python directly:**
```bash
pip install -r requirements.txt
# Windows:
$env:DB_PATH="C:\Users\<you>\AppData\Local\Temp\learnhub.db"
python app.py
# Linux/macOS:
DB_PATH=/tmp/learnhub.db python app.py
```

**Default credentials:**

| Username | Password | Role |
|---|---|---|
| `jordan.reyes` | `Wint3r!2024` | student |
| `admin` | `Pr0d-Adm1n_7xQ2` | admin |

---

*End of Technical Report*
