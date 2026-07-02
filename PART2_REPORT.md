# PART 2 – Transaction & Session Module Analysis

## Application Under Review

**LearnHub** — a Flask + SQLite e-learning platform with user authentication and a course transaction/download system. Users log in, browse a catalog, and download course content (free or premium).

---

## 1. Identified Threats and Potential Exploits (2 marks)

### Threat 1: Session Fixation / Hijacking

**Location:** `app.py` — `login()` function and Flask session configuration.

**Issue:** After successful authentication, the application stores the username in the session but **never regenerates the session ID**. Flask's default `session` is a client-side signed cookie, and the `secret_key` is hardcoded:

```python
app.secret_key = os.environ.get("SECRET_KEY", "8f42c1b9e7a04d6fb3c5e21a9d7f0c84e1b2")
```

**Exploit scenario:**
1. An attacker who obtains the hardcoded secret key can **forge any session cookie** — signing `{"user": "admin"}` themselves without ever authenticating.
2. The session cookie has **no expiry, no `Secure` flag, and no `HttpOnly` enforcement** beyond Flask defaults. On a non-HTTPS deployment, session cookies travel in cleartext and can be intercepted via network sniffing.
3. There is no session regeneration on login — if an attacker sets a known session cookie before the victim logs in (fixation), the attacker's cookie becomes authenticated.

**Evidence (from `app.py`):**
```python
if row:
    session["user"] = row["username"]          # no session regeneration
    return redirect(url_for("dashboard"))
```

---

### Threat 2: Client-Side State Manipulation

**Location:** `templates/course.html` — UI-only access control.

**Issue:** Premium course content is gated **only in the HTML template** by checking `course['premium']`. The server still sends the course row to the template — the decision to hide/show is purely client-side rendering. While the template doesn't embed the body for premium courses, the download endpoint (`/download/<id>`) has **no server-side authorization check**, making client-side gating meaningless.

**Exploit scenario:**
A user can bypass the disabled download button by directly requesting:
```
GET /download/3 HTTP/1.1
```
The server returns full premium content regardless of enrollment status.

**Evidence (from `app.py`):**
```python
@app.route("/download/<int:course_id>")
def download(course_id):
    # No check for row["premium"] or user enrollment
    row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    pdf = _course_pdf(row)
    return Response(pdf, ...)
```

---

### Threat 3: Authorization Gaps (Missing Role-Based Access Control)

**Location:** All routes — no user roles, no permission model.

**Issue:** The application has no concept of user roles (student, admin, instructor). Both seeded users (`jordan.reyes` and `admin`) have identical access. The `admin` account grants no additional privileges — any authenticated user can access all free content and exploit IDOR to access premium content.

**Exploit scenario:** Since there is no role differentiation, any compromised account has equal standing. There is no admin panel, no audit log, and no way to restrict operations by privilege level.

---

### Threat 4: Input/Output Sanitization Flaws

**Location:** `app.py` — `login()` route; `templates/login.html`.

**Issue:** The login page **echoes the raw SQL query** back to the user in a `<pre>` block:

```html
<details class="debug" open>
  <summary>Debug: SQL executed</summary>
  <pre>{{ query }}</pre>
</details>
```

While Jinja2's auto-escaping prevents XSS in this specific rendering, the practice of reflecting internal SQL to end users:
- Leaks database schema information (table/column names).
- Confirms successful injection payloads to attackers.
- Violates the principle of least information disclosure.

Additionally, the SQL injection vulnerability itself represents a **complete failure of input sanitization** — user input flows directly into SQL without any validation or parameterization.

---

## 2. Risk Explanation and Impact (1 mark)

| Threat | Severity | Impact |
|--------|----------|--------|
| Session fixation/hijacking | **High** | Full account takeover. Attacker gains authenticated access without credentials. Hardcoded secret key means any party with source access can forge sessions for any user. |
| Client-side state manipulation | **Medium** | Unauthorized access to paid content. Financial loss from premium content theft. |
| Authorization gaps | **High** | No privilege separation. A compromised low-privilege account has the same access as admin. No ability to contain breaches. |
| Input/output sanitization | **Critical** | Complete authentication bypass via SQL injection. Database exfiltration. Information leakage through debug output. |

**Combined impact:** An attacker can bypass authentication (SQLi), access all content regardless of payment status (IDOR), and maintain persistent access by forging session cookies (hardcoded secret). There is no detection, logging, or containment mechanism.

---

## 3. Suggested Security Improvements (1 mark)

### Session Management
```python
# 1. Use environment variable for secret key (never hardcode)
app.secret_key = os.environ["SECRET_KEY"]  # Fail loud if not set

# 2. Configure secure session settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,        # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,   # 30-minute timeout
)

# 3. Regenerate session on login
from flask import session
session.clear()                        # Destroy old session
session["user"] = row["username"]
session["role"] = row["role"]
session.modified = True
```

### Input Validation & Parameterized Queries
```python
# Replace string concatenation with parameterized query
row = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
```

### Authorization Enforcement
```python
# Add role check on every protected endpoint
@app.route("/download/<int:course_id>")
def download(course_id):
    if not session.get("user"):
        return redirect(url_for("login"))
    row = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if row["premium"] and not is_enrolled(session["user"], course_id):
        abort(403)
    # ... serve content
```

### Remove Debug Output
```python
# Never echo SQL queries to end users
return render_template("login.html", error="Invalid credentials.")
# Remove the 'query' variable entirely from production
```

---

## 4. Evidence Summary (1 mark)

| Finding | File:Line | Code Evidence |
|---------|-----------|---------------|
| Hardcoded secret key | `app.py:12` | `app.secret_key = "8f42c1b9e7a04d6fb3c5e21a9d7f0c84e1b2"` |
| No session regeneration | `app.py:166` | `session["user"] = row["username"]` (direct set, no clear) |
| SQL injection sink | `app.py:154-160` | String concatenation into SQL query |
| IDOR / no auth check | `app.py:199-215` | Download serves content by ID with no enrollment check |
| Debug SQL echo | `templates/login.html:19-22` | `<pre>{{ query }}</pre>` shown to user |
| No session timeout | `app.py` (absent) | No `PERMANENT_SESSION_LIFETIME` configured |
| No CSRF protection | `templates/login.html` | Form has no CSRF token |

*Screenshots of exploitation are available by running the Docker container and following the exploit steps documented in `EXPLOIT.md`.*
