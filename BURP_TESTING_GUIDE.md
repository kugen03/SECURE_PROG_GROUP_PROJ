# LearnHub — Burp Suite Testing Guide
## SECR4483 Secure Programming | Security Verification Tests

**Target:** `http://127.0.0.1:5000`
**Tool:** Burp Suite Community Edition
**Prerequisites:** App running via `python app.py` or `docker compose up --build`

---

## Setup: Configure Burp Proxy

1. Open Burp Suite → **Proxy** tab → **Options**
2. Confirm listener is on `127.0.0.1:8080`
3. In your browser, set HTTP proxy to `127.0.0.1:8080`
4. Visit `http://127.0.0.1:5000` — traffic should appear in **Proxy > Intercept**
5. Turn **Intercept off** for browsing; turn it **on** when you want to capture a specific request

---

## Test 1 — SQL Injection (Input Validation)

**What it verifies:** Parameterized queries block authentication bypass.

### Steps

1. Go to `http://127.0.0.1:5000/login`
2. Turn **Intercept ON** in Burp
3. Enter any text in username/password and click **Log in**
4. The request appears in Intercept. Right-click → **Send to Repeater**
5. Turn Intercept **OFF**

In **Repeater**, edit the request body. Change `username` to each payload below one at a time and click **Send**:

| Payload | Intent |
|---|---|
| `' OR '1'='1' --` | Classic auth bypass |
| `admin' --` | Direct admin bypass |
| `' UNION SELECT 1,username,password,role,credits FROM users --` | Data exfiltration |
| `'; DROP TABLE users; --` | Destructive injection |

**Raw request to send:**
```
POST /login HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded

username=%27+OR+%271%27%3D%271%27+--&password=anything&csrf_token=<token>
```

> **Note on CSRF token:** Copy a valid `csrf_token` value from the login page source first (right-click → View Page Source). The token is in the hidden input field.

### Expected Result (Secured App)
- Response: HTTP 200 with body containing `Invalid credentials.`
- No redirect to `/dashboard`
- No SQL error or stack trace in the response

### Pass Criteria
Response body contains `Invalid credentials.` for all four payloads. No 500 error.

---

## Test 2 — Brute-Force Protection (Rate Limiting)

**What it verifies:** Login is blocked after 5 attempts per minute.

### Steps

1. Go to `http://127.0.0.1:5000/login`
2. Intercept a POST login request → Send to **Intruder**
3. In Intruder → **Positions** tab:
   - Set attack type to **Sniper**
   - Highlight the `password` value → click **Add §**
4. Go to **Payloads** tab:
   - Payload type: **Simple list**
   - Add 8 entries: `wrong1`, `wrong2`, `wrong3`, `wrong4`, `wrong5`, `wrong6`, `wrong7`, `wrong8`
5. Go to **Settings** tab → set **Request concurrency** to 1 (sequential)
6. Click **Start attack**

### Expected Result
- Requests 1–5: HTTP 200 with `Invalid credentials.`
- Request 6 onward: HTTP **429** with `Too many attempts. Please wait a minute.`

### Pass Criteria
Status code 429 appears by the 6th request. ✅

---

## Test 3 — CSRF Protection

**What it verifies:** State-changing POST requests require a valid CSRF token.

### Steps — Test 3A: Missing Token

1. Log in as `jordan.reyes` / `Wint3r!2024`
2. Navigate to any premium course, e.g. `http://127.0.0.1:5000/course/3`
3. Turn **Intercept ON**, click **Buy**
4. In the intercepted request, **delete** the `csrf_token` parameter entirely
5. Forward the modified request

### Steps — Test 3B: Invalid Token

Repeat steps 1–3, but instead of deleting, change `csrf_token` value to `invalidtoken123`, then forward.

### Steps — Test 3C: Cross-Origin Simulation

In Repeater, craft a POST to `/buy/3` with no `csrf_token`:
```
POST /buy/3 HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
Cookie: session=<your session cookie>

```
(empty body — no csrf_token at all)

### Expected Result
All three variants return HTTP **400 Bad Request**.
Response body does not indicate a successful purchase.

### Pass Criteria
HTTP 400 for missing token. HTTP 400 for invalid token. No purchase recorded. ✅

---

## Test 4 — IDOR on Download Endpoint (Authorization Check)

**What it verifies:** Non-enrolled users cannot download premium courses by guessing the URL.

### Steps

1. Log in as `jordan.reyes` / `Wint3r!2024` (student — enrolled in courses #1 and #2 only)
2. In Burp Repeater, craft these requests:

```
GET /download/1 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<jordan.reyes session cookie>
```

```
GET /download/3 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<jordan.reyes session cookie>
```

```
GET /download/4 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<jordan.reyes session cookie>
```

Send each one.

### Expected Result
| Request | Expected Status |
|---|---|
| `GET /download/1` | 200 OK — PDF returned (enrolled) |
| `GET /download/3` | 403 Forbidden |
| `GET /download/4` | 403 Forbidden |

### Pass Criteria
Courses 3 and 4 return 403. No PDF content in response body. ✅

---

## Test 5 — Role-Based Access Control (Admin Endpoint)

**What it verifies:** The `/admin` panel is inaccessible to student-role users.

### Steps — Test 5A: Direct Access as Student

1. Log in as `jordan.reyes` / `Wint3r!2024`
2. Copy the session cookie from Burp (Proxy history → any request → Cookie header)
3. In Repeater, send:

```
GET /admin HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<jordan.reyes session cookie>
```

### Steps — Test 5B: Role Tampering (Cookie Forgery Attempt)

Flask session cookies are base64-encoded and HMAC-signed. Try to forge an admin session:

1. In Burp, go to **Decoder** tab
2. Paste the session cookie value (the part before the dot, after `session=`)
3. Decode as **Base64** — you'll see the JSON payload e.g. `{"user":"jordan.reyes","role":"student",...}`
4. Modify `"role":"student"` to `"role":"admin"`, re-encode as Base64
5. Replace the cookie value in a Repeater request to `/admin` with the tampered (unsigned) value

### Steps — Test 5C: Unauthenticated Access

Send a request to `/admin` with **no session cookie** at all.

### Expected Result
| Scenario | Expected |
|---|---|
| Student session | HTTP 403 — `Access denied.` |
| Forged/tampered cookie | HTTP 403 — cookie signature invalid, session rejected |
| No cookie | HTTP 302 → redirect to `/login` |

### Pass Criteria
All three return either 403 or redirect. Admin page HTML never rendered for non-admins. ✅

---

## Test 6 — Session Management (Timeout + Regeneration)

**What it verifies:** Session expires after inactivity and regenerates on login.

### Steps — Test 6A: Session Timeout

1. Log in as `jordan.reyes` — note the `session` cookie value in Burp Proxy history
2. Log out (`/logout`)
3. In Repeater, send a request to `/dashboard` using the **old** (now-logged-out) session cookie:

```
GET /dashboard HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<old session cookie>
```

### Steps — Test 6B: Session Regeneration on Login

1. Note the session cookie **before** logging in (from any failed login attempt)
2. Log in successfully
3. Note the session cookie **after** login

### Steps — Test 6C: Logout Invalidates Session

1. Log in, copy the active session cookie
2. Navigate to `/logout`
3. In Repeater, use the copied (pre-logout) cookie to request `/dashboard`

### Expected Result
| Scenario | Expected |
|---|---|
| Logged-out cookie reused | HTTP 302 → `/login` |
| Session cookie before vs after login | Values are **different** (regenerated) |
| Pre-logout cookie after logout | HTTP 302 → `/login` |

### Pass Criteria
Old cookies do not grant access. Session value changes on login. ✅

---

## Test 7 — Security Headers (Secure Transmission)

**What it verifies:** Every response includes the required security headers.

### Steps

1. In Burp Proxy history, click on any response from the app
2. Switch to the **Response** tab
3. Check the headers section

Alternatively, in Repeater send any GET:
```
GET / HTTP/1.1
Host: 127.0.0.1:5000
```

### Expected Headers in Every Response

| Header | Expected Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Cache-Control` | `no-store, no-cache, must-revalidate` |

### Pass Criteria
All 5 headers present on every response. ✅

---

## Test 8 — Output Sanitization / XSS

**What it verifies:** User-supplied input is HTML-escaped before rendering (no XSS).

### Steps — Test 8A: Reflected XSS via Username

1. On the login page, intercept the POST
2. Set `username` to: `<script>alert(1)</script>`
3. Forward the request

### Steps — Test 8B: Stored XSS via Admin Credit Description

1. Log in as `admin` / `Pr0d-Adm1n_7xQ2`
2. Intercept a POST to `/admin/credit`
3. Set `username=jordan.reyes` and `amount=1`
4. Observe the response — check if the description field reflects any input

### Expected Result
- Test 8A: Response body shows `Invalid credentials.` — no script executed, username not reflected
- Test 8B: Any rendered text shows HTML entities (`&lt;`, `&gt;`) not raw tags

### How to Confirm in Burp
In the response body, search (Ctrl+F) for `<script>` — it should **not** appear as raw HTML. You should see `&lt;script&gt;` instead, or the input should be rejected.

### Pass Criteria
No `<script>` tags appear unescaped in any response. ✅

---

## Test 9 — Information Disclosure (Error Handling)

**What it verifies:** Errors return generic messages without leaking internals.

### Steps

1. In Repeater, send requests to non-existent pages and forbidden pages:

```
GET /admin HTTP/1.1          (as student — expect 403)
GET /nonexistent HTTP/1.1    (expect 404)
GET /course/9999 HTTP/1.1    (expect 404)
```

2. Check each response body carefully for:
   - Python stack traces
   - File paths (e.g. `C:\Users\...` or `/app/...`)
   - SQL query text
   - Internal variable names or table names

### Expected Result
All error responses contain only:
- The numeric error code
- A short, generic message (`Access denied.` / `Page not found.`)
- No internal details whatsoever

### Pass Criteria
Zero internal details in error responses. ✅

---

## Test 10 — Cookie Flags (Session Security)

**What it verifies:** Session cookie has `HttpOnly` and `SameSite` flags set.

### Steps

1. Log in to the app
2. In Burp Proxy history, find the `Set-Cookie` response header from the login redirect
3. Inspect the cookie flags

### Expected Cookie Header
```
Set-Cookie: session=<value>; HttpOnly; Path=/; SameSite=Lax
```

### Pass Criteria
`HttpOnly` present — JavaScript cannot steal the cookie via XSS.
`SameSite=Lax` present — cross-site form submissions are blocked. ✅

---

## Test Results Summary Table

Fill this in as you run each test:

| # | Test | Security Element | Expected | Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | SQL Injection | Input Validation | 200 `Invalid credentials.` | | |
| 2 | Brute Force | Rate Limiting | 429 after 5 attempts | | |
| 3 | CSRF | CSRF Protection | 400 Bad Request | | |
| 4 | IDOR Download | RBAC + Authorization | 403 Forbidden | | |
| 5 | Admin Access | RBAC | 403 / Redirect | | |
| 6 | Session Timeout | Session Management | Old cookie rejected | | |
| 7 | Security Headers | Secure Transmission | All 5 headers present | | |
| 8 | XSS | Output Sanitization | Input escaped | | |
| 9 | Error Messages | Error Handling | No internals disclosed | | |
| 10 | Cookie Flags | Session Management | HttpOnly + SameSite | | |

---

## Credentials Reference

| Username | Password | Role | Credits |
|---|---|---|---|
| `jordan.reyes` | `Wint3r!2024` | student | $50.00 |
| `admin` | `Pr0d-Adm1n_7xQ2` | admin | $999.00 |

## Quick Start

```bash
# Run the app
python app.py

# Or via Docker
docker compose up --build
```

App available at: `http://127.0.0.1:5000`
Burp proxy: `127.0.0.1:8080`
