"""
LearnHub — Secure Integrated Application (Part 3)

A Flask + SQLite e-learning platform combining login and transaction features
with robust security controls:
- Input validation and output sanitization
- Password hashing with bcrypt (encrypted storage)
- Role-based access control (admin / student)
- Secure session management (timeout, regeneration, secure cookies)
- CSRF protection via Flask-WTF
- Rate limiting on login (brute-force protection)
- Proper error handling with limited information disclosure
- Simulated HTTPS headers (Strict-Transport-Security)
- Transaction module (course purchases with credits)
"""
import sqlite3
import os
import secrets
import time
import re
from functools import wraps
from datetime import datetime

import bcrypt
from flask import (
    Flask, request, redirect, render_template, session,
    url_for, g, abort, Response, flash
)
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Secure secret key — generated at startup if not provided via env
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Secure session settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    WTF_CSRF_ENABLED=True,
)

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting (brute-force protection on login)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

DB_PATH = os.environ.get("DB_PATH", "/tmp/learnhub.db")


# ---------------------------------------------------------------------------
# Security headers middleware (simulated HTTPS / secure transmission)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Get database connection for current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
def validate_username(username: str) -> bool:
    """Validate username: alphanumeric, dots, underscores, 3-80 chars."""
    return bool(re.match(r'^[a-zA-Z0-9._]{3,80}$', username))


def validate_amount(amount_str: str) -> float:
    """Validate and parse a monetary amount. Returns float or raises ValueError."""
    amount = float(amount_str)
    if amount <= 0 or amount > 10000:
        raise ValueError("Amount must be between 0 and 10000")
    return round(amount, 2)


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------
def init_db():
    """Create tables and seed users/courses on startup."""
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS courses;
        DROP TABLE IF EXISTS enrollments;
        DROP TABLE IF EXISTS transactions;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            credits REAL NOT NULL DEFAULT 0.0
        );

        CREATE TABLE courses (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            summary TEXT,
            body TEXT,
            premium INTEGER DEFAULT 0,
            price REAL NOT NULL DEFAULT 0.0
        );

        CREATE TABLE enrollments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrolled_at TEXT NOT NULL,
            UNIQUE(user_id, course_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(course_id) REFERENCES courses(id)
        );

        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            course_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(course_id) REFERENCES courses(id)
        );
        """
    )

    # Seed users with hashed passwords, roles, and starting credits
    users = [
        ("jordan.reyes", hash_password("Wint3r!2024"), "student", 50.0),
        ("admin", hash_password("Pr0d-Adm1n_7xQ2"), "admin", 999.0),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)",
        users,
    )

    # Seed courses with prices
    courses = [
        ("Intro to Python",
         "Variables, loops, and functions for absolute beginners.",
         "Welcome to Intro to Python. This module covers the core building "
         "blocks you will reach for in every program you write.\n\n"
         "1. Variables and types\n"
         "Python stores values in variables with no explicit type declaration. "
         "The first types you will meet are strings, integers, floats, and booleans.\n\n"
         "2. Control flow\n"
         "if/elif/else statements let a program choose between paths, while for "
         "and while loops repeat work across ranges and collections.\n\n"
         "3. Functions\n"
         "Group reusable logic with def, accept parameters, and hand back "
         "results with return.",
         0, 0.0),
        ("Web Fundamentals",
         "HTML, CSS, and how the web actually works.",
         "Web Fundamentals explains what happens between typing a URL and "
         "seeing a finished page in your browser.\n\n"
         "1. The request/response cycle\n"
         "Your browser opens a connection to a server and sends an HTTP request. "
         "The server returns a response with status code, headers, and HTML.\n\n"
         "2. Structure with HTML\n"
         "HTML marks up content with elements such as headings, paragraphs, "
         "lists, links, and images.\n\n"
         "3. Style with CSS\n"
         "CSS controls layout, colour, spacing, and typography.",
         0, 0.0),
        ("Advanced Offensive Security [PREMIUM]",
         "Exploitation, post-exploitation, and red-team tradecraft.",
         "Advanced Offensive Security is a hands-on, lab-driven course.\n\n"
         "Module 1 — Reconnaissance and enumeration\n"
         "Map an engagement scope and fingerprint services.\n\n"
         "Module 2 — Exploitation\n"
         "Identify and validate common web and service vulnerabilities.\n\n"
         "Module 3 — Post-exploitation and privilege escalation\n"
         "Establish footholds and chain low-impact issues into meaningful access.\n\n"
         "Module 4 — Reporting and remediation\n"
         "Document findings with clear reproduction steps and business impact.",
         1, 25.0),
        ("Cloud Security Mastery [PREMIUM]",
         "Securing AWS, GCP, and Azure at scale.",
         "Cloud Security Mastery teaches the controls that keep modern cloud "
         "workloads safe.\n\n"
         "Module 1 — Identity and access management\n"
         "Design least-privilege roles and scope policies correctly.\n\n"
         "Module 2 — Data protection\n"
         "Encrypt data at rest and in transit, manage keys with KMS services.\n\n"
         "Module 3 — Network and workload security\n"
         "Segment networks and harden compute and container workloads.\n\n"
         "Module 4 — Monitoring and the capstone\n"
         "Centralise logs, build actionable alerts, and complete a capstone project.",
         1, 30.0),
    ]
    cur.executemany(
        "INSERT INTO courses (title, summary, body, premium, price) VALUES (?, ?, ?, ?, ?)",
        courses,
    )

    # Enroll admin in all courses by default
    now = datetime.utcnow().isoformat()
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (2, 1, ?)", (now,))
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (2, 2, ?)", (now,))
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (2, 3, ?)", (now,))
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (2, 4, ?)", (now,))
    # Student gets free courses
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (1, 1, ?)", (now,))
    cur.execute("INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (1, 2, ?)", (now,))

    # Seed initial transactions (credit top-ups)
    cur.execute(
        "INSERT INTO transactions (user_id, type, amount, description, created_at) VALUES (1, 'credit', 50.0, 'Initial account credit', ?)",
        (now,),
    )
    cur.execute(
        "INSERT INTO transactions (user_id, type, amount, description, created_at) VALUES (2, 'credit', 999.0, 'Admin account credit', ?)",
        (now,),
    )

    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Decorators for access control
# ---------------------------------------------------------------------------
def login_required(f):
    """Require an authenticated session with timeout enforcement."""
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
    """Require admin role for access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


def is_enrolled(username: str, course_id: int) -> bool:
    """Check if a user is enrolled in a specific course."""
    db = get_db()
    row = db.execute(
        """SELECT e.id FROM enrollments e
           JOIN users u ON u.id = e.user_id
           WHERE u.username = ? AND e.course_id = ?""",
        (username, course_id),
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# PDF generation (dependency-free, hand-built PDF 1.4)
# ---------------------------------------------------------------------------
def _pdf_escape(text):
    """Escape special PDF characters."""
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text, width):
    """Word-wrap a single paragraph to roughly `width` characters."""
    words = text.split()
    lines, line = [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        lines.append(line)
    return lines or [""]


def _course_pdf(row):
    """Render a course into a PDF and return the bytes."""
    elems = [("F2", 18, 30, row["title"]),
             ("F1", 11, 18, row["summary"]),
             ("F1", 11, 12, "")]
    for para in (row["body"] or "").split("\n"):
        if not para.strip():
            elems.append(("F1", 11, 9, ""))
            continue
        for ln in _wrap(para, 92):
            elems.append(("F1", 11, 15, ln))

    pages, cur, y = [], [], 748
    for font, size, lead, text in elems:
        y -= lead
        if y < 64:
            pages.append(cur)
            cur, y = [], 748 - lead
        cur.append((font, size, y, text))
    if cur:
        pages.append(cur)

    pages_content = []
    for page in pages:
        ops = []
        for font, size, y, text in page:
            if text == "":
                continue
            ops.append(f"BT /{font} {size} Tf 56 {y} Td ({_pdf_escape(text)}) Tj ET")
        pages_content.append("\n".join(ops))
    return _build_pdf_bytes(pages_content)


def _build_pdf_bytes(pages_content):
    """Build raw PDF bytes from page content streams."""
    n = len(pages_content) or 1
    if not pages_content:
        pages_content = [""]
    content_start = 5
    page_start = 5 + n
    total = 4 + 2 * n

    out = bytearray()
    out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}

    def write_obj(num, body):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        offsets[num] = len(out)
        out.extend(b"%d 0 obj\n" % num)
        out.extend(body)
        out.extend(b"\nendobj\n")

    kids = " ".join(f"{page_start + i} 0 R" for i in range(n))
    write_obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    write_obj(2, f"<< /Type /Pages /Count {n} /Kids [{kids}] >>")
    write_obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    write_obj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    for i, content in enumerate(pages_content):
        stream = content.encode("latin-1", "replace")
        body = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        write_obj(content_start + i, body)

    for i in range(n):
        write_obj(page_start + i,
                  f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                  f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                  f"/Contents {content_start + i} 0 R >>")

    xref_pos = len(out)
    out.extend(b"xref\n0 %d\n" % (total + 1))
    out.extend(b"0000000000 65535 f \n")
    for num in range(1, total + 1):
        out.extend(b"%010d 00000 n \n" % offsets[num])
    out.extend(b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (total + 1))
    out.extend(b"startxref\n%d\n%%%%EOF\n" % xref_pos)
    return bytes(out)


# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Redirect to dashboard if logged in, otherwise login."""
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Authenticate user with parameterized query and bcrypt verification."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not username or not password:
            error = "Username and password are required."
            return render_template("login.html", error=error)

        if len(username) > 80 or len(password) > 128:
            error = "Invalid credentials."
            return render_template("login.html", error=error)

        if not validate_username(username):
            error = "Invalid credentials."
            return render_template("login.html", error=error)

        # SECURE: Parameterized query — no SQL injection
        db = get_db()
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # SECURE: bcrypt hash comparison — timing-safe
        if row and check_password(password, row["password"]):
            # SECURE: Session regeneration on login
            session.clear()
            session["user"] = row["username"]
            session["role"] = row["role"]
            session["user_id"] = row["id"]
            session["last_active"] = time.time()
            session.permanent = True
            return redirect(url_for("dashboard"))

        # Generic error — no information disclosure
        error = "Invalid credentials."
        return render_template("login.html", error=error)

    return render_template("login.html", error=error)


# ---------------------------------------------------------------------------
# Routes — Dashboard & Courses
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    """Show course catalog with enrollment status."""
    db = get_db()
    courses = db.execute(
        "SELECT id, title, summary, premium, price FROM courses ORDER BY id"
    ).fetchall()

    enrolled_ids = set()
    rows = db.execute(
        """SELECT course_id FROM enrollments e
           JOIN users u ON u.id = e.user_id
           WHERE u.username = ?""",
        (session["user"],),
    ).fetchall()
    for r in rows:
        enrolled_ids.add(r["course_id"])

    # Get user credits
    user = db.execute(
        "SELECT credits FROM users WHERE username = ?", (session["user"],)
    ).fetchone()

    return render_template(
        "dashboard.html",
        courses=courses,
        user=session["user"],
        role=session.get("role"),
        enrolled_ids=enrolled_ids,
        credits=user["credits"],
    )


@app.route("/course/<int:course_id>")
@login_required
def course(course_id):
    """View a single course — respects enrollment for premium content."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM courses WHERE id = ?", (course_id,)
    ).fetchone()
    if row is None:
        abort(404)

    enrolled = is_enrolled(session["user"], course_id)
    return render_template(
        "course.html",
        course=row,
        user=session["user"],
        role=session.get("role"),
        enrolled=enrolled,
    )


@app.route("/download/<int:course_id>")
@login_required
def download(course_id):
    """Download course PDF — enforces enrollment authorization."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM courses WHERE id = ?", (course_id,)
    ).fetchone()
    if row is None:
        abort(404)

    # SECURE: Authorization check — must be enrolled for premium content
    if row["premium"] and not is_enrolled(session["user"], course_id):
        abort(403)

    pdf = _course_pdf(row)
    filename = f"course-{row['id']}.pdf"
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Routes — Transaction Module (Purchase Courses)
# ---------------------------------------------------------------------------
@app.route("/buy/<int:course_id>", methods=["POST"])
@login_required
def buy_course(course_id):
    """Purchase a premium course using account credits."""
    db = get_db()
    course_row = db.execute(
        "SELECT * FROM courses WHERE id = ?", (course_id,)
    ).fetchone()
    if course_row is None:
        abort(404)

    # Check if already enrolled
    if is_enrolled(session["user"], course_id):
        flash("You are already enrolled in this course.", "error")
        return redirect(url_for("course", course_id=course_id))

    # Check if course is free
    if not course_row["premium"]:
        # Free course — enroll directly
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (?, ?, ?)",
            (session["user_id"], course_id, now),
        )
        db.commit()
        flash(f"Enrolled in {course_row['title']}!", "success")
        return redirect(url_for("course", course_id=course_id))

    # Check sufficient credits
    user = db.execute(
        "SELECT credits FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    price = course_row["price"]

    if user["credits"] < price:
        flash(f"Insufficient credits. You have ${user['credits']:.2f} but need ${price:.2f}.", "error")
        return redirect(url_for("course", course_id=course_id))

    # Process transaction
    now = datetime.utcnow().isoformat()
    new_balance = user["credits"] - price

    # Deduct credits
    db.execute(
        "UPDATE users SET credits = ? WHERE id = ?",
        (new_balance, session["user_id"]),
    )
    # Create enrollment
    db.execute(
        "INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (?, ?, ?)",
        (session["user_id"], course_id, now),
    )
    # Record transaction
    db.execute(
        "INSERT INTO transactions (user_id, course_id, type, amount, description, created_at) VALUES (?, ?, 'purchase', ?, ?, ?)",
        (session["user_id"], course_id, price, f"Purchased: {course_row['title']}", now),
    )
    db.commit()

    flash(f"Successfully purchased {course_row['title']} for ${price:.2f}! New balance: ${new_balance:.2f}", "success")
    return redirect(url_for("course", course_id=course_id))


@app.route("/transactions")
@login_required
def transactions():
    """View transaction history for current user."""
    db = get_db()
    rows = db.execute(
        """SELECT t.*, c.title as course_title
           FROM transactions t
           LEFT JOIN courses c ON c.id = t.course_id
           WHERE t.user_id = ?
           ORDER BY t.created_at DESC""",
        (session["user_id"],),
    ).fetchall()

    user = db.execute(
        "SELECT credits FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    return render_template(
        "transactions.html",
        transactions=rows,
        user=session["user"],
        role=session.get("role"),
        credits=user["credits"],
    )


# ---------------------------------------------------------------------------
# Routes — Admin Panel (Role-Based Access Control)
# ---------------------------------------------------------------------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    """Admin dashboard — manage users, courses, enrollments."""
    db = get_db()
    users = db.execute("SELECT id, username, role, credits FROM users ORDER BY id").fetchall()
    courses = db.execute("SELECT id, title, premium, price FROM courses ORDER BY id").fetchall()
    enrollments = db.execute(
        """SELECT e.id, u.username, c.title, c.id as course_id, e.enrolled_at
           FROM enrollments e
           JOIN users u ON u.id = e.user_id
           JOIN courses c ON c.id = e.course_id
           ORDER BY e.enrolled_at DESC"""
    ).fetchall()
    recent_transactions = db.execute(
        """SELECT t.*, u.username, c.title as course_title
           FROM transactions t
           JOIN users u ON u.id = t.user_id
           LEFT JOIN courses c ON c.id = t.course_id
           ORDER BY t.created_at DESC LIMIT 20"""
    ).fetchall()
    return render_template(
        "admin.html",
        users=users, courses=courses,
        enrollments=enrollments, recent_transactions=recent_transactions,
        user=session["user"], role=session.get("role"),
    )


@app.route("/admin/enroll", methods=["POST"])
@login_required
@admin_required
def admin_enroll():
    """Admin can enroll any user in a course."""
    username = request.form.get("username", "").strip()
    course_id_str = request.form.get("course_id", "").strip()

    if not username or not course_id_str:
        flash("Username and course ID are required.", "error")
        return redirect(url_for("admin_panel"))

    if not validate_username(username):
        flash("Invalid username format.", "error")
        return redirect(url_for("admin_panel"))

    try:
        course_id = int(course_id_str)
    except ValueError:
        flash("Invalid course ID.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))

    course_row = db.execute("SELECT id FROM courses WHERE id = ?", (course_id,)).fetchone()
    if not course_row:
        flash("Course not found.", "error")
        return redirect(url_for("admin_panel"))

    try:
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (?, ?, ?)",
            (user["id"], course_id, now),
        )
        db.commit()
        flash(f"Enrolled {username} in course #{course_id}.", "success")
    except sqlite3.IntegrityError:
        flash("User is already enrolled in that course.", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/credit", methods=["POST"])
@login_required
@admin_required
def admin_add_credit():
    """Admin can add credits to a user account."""
    username = request.form.get("username", "").strip()
    amount_str = request.form.get("amount", "").strip()

    if not username or not amount_str:
        flash("Username and amount are required.", "error")
        return redirect(url_for("admin_panel"))

    if not validate_username(username):
        flash("Invalid username format.", "error")
        return redirect(url_for("admin_panel"))

    try:
        amount = validate_amount(amount_str)
    except (ValueError, TypeError):
        flash("Invalid amount. Must be between 0 and 10000.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    user = db.execute("SELECT id, credits FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))

    now = datetime.utcnow().isoformat()
    new_balance = user["credits"] + amount
    db.execute("UPDATE users SET credits = ? WHERE id = ?", (new_balance, user["id"]))
    db.execute(
        "INSERT INTO transactions (user_id, type, amount, description, created_at) VALUES (?, 'credit', ?, ?, ?)",
        (user["id"], amount, f"Admin credit top-up by {session['user']}", now),
    )
    db.commit()
    flash(f"Added ${amount:.2f} to {username}. New balance: ${new_balance:.2f}", "success")
    return redirect(url_for("admin_panel"))


# ---------------------------------------------------------------------------
# Logout & Error Handlers
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    """Clear session securely on logout."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(_e):
    """403 Forbidden — limited information disclosure."""
    return render_template("error.html", code=403,
                           message="Access denied.",
                           user=session.get("user"),
                           role=session.get("role")), 403


@app.errorhandler(404)
def not_found(_e):
    """404 Not Found — limited information disclosure."""
    return render_template("error.html", code=404,
                           message="Page not found.",
                           user=session.get("user"),
                           role=session.get("role")), 404


@app.errorhandler(429)
def rate_limited(_e):
    """429 Too Many Requests — rate limit exceeded."""
    return render_template("error.html", code=429,
                           message="Too many attempts. Please wait a minute.",
                           user=session.get("user"),
                           role=session.get("role")), 429


@app.errorhandler(500)
def internal_error(_e):
    """500 Internal Server Error — no stack trace disclosure."""
    return render_template("error.html", code=500,
                           message="An unexpected error occurred.",
                           user=session.get("user"),
                           role=session.get("role")), 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
