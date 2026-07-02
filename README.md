# 📚 LearnHub — Intentionally Vulnerable E-Learning Lab

A tiny, deliberately vulnerable e-learning site for practicing web security.
Flask + SQLite, minimalist UI, runs in one small Docker container.

> ⚠️ **For local, educational use only.** Contains intentional SQL injection and IDOR bugs.
> Do **not** expose it to the internet.

## Stack
- Python 3.12 (slim) + Flask, stdlib `sqlite3` — no ORM, no JS frameworks
- One `app.py`, a few Jinja templates, one CSS file

## Run
```bash
docker compose up --build
# → http://127.0.0.1:5000
```

## What to practice
| # | Vulnerability | Page | Guide |
|---|---------------|------|-------|
| 1 | SQL Injection (auth bypass) | `/login` | see [EXPLOIT.md](EXPLOIT.md) |
| 2 | IDOR (premium download) | `/download/<id>` | see [EXPLOIT.md](EXPLOIT.md) |

**[EXPLOIT.md](EXPLOIT.md)** has step-by-step exploits, payloads, the exact vulnerable
source locations, and patched code for both bugs.

## Files
```
app.py               # routes + DB seed (vulns marked with # [VULN ...])
templates/           # base, login, dashboard, course
static/style.css     # minimalist dark UI
Dockerfile           # python:3.12-slim
docker-compose.yml   # builds + maps 127.0.0.1:5000
requirements.txt     # Flask only
EXPLOIT.md           # exploit + patch guide
```

## Reset
```bash
docker compose down && docker compose up --build   # DB re-seeds on startup
```
