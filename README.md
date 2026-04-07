# secure-grade-portal

**SOFE4840U Software & Computer Security — Group 6**
Ontario Tech University

A dual-version web application built to demonstrate common web security vulnerabilities alongside their mitigations. The project consists of two independently runnable Flask applications that share the same visual design but differ entirely in their security posture.

---

## Project Overview

| Version | Directory | Purpose |
|---------|-----------|---------|
| Insecure | `insecure_app/` | Intentionally vulnerable — used to demonstrate attacks |
| Secure | `secure_app/` | Hardened — used to demonstrate each fix |

Both apps simulate a Student Grade Portal for a fictional academic institution. The contrast between them is the core deliverable of the project.

**Vulnerabilities demonstrated:**

1. SQL Injection — login bypass
2. SQL Injection — full database read via grade search
3. SQL Injection — UNION-based credential theft
4. Stored Cross-Site Scripting (XSS)
5. Plaintext password storage
6. Unauthenticated admin route (broken access control)
7. Weak hardcoded session secret

---

## Repository Structure

```
secure-grade-portal/
├── insecure_app/
│   ├── app.py               # Vulnerable Flask application
│   ├── init_db.py           # Seeds database with plaintext passwords
│   ├── students.db          # SQLite database (generated)
│   └── templates/
│       ├── login.html
│       ├── dashboard.html
│       └── admin.html
│
├── secure_app/
│   ├── app.py               # Hardened Flask application
│   ├── init_db.py           # Seeds database with bcrypt-hashed passwords
│   ├── students.db          # SQLite database (generated)
│   └── templates/
│       ├── login.html
│       ├── dashboard.html
│       ├── admin.html
│       └── 403.html
│
├── README.md                # This file
└── README_secure_app.md     # Detailed fix-by-fix security reference
```

---

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Install dependencies

```bash
pip install flask bcrypt
```

### Running the insecure app

```bash
cd insecure_app
python init_db.py      # Creates and seeds the database
python app.py          # Starts the server on http://localhost:5000
```

### Running the secure app

```bash
cd secure_app
python init_db.py      # Creates and seeds the database with hashed passwords
python app.py          # Starts the server on http://localhost:5001
```

Run both simultaneously during the demo to show them side by side in two browser tabs.

---

## Demo Accounts

| Username | Password | Role |
|----------|----------|------|
| `alice` | `password123` | Student (primary demo account) |
| `bob` | `pass456` | Student |
| `admin` | `admin123` | Admin |

---

## Demo Attack Reference

### Attack 1 — SQL Injection Login Bypass

**Target:** Insecure app login page

Enter in the **Username** field:
```
' OR '1'='1'--
```
Enter anything in the Password field. You will be logged in as the first user in the database without valid credentials.

**Secure app result:** Login fails. The parameterized query treats the payload as a literal string, no user matches, and access is denied.

---

### Attack 2 — SQL Injection Full Grade Dump

**Target:** Insecure app grade search bar (after logging in)

Enter in the **Student ID** search field:
```
' OR '1'='1'--
```
Every student's grades are returned regardless of your logged-in identity.

**Secure app result:** The search field does not accept arbitrary IDs. Results are always scoped to the session user via a parameterized query.

---

### Attack 3 — UNION-Based Credential Theft

**Target:** Insecure app grade search bar

Enter:
```
' UNION SELECT username, password, username, password FROM users--
```
All usernames and plaintext passwords from the users table are displayed in the grade results table.

**Secure app result:** The parameterized query treats the entire input as a data value. The UNION keyword is never parsed by the database engine. No data is returned.

---

### Attack 4 — Stored XSS

**Target:** Insecure app — any page that renders the `notes` field for `alice`'s courses

The database has been pre-seeded with a malicious script in one of alice's course notes:
```html
<script>alert('XSS: session cookie = ' + document.cookie)</script>
```

Log in as `alice` and navigate to the dashboard. The script executes immediately in the browser.

**Secure app result:** Log in as `alice` in the secure app. The same note value is stored in the database, but Jinja2 escapes it to `&lt;script&gt;...&lt;/script&gt;` before rendering. The browser displays it as text — nothing executes.

---

### Attack 5 — Plaintext Password Exposure

**Target:** Insecure app database file

Open the SQLite database directly in a terminal or DB browser:

```bash
sqlite3 insecure_app/students.db "SELECT * FROM users;"
```

All passwords are visible in plain text.

**Secure app result:**

```bash
sqlite3 secure_app/students.db "SELECT * FROM users;"
```

Passwords are stored as 60-character bcrypt hashes (e.g., `$2b$12$eW5...`). They cannot be reversed.

---

### Attack 6 — Unauthenticated Admin Access

**Target:** Insecure app

Without logging in, navigate directly to:
```
http://localhost:5000/admin
```
The admin dashboard loads and displays all student records.

**Secure app result:** Navigating to `http://localhost:5001/admin` without an admin session returns a **403 Forbidden** page. The database is never queried.

---

### Attack 7 — Session Cookie Forgery (Conceptual)

**Target:** Insecure app

The insecure app uses `app.secret_key = 'secret'`. Flask signs session cookies with this key using HMAC-SHA1. Because the key is publicly known (visible in the source code), an attacker can use a tool like `flask-unsign` to forge a session cookie for any user:

```bash
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'secret'
```

Submitting the forged cookie to the server grants admin access without logging in.

**Secure app result:** The secure app generates its secret with `os.urandom(24)` at startup — 192 bits of entropy. The key is never stored or exposed. Forging a cookie is computationally infeasible.

---

## Security Fixes Summary

For a detailed technical explanation of each fix — including code comparisons, the mechanism behind each mitigation, and NIST/OWASP references — see [`README_secure_app.md`](./README_secure_app.md).

| Vulnerability | OWASP Category | Fix Applied |
|---------------|----------------|-------------|
| SQL Injection (login) | A03:2021 Injection | Parameterized queries |
| SQL Injection (search) | A03:2021 Injection | Parameterized queries + session-scoped results |
| SQL Injection (UNION) | A03:2021 Injection | Parameterized queries |
| Stored XSS | A03:2021 Injection | Jinja2 auto-escaping (removed `\| safe`) |
| Plaintext passwords | A07:2021 Auth Failures | bcrypt hashing with salt |
| Broken access control | A01:2021 Broken Access Control | Session + role check, `abort(403)` |
| Weak session secret | A07:2021 Auth Failures | `os.urandom(24)` |

---

## References

- OWASP Foundation. (2021). *OWASP Top Ten*. https://owasp.org/www-project-top-ten/
- NIST. (2020). *Digital Identity Guidelines — SP 800-63B*. https://pages.nist.gov/800-63-3/sp800-63b.html
- Python Software Foundation. *sqlite3 — DB-API 2.0 interface for SQLite*. https://docs.python.org/3/library/sqlite3.html
- Jinja2 Documentation. *HTML Escaping*. https://jinja.palletsprojects.com/en/3.1.x/templates/#html-escaping

---

*SOFE4840U Software & Computer Security — Group 6 | Ontario Tech University*
