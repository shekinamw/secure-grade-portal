# Secure Grade Portal — Security Fixes Reference

This document explains every security vulnerability present in the **insecure** version of the Student Grade Portal and describes precisely how it was fixed in the **secure** version. It is intended as a companion to the final report for SOFE4840U Group 6.

---

## Table of Contents

1. [SQL Injection — Login Bypass](#1-sql-injection--login-bypass)
2. [SQL Injection — Grade Search (Data Exposure)](#2-sql-injection--grade-search-data-exposure)
3. [SQL Injection — UNION Attack (Credential Theft)](#3-sql-injection--union-attack-credential-theft)
4. [Stored Cross-Site Scripting (XSS)](#4-stored-cross-site-scripting-xss)
5. [Plaintext Password Storage](#5-plaintext-password-storage)
6. [Broken Access Control — Unauthenticated Admin Route](#6-broken-access-control--unauthenticated-admin-route)
7. [Weak Session Secret](#7-weak-session-secret)

---

## 1. SQL Injection — Login Bypass

### Vulnerability (Insecure Version)

The login route builds its SQL query by directly concatenating the user-supplied username into a string:

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

An attacker can enter the following in the username field:

```
' OR '1'='1'--
```

This transforms the query into:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = '...'
```

Because `'1'='1'` is always true and `--` comments out the rest, the query returns the first user in the database regardless of what password was entered. The attacker is logged in without valid credentials.

**CIA Impact:** Confidentiality — unauthorized access to a student account.

### Fix (Secure Version)

The secure version uses a **parameterized query** (also called a prepared statement):

```python
query = "SELECT * FROM users WHERE username = ?"
user = db.execute(query, (username,)).fetchone()
```

The `?` placeholder is handled by Python's `sqlite3` driver, which sends the query structure and the user input to the database engine as two separate operations. The database engine **never interprets the input as SQL code** — it treats it purely as a data value. No string concatenation occurs, so the injection payload `' OR '1'='1'--` is matched literally against the `username` column and finds no row.

---

## 2. SQL Injection — Grade Search (Data Exposure)

### Vulnerability (Insecure Version)

The grade search route concatenates the student ID directly into the query:

```python
query = "SELECT * FROM grades WHERE student_id = '" + student_id + "'"
```

An attacker enters:

```
' OR '1'='1'--
```

The resulting query returns **every row in the grades table**, exposing all students' academic records without authorization.

**CIA Impact:** Confidentiality — full database read by an unauthorized party.

### Fix (Secure Version)

The secure version uses a parameterized query **and** restricts results to the currently logged-in student only, so even a valid student cannot query another student's records:

```python
query = "SELECT * FROM grades WHERE student_id = ?"
grades = db.execute(query, (session['student_id'],)).fetchall()
```

The search field is removed entirely from student-facing pages. The student ID is always taken from the server-side session, never from user input.

---

## 3. SQL Injection — UNION Attack (Credential Theft)

### Vulnerability (Insecure Version)

Because the grade search query is injectable, an attacker can use a `UNION`-based payload to append a second query that reads from the `users` table:

```
' UNION SELECT username, password, username, password FROM users--
```

This appends a second result set containing all usernames and passwords to the grade results, displaying them directly in the browser. Even if passwords were hashed, this leaks the hash values for offline cracking.

**CIA Impact:** Confidentiality — full credential database extracted through the UI.

### Fix (Secure Version)

Parameterized queries neutralize UNION injection for the same reason described in Fix #2: the payload is treated as a literal string value, not executable SQL. The `UNION` keyword and everything after it is never parsed by the database engine.

---

## 4. Stored Cross-Site Scripting (XSS)

### Vulnerability (Insecure Version)

The grade display template renders the `notes` field from the database using Jinja2's `safe` filter, which explicitly disables output escaping:

```html
<td>{{ c.notes | safe }}</td>
```

If a professor (or an attacker with database access) stores the following value in a notes field:

```html
<script>alert('XSS')</script>
```

Every student who loads the grade page will have that script execute in their browser. In a more targeted attack, the script could steal session cookies and send them to an external server, allowing session hijacking.

**CIA Impact:** Integrity — malicious content injected into legitimate pages. Confidentiality — session tokens can be exfiltrated.

### Fix (Secure Version)

The `| safe` filter is removed. Jinja2's **default auto-escaping** is restored:

```html
<td>{{ c.notes }}</td>
```

Jinja2 converts any HTML characters in the `notes` string into their safe HTML entity equivalents before sending the page to the browser. For example:

| Raw input | Rendered output |
|-----------|----------------|
| `<script>` | `&lt;script&gt;` |
| `"` | `&quot;` |
| `&` | `&amp;` |

The browser displays these as literal text rather than interpreting them as markup or code. The script never executes.

---

## 5. Plaintext Password Storage

### Vulnerability (Insecure Version)

Passwords are stored in the SQLite database as plain text:

```
username | password
---------|----------
alice    | password123
admin    | admin123
```

If an attacker gains access to the `.db` file (via SQL injection, a misconfigured server, or physical access), every user's password is immediately readable — including passwords they may reuse on other services.

**CIA Impact:** Confidentiality — direct credential exposure.

### Fix (Secure Version)

The secure version uses **bcrypt** to hash passwords before storing them. bcrypt is a one-way adaptive hashing function designed specifically for passwords.

```python
import bcrypt

# At registration / database seeding:
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
# stored value: $2b$12$eW5... (60-character hash)

# At login:
if bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash):
    # login succeeds
```

Key properties of bcrypt that make it appropriate here:

- **One-way:** There is no function that reverses a bcrypt hash back to the original password.
- **Salted:** `bcrypt.gensalt()` generates a random salt for every password, so two users with the same password produce different hashes. This defeats rainbow table attacks.
- **Adaptive work factor:** The cost parameter (default `12`) controls how many rounds of hashing occur. As hardware gets faster, the cost can be increased to keep brute-force attacks slow.

NIST SP 800-63B explicitly recommends using a memory-hard or slow hashing function such as bcrypt for credential storage, which this implementation follows.

---

## 6. Broken Access Control — Unauthenticated Admin Route

### Vulnerability (Insecure Version)

The `/admin` route has no authentication check:

```python
@app.route('/admin')
def admin():
    # No session check — anyone can reach this page
    students = db.execute("SELECT * FROM users").fetchall()
    return render_template('admin.html', students=students)
```

Any user who navigates directly to `http://localhost:5000/admin` in their browser receives the full admin dashboard, including all student records.

**CIA Impact:** Confidentiality — unauthorized access to privileged data.

### Fix (Secure Version)

The secure version checks the session for both an authenticated user and the `admin` role before serving the page:

```python
@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        abort(403)
    students = db.execute("SELECT * FROM users").fetchall()
    return render_template('admin.html', students=students)
```

If either condition fails, Flask returns a **403 Forbidden** response. The database query never executes. The same session and role check is applied to every protected route — there is no way to bypass it by guessing a URL.

---

## 7. Weak Session Secret

### Vulnerability (Insecure Version)

Flask uses a secret key to cryptographically sign session cookies. In the insecure version, this key is hardcoded as a short, predictable string:

```python
app.secret_key = 'secret'
```

Flask session cookies are Base64-encoded and signed with HMAC-SHA1 using this key. If an attacker knows (or can guess) the secret key, they can forge a valid session cookie for any user — including the admin — without ever logging in.

**CIA Impact:** Confidentiality and Integrity — session forgery enables full impersonation.

### Fix (Secure Version)

The secure version generates a cryptographically random 24-byte secret at startup using Python's `os.urandom`:

```python
import os
app.secret_key = os.urandom(24)
```

`os.urandom` reads from the operating system's cryptographically secure random number generator (e.g., `/dev/urandom` on Linux). The resulting key has 192 bits of entropy, making it computationally infeasible to brute-force or guess. Because it is regenerated each time the server starts, it is never stored where an attacker could find it.

---

## Summary Table

| # | Vulnerability | OWASP Category | Insecure Pattern | Secure Fix |
|---|--------------|----------------|------------------|------------|
| 1 | SQL Injection (login) | A03:2021 Injection | String concatenation in query | Parameterized query (`?` placeholder) |
| 2 | SQL Injection (search) | A03:2021 Injection | User input in WHERE clause | Parameterized query + session-scoped results |
| 3 | SQL Injection (UNION) | A03:2021 Injection | Injectable query allows UNION | Parameterized query neutralizes payload |
| 4 | Stored XSS | A03:2021 Injection | `{{ c.notes \| safe }}` bypasses escaping | Default Jinja2 auto-escaping restored |
| 5 | Plaintext Passwords | A07:2021 Auth Failures | Raw text in database | bcrypt one-way hash with salt |
| 6 | Broken Access Control | A01:2021 Broken Access Control | No session check on `/admin` | Session + role check, `abort(403)` on failure |
| 7 | Weak Session Secret | A07:2021 Auth Failures | Hardcoded `'secret'` key | `os.urandom(24)` at startup |

---

*SOFE4840U Software & Computer Security — Group 6 | Ontario Tech University*