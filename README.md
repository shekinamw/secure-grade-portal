# secure-grade-portal

A Flask web application demonstrating SQL injection, XSS, and broken authentication vulnerabilities alongside their mitigations. Built as part of a university computer security course.

---

## Setup

```bash
pip install -r requirements.txt
```

### Run the insecure version
```bash
cd insecure_app
python db_setup.py     # initialise the database
python app.py          # runs on http://localhost:5000
```

### Run the secure version
```bash
cd secure_app
python db_setup.py
python app.py          # runs on http://localhost:5001
```

---

## Demo credentials

| Username | Password   | Role    |
|----------|------------|---------|
| admin    | admin123   | admin   |
| student1 | password1  | student |
| student2 | qwerty     | student |

---

## Vulnerabilities demonstrated

| Attack | Insecure | Secure |
|--------|----------|--------|
| SQL Injection | Raw string concatenation in queries | Parameterized queries (`?` placeholders) |
| Stored XSS | Notes rendered with `\| safe` (raw HTML) | Jinja2 auto-escaping (default) |
| Broken Auth | Plaintext passwords in SQLite | bcrypt hashing with salt |
| Access Control | No session checks on protected routes | Role-based session enforcement |

---

## Course
SOFE4840U — Software & Computer Security  
Ontario Tech University, Winter 2026