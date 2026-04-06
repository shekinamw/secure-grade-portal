"""
SECURE VERSION - Student Grade Portal
---------------------------------------
Every vulnerability from the insecure version is fixed here.
Each fix is documented inline next to the code it replaces.

Fix summary:
  1. SQL Injection (login)    → parameterized query with ? placeholder
  2. SQL Injection (search)   → parameterized query with ? placeholder
  3. Stored XSS               → Jinja2 default escaping (no | safe)
  4. Broken Authentication    → bcrypt.checkpw() instead of plaintext compare
  5. Broken Access Control    → session role check on every protected route
  6. Weak session secret      → os.urandom(24) — cryptographically random key
"""
from flask import Flask, render_template, request, redirect, url_for, session, abort
import sqlite3, os, bcrypt

app = Flask(__name__)

# SECURITY MEASURE (fix #6 — Weak Session Secret):
# os.urandom(24) generates 24 cryptographically random bytes (192 bits of entropy).
# This is computationally infeasible to brute-force, unlike the hardcoded "secret"
# in the insecure version which can be cracked in seconds with flask-unsign.
# For production, load this from an environment variable so it never appears in code.
app.secret_key = os.urandom(24)

DB_PATH = os.path.join(os.path.dirname(__file__), "grades.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── LOGIN ──────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()

        # SECURITY MEASURE (fix #1 — SQL Injection on login):
        # The ? placeholder tells the database driver to treat the username
        # as a literal data value, never as SQL syntax.
        # The payload  ' OR '1'='1'--  becomes a literal string to search for,
        # which matches no username, so login correctly fails.
        #
        # INSECURE:  "WHERE username='" + username + "' AND password='" + password + "'"
        # SECURE:    "WHERE username=?"  with (username,) passed separately
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        conn.close()

        if user:
            # SECURITY MEASURE (fix #4 — Broken Authentication):
            # bcrypt.checkpw() hashes the submitted password and compares it
            # to the stored hash. The original password is never stored anywhere.
            # Even if an attacker reads the database, they only see $2b$12$... hashes.
            #
            # INSECURE:  password stored as plaintext, compared directly
            # SECURE:    bcrypt.checkpw(submitted, stored_hash)
            password_matches = bcrypt.checkpw(
                password.encode("utf-8"),
                user["password"].encode("utf-8")
            )
            if password_matches:
                session["username"]   = user["username"]
                session["role"]       = user["role"]
                session["student_id"] = user["student_id"]
                return redirect(url_for("dashboard"))

        # Deliberately vague error — don't reveal whether username or password was wrong
        error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── STUDENT DASHBOARD ──────────────────────────────────────────────────────
@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    # SECURITY MEASURE (fix #5 — Broken Access Control):
    # Every protected route checks the session before doing anything.
    # If there is no active login, the user is redirected to the login page.
    if not session.get("username"):
        return redirect(url_for("login"))

    search     = request.form.get("search","").strip() if request.method == "POST" else ""
    student_id = session.get("student_id","")
    conn       = get_db()

    # SECURITY MEASURE (fix #2 — SQL Injection on course search):
    # Both student_id and the search term are passed as parameters.
    # The payload  ' OR '1'='1'--  is treated as a literal string —
    # it matches no course name, so the result is empty rather than
    # dumping all records. The UNION attack also fails because the
    # input is never interpreted as SQL.
    #
    # INSECURE:  "... student_id='" + student_id + "' AND course LIKE '%" + search + "%'"
    # SECURE:    "... student_id=? AND course LIKE ?"  with values passed as tuple
    if search:
        courses = conn.execute(
            "SELECT * FROM grades WHERE student_id=? AND course LIKE ?",
            (student_id, f"%{search}%")
        ).fetchall()
    else:
        courses = conn.execute(
            "SELECT * FROM grades WHERE student_id=?",
            (student_id,)
        ).fetchall()

    conn.close()
    return render_template("dashboard.html",
                           username=session.get("username"),
                           role=session.get("role"),
                           courses=courses,
                           search=search)

# ── ADMIN ──────────────────────────────────────────────────────────────────
@app.route("/admin")
def admin():
    # SECURITY MEASURE (fix #5 — Broken Access Control):
    # Two checks:
    #   1. Is there an active session at all?
    #   2. Does that session have the admin role?
    # If either check fails, Flask returns a 403 Forbidden response.
    # In the insecure version there were no checks — anyone could visit /admin.
    if not session.get("username"):
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        abort(403)

    conn    = get_db()
    users   = conn.execute("SELECT * FROM users").fetchall()
    grades  = conn.execute("SELECT * FROM grades").fetchall()
    conn.close()
    return render_template("admin.html",
                           username=session.get("username"),
                           role=session.get("role"),
                           users=users, grades=grades)

if __name__ == "__main__":
    # debug=False in the secure version — debug mode exposes stack traces
    # and an interactive console to anyone who triggers an error.
    app.run(debug=False, port=5001)

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403
