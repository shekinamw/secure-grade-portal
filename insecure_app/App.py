"""
INSECURE VERSION - Student Grade Portal
Intentional vulnerabilities (demo only — do not deploy):
  1. SQL Injection on login        — raw string concat, use:  ' OR '1'='1'--
  2. SQL Injection on course search — raw string concat, use:  ' OR '1'='1'--
  3. Stolen credentials via UNION  — search: ' UNION SELECT id,username,password,student_id,password FROM users--
  4. Stored XSS                    — log in as bob, XSS fires on dashboard load
  5. Broken Auth                   — plaintext passwords visible in DB and /admin
  6. No access control on /admin   — visit without logging in
"""
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3, os

app = Flask(__name__)
app.secret_key = "secret"   # VULNERABILITY: weak hardcoded key

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
        # VULNERABILITY (SQL Injection): string concat — no parameterization.
        # Payload → username: ' OR '1'='1'--   password: anything
        query = ("SELECT * FROM users WHERE username='"
                 + username + "' AND password='" + password + "'")
        user = conn.execute(query).fetchone()
        conn.close()
        if user:
            session["username"]   = user["username"]
            session["role"]       = user["role"]
            session["student_id"] = user["student_id"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── STUDENT DASHBOARD ──────────────────────────────────────────────────────
@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))

    search     = request.form.get("search","").strip() if request.method == "POST" else ""
    student_id = session.get("student_id", "")
    conn       = get_db()

    if search:
        # VULNERABILITY (SQL Injection): search term injected directly.
        # Payload → ' OR '1'='1'--                dumps ALL students' grades
        # Payload → ' UNION SELECT id,username,password,student_id,password FROM users--
        #            shows the users table (with plaintext passwords) as grade cards
        query = ("SELECT * FROM grades WHERE student_id='"
                 + student_id
                 + "' AND course LIKE '%"
                 + search + "%'")
    else:
        query = "SELECT * FROM grades WHERE student_id='" + student_id + "'"

    courses = conn.execute(query).fetchall()
    conn.close()
    return render_template("dashboard.html",
                           username=session.get("username"),
                           role=session.get("role"),
                           courses=courses,
                           search=search)

# ── ADMIN ──────────────────────────────────────────────────────────────────
@app.route("/admin")
def admin():
    # VULNERABILITY: zero session/role check — anyone can visit /admin directly
    conn    = get_db()
    users   = conn.execute("SELECT * FROM users").fetchall()
    grades  = conn.execute("SELECT * FROM grades").fetchall()
    conn.close()
    return render_template("admin.html",
                           username=session.get("username"),
                           role=session.get("role"),
                           users=users, grades=grades)

if __name__ == "__main__":
    app.run(debug=True, port=5000)