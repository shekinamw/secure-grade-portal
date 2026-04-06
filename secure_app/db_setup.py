"""
SECURE VERSION - Database setup
---------------------------------
SECURITY MEASURE — Broken Authentication fix:
  Passwords are hashed with bcrypt before being stored.
  bcrypt is a one-way function — the original password cannot be recovered
  from the hash, even with full database access.
  Each hash includes a random salt, so identical passwords produce
  different hashes, preventing rainbow table attacks.
"""
import sqlite3, os, bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "grades.db")

def hash_password(plaintext):
    """Hash a password with bcrypt. Returns a string ready to store."""
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS grades")

    # Same schema as the insecure version — the only difference is the
    # password column now stores a bcrypt hash, not a plaintext string.
    c.execute("""
        CREATE TABLE users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL UNIQUE,
            password    TEXT NOT NULL,
            student_id  TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'student'
        )
    """)
    c.execute("""
        CREATE TABLE grades (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            course     TEXT NOT NULL,
            grade      TEXT NOT NULL,
            notes      TEXT
        )
    """)

    # SECURITY MEASURE: passwords are hashed with bcrypt before INSERT.
    # Opening this .db file reveals only $2b$12$... strings — useless to an attacker.
    users = [
        ("admin", hash_password("admin123"),  "0000", "admin"),
        ("alice", hash_password("password1"), "1001", "student"),
        ("bob",   hash_password("qwerty"),    "1002", "student"),
        ("carol", hash_password("letmein"),   "1003", "student"),
    ]
    c.executemany(
        "INSERT INTO users (username, password, student_id, role) VALUES (?,?,?,?)",
        users
    )

    # NOTE: the XSS payload is still stored in the database here —
    # but in the secure version the template escapes it, so it renders
    # as visible text rather than executing as code.
    grades = [
        # ── Alice (1001) ──────────────────────────────────────────────────
        ("1001","SOFE4840U - Software & Computer Security","A",
         "Excellent project work. Strong grasp of threat modelling and mitigation strategies."),
        ("1001","SOFE3650U - Software Design and Architectures","B+",
         "Good understanding of design patterns. UML diagrams were well structured."),
        ("1001","SOFE4500U - Software Requirements","A-",
         "Thorough requirements analysis. Use-case coverage was particularly strong."),
        ("1001","SOFE3700U - Software Correctness and Robustness","B",
         "Solid test coverage overall. Formal proof sections could be more rigorous."),
        ("1001","SOFE2720U - Data Structures","A+",
         "Outstanding performance. Fastest runtime on the sorting assignment."),

        # ── Bob (1002) ────────────────────────────────────────────────────
        ("1002","SOFE4840U - Software & Computer Security","C+",
         "Needs to engage more with security concepts beyond the surface level."),
        ("1002","SOFE3650U - Software Design and Architectures","B",
         "Adequate design skills. Diagrams were readable but lacked detail."),
        # Same XSS payload as insecure version — but the secure template
        # will escape it to plain text, so it never executes.
        ("1002","SOFE4500U - Software Requirements","B-",
         "<script>alert('XSS: cookie = ' + document.cookie)</script>"),
        ("1002","SOFE2720U - Data Structures","C",
         "Struggled with tree traversals. Recommended to revisit recursion fundamentals."),

        # ── Carol (1003) ──────────────────────────────────────────────────
        ("1003","SOFE4840U - Software & Computer Security","A+",
         "Outstanding. Best security analysis report in the class. Publication quality."),
        ("1003","SOFE3650U - Software Design and Architectures","A",
         "Excellent architecture diagrams. System decomposition was clean and justified."),
        ("1003","SOFE4500U - Software Requirements","A",
         "Very well written requirements specification. Minimal ambiguity throughout."),
        ("1003","SOFE3700U - Software Correctness and Robustness","A-",
         "Strong formal methods background. Proofs were concise and correct."),
    ]
    c.executemany(
        "INSERT INTO grades (student_id, course, grade, notes) VALUES (?,?,?,?)",
        grades
    )
    conn.commit()
    conn.close()
    print("Secure DB ready.")
    print("Logins: alice/password1 · bob/qwerty · carol/letmein · admin/admin123")
    print("Passwords are stored as bcrypt hashes — run:")
    print("  sqlite3 grades.db \"SELECT username, password FROM users;\"")
    print("to see the difference from the insecure version.")

if __name__ == "__main__":
    init_db()
