"""
INSECURE VERSION - Database setup
Passwords stored as plaintext — intentional vulnerability.
"""
import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "grades.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS grades")

    # VULNERABILITY: password stored as plaintext
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

    # Set up users info
    users = [
        ("admin",  "admin123",  "0000", "admin"),
        ("alice",  "password1", "1001", "student"),
        ("bob",    "qwerty",    "1002", "student"),
        ("carol",  "letmein",   "1003", "student"),
    ]
    c.executemany(
        "INSERT INTO users (username, password, student_id, role) VALUES (?,?,?,?)",
        users
    )

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
        # Bob's SOFE4500U record has a stored XSS payload in the notes
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
    print("DB ready.")
    print("Logins:  alice/password1 · bob/qwerty · carol/letmein · admin/admin123")

if __name__ == "__main__":
    init_db()
