import asyncio
import json
import os
from datetime import datetime, timedelta

from flask import Flask, flash, redirect, render_template, request, session, url_for
from libsql_client import create_client
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
DATABASE_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")

if not DATABASE_URL:
    raise RuntimeError("TURSO_DATABASE_URL is not set. Store it in Replit Secrets.")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")


async def _execute(query, args=None):
    async with create_client(DATABASE_URL, auth_token=DATABASE_AUTH_TOKEN) as client:
        return await client.execute(query, args or ())


def db_execute(query, args=None):
    return asyncio.run(_execute(query, args))


def db_fetchall(query, args=None):
    result = asyncio.run(_execute(query, args))
    return [dict(zip(result.columns, row)) for row in result.rows]


def db_fetchone(query, args=None):
    rows = db_fetchall(query, args)
    return rows[0] if rows else None


def init_db():
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
        """
    )
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS mcqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            options_json TEXT NOT NULL,
            correct_index INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        )
        """
    )
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mcq_id INTEGER NOT NULL,
            selected_index INTEGER NOT NULL,
            is_correct INTEGER NOT NULL,
            attempted_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(mcq_id) REFERENCES mcqs(id)
        )
        """
    )
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mode TEXT NOT NULL,
            subject_ids_json TEXT NOT NULL,
            question_count INTEGER NOT NULL,
            time_limit_minutes INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            submitted_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS exam_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            mcq_id INTEGER NOT NULL,
            selected_index INTEGER,
            is_correct INTEGER,
            FOREIGN KEY(exam_id) REFERENCES exams(id),
            FOREIGN KEY(mcq_id) REFERENCES mcqs(id)
        )
        """
    )


def ensure_admin_seed():
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_email or not admin_password:
        return
    existing = db_fetchone("SELECT id FROM users WHERE email = ?", (admin_email,))
    if existing:
        return
    db_execute(
        "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)",
        (admin_email, generate_password_hash(admin_password), datetime.utcnow().isoformat()),
    )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db_fetchone("SELECT id, email, is_admin FROM users WHERE id = ?", (user_id,))

@app.context_processor
def inject_current_user():
    return {"current_user": current_user()}


def login_required(func):
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user["is_admin"]:
            flash("Admin access required.")
            return redirect(url_for("dashboard"))
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.")
            return render_template("signup.html")
        existing = db_fetchone("SELECT id FROM users WHERE email = ?", (email,))
        if existing:
            flash("Email already registered.")
            return render_template("signup.html")
        db_execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            (email, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db_fetchone("SELECT id, password_hash FROM users WHERE email = ?", (email,))
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.")
            return render_template("login.html")
        session["user_id"] = user["id"]
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    subjects = db_fetchall(
        """
        SELECT subjects.id, subjects.name, COUNT(mcqs.id) AS mcq_count
        FROM subjects
        LEFT JOIN mcqs ON mcqs.subject_id = subjects.id
        GROUP BY subjects.id
        ORDER BY subjects.name
        """
    )
    total_mcqs = sum(item["mcq_count"] for item in subjects)
    attempts = db_fetchone(
        """
        SELECT COUNT(*) AS total_attempts,
               SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) AS correct_attempts
        FROM attempts
        WHERE user_id = ?
        """,
        (user["id"],),
    )
    attempts = attempts or {"total_attempts": 0, "correct_attempts": 0}
    accuracy = 0
    if attempts["total_attempts"]:
        accuracy = round((attempts["correct_attempts"] / attempts["total_attempts"]) * 100, 2)
    trend_rows = db_fetchall(
        """
        SELECT DATE(attempted_at) AS attempt_date,
               COUNT(*) AS total,
               SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) AS correct
        FROM attempts
        WHERE user_id = ?
        GROUP BY DATE(attempted_at)
        ORDER BY attempt_date DESC
        LIMIT 7
        """,
        (user["id"],),
    )
    trends = [
        {
            "date": row["attempt_date"],
            "accuracy": round((row["correct"] / row["total"]) * 100, 2) if row["total"] else 0,
        }
        for row in trend_rows
    ]
    return render_template(
        "dashboard.html",
        user=user,
        subjects=subjects,
        total_mcqs=total_mcqs,
        attempts=attempts,
        accuracy=accuracy,
        trends=trends,
    )


@app.route("/admin")
@admin_required
def admin_panel():
    return redirect(url_for("admin_subjects"))


@app.route("/admin/subjects", methods=["GET", "POST"])
@admin_required
def admin_subjects():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Subject name is required.")
        else:
            try:
                db_execute("INSERT INTO subjects (name) VALUES (?)", (name,))
                flash("Subject added.")
            except Exception:
                flash("Subject already exists.")
        return redirect(url_for("admin_subjects"))
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    return render_template("admin_subjects.html", subjects=subjects)


@app.route("/admin/subjects/<int:subject_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_subject(subject_id):
    subject = db_fetchone("SELECT id, name FROM subjects WHERE id = ?", (subject_id,))
    if not subject:
        flash("Subject not found.")
        return redirect(url_for("admin_subjects"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Subject name is required.")
        else:
            db_execute("UPDATE subjects SET name = ? WHERE id = ?", (name, subject_id))
            flash("Subject renamed.")
            return redirect(url_for("admin_subjects"))
    return render_template("edit_subject.html", subject=subject)


@app.route("/admin/subjects/<int:subject_id>/delete", methods=["POST"])
@admin_required
def delete_subject(subject_id):
    db_execute("DELETE FROM mcqs WHERE subject_id = ?", (subject_id,))
    db_execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
    flash("Subject deleted.")
    return redirect(url_for("admin_subjects"))


@app.route("/admin/mcqs")
@admin_required
def admin_mcqs():
    subject_id = request.args.get("subject_id", "all")
    page = max(int(request.args.get("page", 1)), 1)
    offset = (page - 1) * 100
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    params = []
    where_clause = ""
    if subject_id != "all":
        where_clause = "WHERE subjects.id = ?"
        params.append(int(subject_id))
    mcqs = db_fetchall(
        f"""
        SELECT mcqs.id, mcqs.question, mcqs.options_json, mcqs.correct_index,
               subjects.name AS subject_name
        FROM mcqs
        JOIN subjects ON subjects.id = mcqs.subject_id
        {where_clause}
        ORDER BY mcqs.id
        LIMIT 100 OFFSET {offset}
        """,
        tuple(params),
    )
    for mcq in mcqs:
        mcq["options"] = json.loads(mcq["options_json"])
    return render_template(
        "admin_mcqs.html",
        mcqs=mcqs,
        subjects=subjects,
        selected_subject=subject_id,
        page=page,
    )


@app.route("/admin/mcqs/add", methods=["GET", "POST"])
@admin_required
def add_mcq():
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    if request.method == "POST":
        subject_id = int(request.form.get("subject_id"))
        question = request.form.get("question", "").strip()
        options = [
            opt.strip()
            for opt in request.form.get("options", "").split("\n")
            if opt.strip()
        ]
        correct_index = int(request.form.get("correct_index", 0))
        if not question or len(options) < 2:
            flash("Provide a question and at least two options.")
            return render_template("add_mcq.html", subjects=subjects)
        if correct_index < 0 or correct_index >= len(options):
            flash("Correct index is out of range.")
            return render_template("add_mcq.html", subjects=subjects)
        db_execute(
            """
            INSERT INTO mcqs (subject_id, question, options_json, correct_index, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                subject_id,
                question,
                json.dumps(options),
                correct_index,
                datetime.utcnow().isoformat(),
            ),
        )
        flash("MCQ added.")
        return redirect(url_for("admin_mcqs"))
    return render_template("add_mcq.html", subjects=subjects)


@app.route("/admin/mcqs/upload", methods=["GET", "POST"])
@admin_required
def upload_mcqs():
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    if request.method == "POST":
        payload = request.form.get("mcq_json", "")
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            flash("Invalid JSON.")
            return render_template("upload_mcqs.html", subjects=subjects)
        if not isinstance(data, list):
            flash("JSON should be a list of MCQs.")
            return render_template("upload_mcqs.html", subjects=subjects)
        created = 0
        for item in data:
            subject_name = item.get("subject")
            question = item.get("question")
            options = item.get("options")
            correct_index = item.get("correct_index")
            if not (subject_name and question and options and correct_index is not None):
                continue
            subject = db_fetchone("SELECT id FROM subjects WHERE name = ?", (subject_name,))
            if not subject:
                db_execute("INSERT INTO subjects (name) VALUES (?)", (subject_name,))
                subject = db_fetchone("SELECT id FROM subjects WHERE name = ?", (subject_name,))
            if not isinstance(options, list) or len(options) < 2:
                continue
            if correct_index < 0 or correct_index >= len(options):
                continue
            db_execute(
                """
                INSERT INTO mcqs (subject_id, question, options_json, correct_index, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    subject["id"],
                    question,
                    json.dumps(options),
                    correct_index,
                    datetime.utcnow().isoformat(),
                ),
            )
            created += 1
        flash(f"Uploaded {created} MCQs.")
        return redirect(url_for("admin_mcqs"))
    return render_template("upload_mcqs.html", subjects=subjects)


@app.route("/admin/mcqs/<int:mcq_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_mcq(mcq_id):
    mcq = db_fetchone(
        """
        SELECT mcqs.id, mcqs.question, mcqs.options_json, mcqs.correct_index, mcqs.subject_id
        FROM mcqs
        WHERE mcqs.id = ?
        """,
        (mcq_id,),
    )
    if not mcq:
        flash("MCQ not found.")
        return redirect(url_for("admin_mcqs"))
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    if request.method == "POST":
        subject_id = int(request.form.get("subject_id"))
        question = request.form.get("question", "").strip()
        options = [
            opt.strip()
            for opt in request.form.get("options", "").split("\n")
            if opt.strip()
        ]
        correct_index = int(request.form.get("correct_index", 0))
        if not question or len(options) < 2:
            flash("Provide a question and at least two options.")
            return render_template("edit_mcq.html", mcq=mcq, subjects=subjects)
        if correct_index < 0 or correct_index >= len(options):
            flash("Correct index is out of range.")
            return render_template("edit_mcq.html", mcq=mcq, subjects=subjects)
        db_execute(
            """
            UPDATE mcqs
            SET subject_id = ?, question = ?, options_json = ?, correct_index = ?
            WHERE id = ?
            """,
            (subject_id, question, json.dumps(options), correct_index, mcq_id),
        )
        flash("MCQ updated.")
        return redirect(url_for("admin_mcqs"))
    mcq["options"] = json.loads(mcq["options_json"])
    return render_template("edit_mcq.html", mcq=mcq, subjects=subjects)


@app.route("/admin/mcqs/<int:mcq_id>/delete", methods=["POST"])
@admin_required
def delete_mcq(mcq_id):
    db_execute("DELETE FROM mcqs WHERE id = ?", (mcq_id,))
    flash("MCQ deleted.")
    return redirect(url_for("admin_mcqs"))


@app.route("/exam/setup", methods=["GET", "POST"])
@login_required
def exam_setup():
    subjects = db_fetchall("SELECT id, name FROM subjects ORDER BY name")
    if request.method == "POST":
        subject_mode = request.form.get("subject_mode")
        mode = request.form.get("mode", "random")
        if mode not in {"random", "progress"}:
            mode = "random"
        subject_ids = []
        if subject_mode == "all":
            subject_ids = [str(subject["id"]) for subject in subjects]
        elif subject_mode == "single":
            subject_id = request.form.get("single_subject")
            if subject_id:
                subject_ids = [subject_id]
        else:
            subject_ids = request.form.getlist("subjects")
        if not subject_ids:
            flash("Select at least one subject.")
            return render_template("exam_setup.html", subjects=subjects)
        try:
            question_count = int(request.form.get("question_count", 0))
            time_limit = int(request.form.get("time_limit", 0))
        except ValueError:
            flash("Invalid numeric values.")
            return render_template("exam_setup.html", subjects=subjects)
        if question_count <= 0 or question_count > 100:
            flash("Question count must be between 1 and 100.")
            return render_template("exam_setup.html", subjects=subjects)
        if time_limit <= 0:
            flash("Time limit must be greater than 0.")
            return render_template("exam_setup.html", subjects=subjects)
        user = current_user()
        selected_mcqs = select_mcqs_for_exam(user["id"], subject_ids, question_count, mode)
        if not selected_mcqs:
            flash("No MCQs available for the selected criteria.")
            return render_template("exam_setup.html", subjects=subjects)
        result = db_execute(
            """
            INSERT INTO exams (user_id, mode, subject_ids_json, question_count, time_limit_minutes, start_time)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                mode,
                json.dumps(subject_ids),
                question_count,
                time_limit,
                datetime.utcnow().isoformat(),
            ),
        )
        exam_id = result.last_insert_rowid
        for mcq_id in selected_mcqs:
            db_execute(
                "INSERT INTO exam_questions (exam_id, mcq_id) VALUES (?, ?)",
                (exam_id, mcq_id),
            )
        return redirect(url_for("take_exam", exam_id=exam_id))
    return render_template("exam_setup.html", subjects=subjects)


def select_mcqs_for_exam(user_id, subject_ids, count, mode):
    placeholders = ",".join(["?"] * len(subject_ids))
    if mode == "progress":
        unattempted = db_fetchall(
            f"""
            SELECT mcqs.id
            FROM mcqs
            WHERE mcqs.subject_id IN ({placeholders})
              AND mcqs.id NOT IN (SELECT mcq_id FROM attempts WHERE user_id = ?)
            """,
            tuple(subject_ids) + (user_id,),
        )
        incorrect = db_fetchall(
            f"""
            SELECT mcqs.id, COUNT(*) AS wrong_count
            FROM attempts
            JOIN mcqs ON mcqs.id = attempts.mcq_id
            WHERE attempts.user_id = ?
              AND attempts.is_correct = 0
              AND mcqs.subject_id IN ({placeholders})
            GROUP BY mcqs.id
            ORDER BY wrong_count DESC
            """,
            (user_id, *subject_ids),
        )
        combined = [row["id"] for row in unattempted] + [row["id"] for row in incorrect]
        unique = []
        seen = set()
        for mcq_id in combined:
            if mcq_id not in seen:
                unique.append(mcq_id)
                seen.add(mcq_id)
        if len(unique) < count:
            remaining = db_fetchall(
                f"""
                SELECT id FROM mcqs
                WHERE subject_id IN ({placeholders})
                ORDER BY RANDOM()
                """,
                tuple(subject_ids),
            )
            for row in remaining:
                if row["id"] not in seen:
                    unique.append(row["id"])
                    seen.add(row["id"])
                if len(unique) >= count:
                    break
        return unique[:count]
    random_rows = db_fetchall(
        f"""
        SELECT id FROM mcqs
        WHERE subject_id IN ({placeholders})
        ORDER BY RANDOM()
        LIMIT ?
        """,
        tuple(subject_ids) + (count,),
    )
    return [row["id"] for row in random_rows]


@app.route("/exam/<int:exam_id>", methods=["GET", "POST"])
@login_required
def take_exam(exam_id):
    user = current_user()
    exam = db_fetchone(
        """
        SELECT id, user_id, mode, question_count, time_limit_minutes, start_time, submitted_at
        FROM exams
        WHERE id = ? AND user_id = ?
        """,
        (exam_id, user["id"]),
    )
    if not exam:
        flash("Exam not found.")
        return redirect(url_for("dashboard"))
    if exam["submitted_at"]:
        return redirect(url_for("exam_result", exam_id=exam_id))
    start_time = datetime.fromisoformat(exam["start_time"])
    deadline = start_time + timedelta(minutes=exam["time_limit_minutes"])
    if datetime.utcnow() >= deadline:
        submit_exam(exam_id, user["id"], request.form)
        flash("Time is up. Exam submitted.")
        return redirect(url_for("exam_result", exam_id=exam_id))
    if request.method == "POST":
        submit_exam(exam_id, user["id"], request.form)
        return redirect(url_for("exam_result", exam_id=exam_id))
    questions = db_fetchall(
        """
        SELECT exam_questions.id AS exam_question_id, mcqs.id AS mcq_id, mcqs.question,
               mcqs.options_json
        FROM exam_questions
        JOIN mcqs ON mcqs.id = exam_questions.mcq_id
        WHERE exam_questions.exam_id = ?
        """,
        (exam_id,),
    )
    for question in questions:
        question["options"] = json.loads(question["options_json"])
    remaining_seconds = int((deadline - datetime.utcnow()).total_seconds())
    return render_template(
        "exam.html",
        exam=exam,
        questions=questions,
        remaining_seconds=remaining_seconds,
    )


def submit_exam(exam_id, user_id, form_data):
    questions = db_fetchall(
        """
        SELECT exam_questions.id AS exam_question_id, mcqs.id AS mcq_id, mcqs.correct_index
        FROM exam_questions
        JOIN mcqs ON mcqs.id = exam_questions.mcq_id
        WHERE exam_questions.exam_id = ?
        """,
        (exam_id,),
    )
    for question in questions:
        selected = form_data.get(f"question_{question['exam_question_id']}")
        if selected is None:
            continue
        selected_index = int(selected)
        is_correct = 1 if selected_index == question["correct_index"] else 0
        db_execute(
            """
            UPDATE exam_questions
            SET selected_index = ?, is_correct = ?
            WHERE id = ?
            """,
            (selected_index, is_correct, question["exam_question_id"]),
        )
        db_execute(
            """
            INSERT INTO attempts (user_id, mcq_id, selected_index, is_correct, attempted_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                question["mcq_id"],
                selected_index,
                is_correct,
                datetime.utcnow().isoformat(),
            ),
        )
    db_execute(
        "UPDATE exams SET submitted_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), exam_id),
    )


@app.route("/exam/<int:exam_id>/result")
@login_required
def exam_result(exam_id):
    user = current_user()
    exam = db_fetchone(
        """
        SELECT id, user_id, mode, question_count, submitted_at
        FROM exams
        WHERE id = ? AND user_id = ?
        """,
        (exam_id, user["id"]),
    )
    if not exam:
        flash("Exam not found.")
        return redirect(url_for("dashboard"))
    summary = db_fetchone(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) AS correct,
               SUM(CASE WHEN is_correct = 0 THEN 1 ELSE 0 END) AS incorrect
        FROM exam_questions
        WHERE exam_id = ?
        """,
        (exam_id,),
    )
    score = 0
    if summary and summary["total"]:
        score = round((summary["correct"] / summary["total"]) * 100, 2)
    return render_template("result.html", exam=exam, summary=summary, score=score)


init_db()
ensure_admin_seed()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
