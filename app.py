import os
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# Boston Pie Ops System
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "svr_system.db"
UPLOAD_FOLDER = BASE_DIR / "svr_uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "boston-pie-svr-secret")
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# ============================================================
# DB helpers
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    cur = db.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'supervisor', 'maintenance')),
            display_name TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS store_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_number TEXT UNIQUE NOT NULL,
            manager_name TEXT,
            manager_email TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS svr_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_date TEXT NOT NULL,
            store_number TEXT NOT NULL,
            supervisor_username TEXT NOT NULL,
            supervisor_name TEXT NOT NULL,
            manager_on_duty TEXT,
            checklist_book_use TEXT,
            restroom_notes TEXT,
            pizza_quality_notes TEXT,
            last_week_svr_review TEXT,
            outside_store_condition_notes TEXT,
            carryout_notes TEXT,
            store_condition_notes TEXT,
            refrigeration_units_notes TEXT,
            bake_wares_notes TEXT,
            oven_heatrack_notes TEXT,
            callout_calendar_notes TEXT,
            deposit_log_notes TEXT,
            pest_control_status TEXT,
            cleaning_list TEXT,
            goals_for_week TEXT,
            maintenance_needs TEXT,
            complete_solution TEXT,
            parking_lot_clean TEXT,
            carryout_clean TEXT,
            customer_area_condition TEXT,
            uniforms_proper TEXT,
            hot_bags_clean TEXT,
            hot_bags_condition TEXT,
            production_area_clean TEXT,
            ceiling_tiles_clean TEXT,
            walls_floors_not_broken TEXT,
            walkin_makeline_clean TEXT,
            bakeware_clean TEXT,
            oven_area_clean TEXT,
            thermometers_available TEXT,
            scales_available TEXT,
            caller_id_working TEXT,
            callout_calendar_present TEXT,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS svr_photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES svr_reports(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS action_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            store_number TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'closed')),
            created_at TEXT NOT NULL,
            closed_at TEXT,
            FOREIGN KEY(report_id) REFERENCES svr_reports(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_label TEXT NOT NULL,
            question_text TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_label TEXT NOT NULL,
            visit_date TEXT NOT NULL,
            store_number TEXT NOT NULL,
            supervisor_username TEXT NOT NULL,
            supervisor_name TEXT NOT NULL,
            notes TEXT,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(week_label, store_number)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            form_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            answer TEXT NOT NULL CHECK(answer IN ('Yes', 'No', 'N/A')),
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(form_id) REFERENCES verification_forms(id) ON DELETE CASCADE,
            FOREIGN KEY(question_id) REFERENCES verification_questions(id) ON DELETE CASCADE
        )
        """
    )

    starter_users = [
        ("admin", "admin123", "admin", "Administrator"),
        ("kelly", "super123", "supervisor", "Kelly"),
        ("maintenance_user", "fixit123", "maintenance", "Maintenance"),
    ]
    for username, password, role, display_name in starter_users:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cur.fetchone():
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role, display_name)
                VALUES (?, ?, ?, ?)
                """,
                (username, generate_password_hash(password), role, display_name),
            )

    count = cur.execute("SELECT COUNT(*) FROM verification_questions").fetchone()[0]
    if count == 0:
        now = datetime.now().isoformat(timespec="seconds")
        week_label = datetime.now().date().isoformat()
        starter_questions = [
            "Bad order / cancel log system in place",
            "Anyone identified for suspicious activity / callbacks made",
            "Is CSR development program in use?",
        ]
        for q in starter_questions:
            cur.execute(
                """
                INSERT INTO verification_questions (week_label, question_text, is_active, created_at)
                VALUES (?, ?, 1, ?)
                """,
                (week_label, q, now),
            )

    db.commit()
    db.close()


# ============================================================
# Auth / utility
# ============================================================
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if session.get("role") not in roles:
                flash("You do not have access to that page.", "error")
                return redirect(url_for("home"))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


def allowed_image(filename):
    return Path(filename).suffix.lower() in ALLOWED_IMAGE_EXTENSIONS


def safe_text(field_name):
    return request.form.get(field_name, "").strip()


def clean_yes_no(field_name):
    value = request.form.get(field_name, "")
    return value if value in {"Yes", "No", "N/A"} else "N/A"


def yes_no_badge(value):
    if value == "Yes":
        return '<span class="badge badge-yes">Yes</span>'
    if value == "No":
        return '<span class="badge badge-no">No</span>'
    return '<span class="badge badge-na">N/A</span>'


app.jinja_env.globals.update(yes_no_badge=yes_no_badge)


def parse_action_items(text_blob):
    if not text_blob:
        return []
    items = []
    for line in text_blob.splitlines():
        line = line.strip("-• \t")
        if line:
            items.append(line)
    return items


def is_maintenance_text(text):
    if not text:
        return False
    text = text.lower()
    keywords = [
        "maintenance",
        "repair",
        "fix",
        "replace",
        "swap",
        "pan",
        "rack",
        "oven",
        "heatrack",
        "cooler",
        "walk-in",
        "walk in",
        "sink",
        "door",
        "condenser",
        "tile",
        "vent",
        "makeline",
        "dish",
        "faucet",
        "plumbing",
        "electrical",
        "light",
        "shelf",
        "shelves",
        "freezer",
        "table",
        "broken",
    ]
    return any(word in text for word in keywords)


def count_failures(report_row):
    yes_no_fields = [
        "parking_lot_clean",
        "carryout_clean",
        "customer_area_condition",
        "uniforms_proper",
        "hot_bags_clean",
        "hot_bags_condition",
        "production_area_clean",
        "ceiling_tiles_clean",
        "walls_floors_not_broken",
        "walkin_makeline_clean",
        "bakeware_clean",
        "oven_area_clean",
        "thermometers_available",
        "scales_available",
        "caller_id_working",
        "callout_calendar_present",
    ]
    return sum(1 for field in yes_no_fields if report_row[field] == "No")


def create_user(username, password, role, display_name):
    db = get_db()
    db.execute(
        """
        INSERT INTO users (username, password_hash, role, display_name)
        VALUES (?, ?, ?, ?)
        """,
        (
            username.strip().lower(),
            generate_password_hash(password),
            role,
            display_name.strip(),
        ),
    )
    db.commit()


def update_user_password(user_id, new_password):
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id),
    )
    db.commit()


def update_user_display_name(user_id, display_name):
    db = get_db()
    db.execute(
        "UPDATE users SET display_name = ? WHERE id = ?",
        (display_name.strip(), user_id),
    )
    db.commit()


def get_store_contact(store_number):
    db = get_db()
    return db.execute(
        "SELECT * FROM store_contacts WHERE store_number = ?",
        (store_number,),
    ).fetchone()


def build_manager_email_link(report, actions, contact_row):
    if not contact_row or not contact_row["manager_email"]:
        return None

    to_email = contact_row["manager_email"].strip()
    subject = f"SVR Summary - Store {report['store_number']} - {report['visit_date']}"

    maintenance_lines = set(parse_action_items(report["maintenance_needs"]))
    manager_actions = [item for item in actions if item["title"] not in maintenance_lines]

    action_lines = [f"- {item['title']}" for item in manager_actions]
    if not action_lines:
        action_lines = ["- No non-maintenance action items"]

    body_lines = [
        f"Store: {report['store_number']}",
        f"Date: {report['visit_date']}",
        f"Supervisor: {report['supervisor_name']}",
        f"Manager on Duty: {report['manager_on_duty'] or '—'}",
        "",
        "Store Condition Notes:",
        report["store_condition_notes"] or "—",
        "",
        "Goals for the Week:",
        report["goals_for_week"] or "—",
        "",
        "Action Items:",
        *action_lines,
        "",
        "Maintenance Needs:",
        report["maintenance_needs"] or "—",
    ]

    body = "\r\n".join(body_lines)
    return f"mailto:{quote(to_email)}?subject={quote(subject)}&body={quote(body)}"


# ============================================================
# UI rendering
# ============================================================
BASE_HEAD = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f6f8;
            color: #1f2937;
        }
        .topbar {
            background: #111827;
            color: white;
            padding: 14px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            position: sticky;
            top: 0;
            z-index: 20;
        }
        .topbar h1 { margin: 0; font-size: 20px; }
        .topbar .nav {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .topbar .nav a {
            color: white;
            text-decoration: none;
            font-weight: bold;
            padding: 8px 10px;
            border-radius: 10px;
            background: rgba(255,255,255,0.08);
        }
        .container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 0 12px 88px;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.08);
            padding: 16px;
            margin-bottom: 16px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
        }
        .stat {
            background: linear-gradient(180deg, #ffffff 0%, #f7fafc 100%);
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            padding: 14px;
        }
        .stat .label {
            font-size: 13px;
            color: #6b7280;
            margin-bottom: 8px;
        }
        .stat .value {
            font-size: 24px;
            font-weight: 700;
            line-height: 1.15;
        }
        h2, h3 { margin-top: 0; }
        label {
            display: block;
            font-weight: 700;
            margin-bottom: 6px;
        }
        input[type=text], input[type=date], input[type=password], textarea, select {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            font-size: 16px;
            background: white;
        }
        textarea {
            min-height: 100px;
            resize: vertical;
        }
        .btn {
            display: inline-block;
            background: #111827;
            color: white;
            border: none;
            border-radius: 10px;
            padding: 12px 16px;
            cursor: pointer;
            font-weight: 700;
            text-decoration: none;
            font-size: 15px;
            margin-right: 8px;
            margin-bottom: 8px;
        }
        .btn.secondary { background: #4b5563; }
        .btn.green { background: #166534; }
        .btn.red { background: #b91c1c; }
        .table-wrap {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 640px;
        }
        th, td {
            padding: 10px 12px;
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
            vertical-align: top;
            font-size: 14px;
        }
        th { background: #f9fafb; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-yes { background: #dcfce7; color: #166534; }
        .badge-no { background: #fee2e2; color: #991b1b; }
        .badge-na { background: #e5e7eb; color: #374151; }
        .badge-open { background: #fef3c7; color: #92400e; }
        .badge-closed { background: #dcfce7; color: #166534; }
        .flash {
            padding: 12px 14px;
            border-radius: 10px;
            margin-bottom: 14px;
            font-weight: 700;
        }
        .flash.success { background: #dcfce7; color: #166534; }
        .flash.error { background: #fee2e2; color: #991b1b; }
        .muted { color: #6b7280; }
        .two-col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }
        .three-col {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }
        .check-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px;
        }
        .check-item {
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 12px;
            background: #fafafa;
        }
        .login-wrap {
            max-width: 420px;
            margin: 40px auto;
            padding: 0 12px;
        }
        .photo-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
        }
        .photo-grid img {
            width: 100%;
            height: 160px;
            object-fit: cover;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
        }
        .small { font-size: 12px; }
        .danger-zone {
            border: 1px solid #fecaca;
            background: #fff1f2;
        }
        @media (max-width: 900px) {
            .two-col, .three-col { grid-template-columns: 1fr; }
            .topbar { align-items: stretch; }
            .topbar .nav { width: 100%; }
            .topbar .nav a {
                flex: 1 1 auto;
                text-align: center;
            }
            .btn {
                width: 100%;
                text-align: center;
                margin-right: 0;
            }
            table { min-width: 560px; }
        }
        @media (max-width: 520px) {
            .container { padding-bottom: 96px; }
            .stat .value { font-size: 22px; }
            .card { padding: 14px; }
            table { min-width: 520px; }
        }
    </style>
</head>
<body>
"""

TOPBAR = """
<div class="topbar">
    <h1>Boston Pie Ops System</h1>
    {% if session.get('user_id') %}
    <div class="nav">
        <a href="{{ url_for('home') }}">Home</a>
        {% if session.get('role') in ['admin', 'supervisor'] %}
            <a href="{{ url_for('new_report') }}">New SVR</a>
            <a href="{{ url_for('new_verification') }}">Verification</a>
        {% endif %}
        {% if session.get('role') == 'admin' %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('action_dashboard') }}">Action Items</a>
            <a href="{{ url_for('maintenance_dashboard') }}">Maintenance</a>
            <a href="{{ url_for('manage_users') }}">Users</a>
            <a href="{{ url_for('manage_store_contacts') }}">Store Contacts</a>
            <a href="{{ url_for('verification_dashboard') }}">Verif Dashboard</a>
            <a href="{{ url_for('manage_verification_questions') }}">Verif Questions</a>
            <a href="{{ url_for('archived_reports') }}">Archived</a>
        {% endif %}
        {% if session.get('role') == 'maintenance' %}
            <a href="{{ url_for('maintenance_dashboard') }}">Maintenance</a>
        {% endif %}
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    {% endif %}
</div>
"""


def render_page(content, **context):
    template = BASE_HEAD + TOPBAR + """
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        """ + content + """
    </div>
</body>
</html>
"""
    return render_template_string(template, **context)
@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    role = session.get("role")

    if role == "admin":
        latest_reports = db.execute(
            """
            SELECT id, visit_date, store_number, supervisor_name, manager_on_duty
            FROM svr_reports
            WHERE is_archived = 0
            ORDER BY created_at DESC
            LIMIT 10
            """
        ).fetchall()

        maintenance_open = 0
        open_items = db.execute(
            "SELECT title FROM action_items WHERE status = 'open'"
        ).fetchall()
        for row in open_items:
            if is_maintenance_text(row["title"]):
                maintenance_open += 1

        content = """
        <div class="grid">
            <div class="stat"><div class="label">Welcome</div><div class="value">{{ session.get('display_name') }}</div></div>
            <div class="stat"><div class="label">Role</div><div class="value">Admin</div></div>
            <div class="stat"><div class="label">Open Maintenance</div><div class="value">{{ maintenance_open }}</div></div>
        </div>

        <div class="card" style="margin-top:18px;">
            <h2>Quick Actions</h2>
            <a class="btn" href="{{ url_for('new_report') }}">Submit SVR</a>
            <a class="btn secondary" href="{{ url_for('new_verification') }}">Submit Verification</a>
            <a class="btn secondary" href="{{ url_for('dashboard') }}">Open Dashboard</a>
            <a class="btn secondary" href="{{ url_for('maintenance_dashboard') }}">Maintenance</a>
            <a class="btn secondary" href="{{ url_for('archived_reports') }}">Archived</a>
        </div>

        <div class="card">
            <h2>Latest Active Reports</h2>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Date</th><th>Store</th><th>Supervisor</th><th>MOD</th><th></th></tr></thead>
                    <tbody>
                        {% for row in latest_reports %}
                        <tr>
                            <td>{{ row['visit_date'] }}</td>
                            <td>{{ row['store_number'] }}</td>
                            <td>{{ row['supervisor_name'] }}</td>
                            <td>{{ row['manager_on_duty'] or '—' }}</td>
                            <td><a class="btn secondary" href="{{ url_for('view_report', report_id=row['id']) }}">Open</a></td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5">No active reports yet.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_page(
            content,
            title="Home",
            latest_reports=latest_reports,
            maintenance_open=maintenance_open,
        )

    if role == "maintenance":
        items = db.execute(
            """
            SELECT ai.id, ai.report_id, ai.store_number, ai.title, ai.status, ai.created_at, ai.closed_at,
                   sr.maintenance_needs
            FROM action_items ai
            LEFT JOIN svr_reports sr ON ai.report_id = sr.id
            ORDER BY ai.status ASC, ai.created_at DESC
            """
        ).fetchall()

        maintenance_items = []
        for row in items:
            maintenance_lines = set(parse_action_items(row["maintenance_needs"] or ""))
            if row["title"] in maintenance_lines:
                maintenance_items.append(row)

        content = """
        <div class="grid">
            <div class="stat"><div class="label">Welcome</div><div class="value">{{ session.get('display_name') }}</div></div>
            <div class="stat"><div class="label">Role</div><div class="value">Maintenance</div></div>
        </div>

        <div class="card" style="margin-top:18px;">
            <h2>Your Work Queue</h2>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Store</th><th>Item</th><th>Status</th><th>Created</th><th>Closed</th><th></th></tr></thead>
                    <tbody>
                        {% for row in maintenance_items %}
                        <tr>
                            <td>{{ row['store_number'] }}</td>
                            <td>{{ row['title'] }}</td>
                            <td>{% if row['status'] == 'open' %}<span class="badge badge-open">Open</span>{% else %}<span class="badge badge-closed">Closed</span>{% endif %}</td>
                            <td>{{ row['created_at'][:10] }}</td>
                            <td>{{ row['closed_at'][:10] if row['closed_at'] else '—' }}</td>
                            <td>
                                {% if row['status'] == 'open' %}
                                    <a class="btn green" href="{{ url_for('close_action_item', item_id=row['id']) }}">Close</a>
                                {% else %}
                                    <a class="btn secondary" href="{{ url_for('reopen_action_item', item_id=row['id']) }}">Reopen</a>
                                {% endif %}
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="6">No maintenance items yet.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_page(
            content,
            title="Home",
            maintenance_items=maintenance_items,
        )

    latest_reports = db.execute(
        """
        SELECT id, visit_date, store_number, supervisor_name, manager_on_duty
        FROM svr_reports
        WHERE supervisor_username = ? AND is_archived = 0
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (session.get("username"),),
    ).fetchall()

    content = """
    <div class="grid">
        <div class="stat"><div class="label">Welcome</div><div class="value">{{ session.get('display_name') }}</div></div>
        <div class="stat"><div class="label">Role</div><div class="value">Supervisor</div></div>
    </div>

    <div class="card" style="margin-top:18px;">
        <h2>Quick Actions</h2>
        <a class="btn" href="{{ url_for('new_report') }}">Submit SVR</a>
        <a class="btn secondary" href="{{ url_for('new_verification') }}">Submit Verification</a>
    </div>

    <div class="card">
        <h2>Your Active Reports</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Date</th><th>Store</th><th>MOD</th><th></th></tr></thead>
                <tbody>
                    {% for row in latest_reports %}
                    <tr>
                        <td>{{ row['visit_date'] }}</td>
                        <td>{{ row['store_number'] }}</td>
                        <td>{{ row['manager_on_duty'] or '—' }}</td>
                        <td><a class="btn secondary" href="{{ url_for('view_report', report_id=row['id']) }}">Open</a></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4">No active reports yet.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    """
    return render_page(content, title="Home", latest_reports=latest_reports)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["display_name"] = user["display_name"]
            return redirect(url_for("home"))

        flash("Invalid username or password.", "error")

    template = BASE_HEAD + """
    <div class="login-wrap">
        <div class="card">
            <h2>Boston Pie Ops System</h2>
            <p class="muted">Sign in to submit reports or view dashboards.</p>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash {{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="post">
                <div style="margin-bottom:12px;"><label>Username</label><input type="text" name="username" required></div>
                <div style="margin-bottom:12px;"><label>Password</label><input type="password" name="password" required></div>
                <button class="btn" type="submit">Log In</button>
            </form>
            <hr style="margin:18px 0; border:none; border-top:1px solid #e5e7eb;">
            <p class="small muted"><strong>Starter logins:</strong><br>admin / admin123<br>kelly / super123<br>maintenance_user / fixit123</p>
        </div>
    </div>
</body>
</html>
"""
    return render_template_string(template, title="Login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
@role_required("admin")
def dashboard():
    db = get_db()

    total_reports = db.execute(
        "SELECT COUNT(*) AS count FROM svr_reports WHERE is_archived = 0"
    ).fetchone()["count"]
    total_open_actions = db.execute(
        "SELECT COUNT(*) AS count FROM action_items WHERE status = 'open'"
    ).fetchone()["count"]
    stores_visited = db.execute(
        "SELECT COUNT(DISTINCT store_number) AS count FROM svr_reports WHERE is_archived = 0"
    ).fetchone()["count"]

    supervisor_visits = db.execute(
        """
        SELECT supervisor_name, COUNT(*) AS count
        FROM svr_reports
        WHERE is_archived = 0
        GROUP BY supervisor_name
        ORDER BY count DESC, supervisor_name ASC
        """
    ).fetchall()

    recent_reports = db.execute(
        """
        SELECT * FROM svr_reports
        WHERE is_archived = 0
        ORDER BY created_at DESC
        LIMIT 20
        """
    ).fetchall()

    issue_counts = db.execute(
        """
        SELECT title, COUNT(*) AS count
        FROM action_items
        GROUP BY title
        ORDER BY count DESC, title ASC
        LIMIT 15
        """
    ).fetchall()

    store_summary = db.execute(
        """
        SELECT store_number, COUNT(*) AS report_count, MAX(visit_date) AS last_visit
        FROM svr_reports
        WHERE is_archived = 0
        GROUP BY store_number
        ORDER BY last_visit DESC
        """
    ).fetchall()

    maintenance_open = 0
    for row in db.execute(
        """
        SELECT ai.title, sr.maintenance_needs
        FROM action_items ai
        LEFT JOIN svr_reports sr ON ai.report_id = sr.id
        WHERE ai.status = 'open'
        """
    ).fetchall():
        maintenance_lines = set(parse_action_items(row["maintenance_needs"] or ""))
        if row["title"] in maintenance_lines:
            maintenance_open += 1

    report_cards = []
    for row in recent_reports:
        report_cards.append(
            {
                "id": row["id"],
                "visit_date": row["visit_date"],
                "store_number": row["store_number"],
                "supervisor_name": row["supervisor_name"],
                "manager_on_duty": row["manager_on_duty"],
                "fails": count_failures(row),
            }
        )

    content = """
    <div class="grid">
        <div class="stat"><div class="label">Active SVRs</div><div class="value">{{ total_reports }}</div></div>
        <div class="stat"><div class="label">Stores Visited</div><div class="value">{{ stores_visited }}</div></div>
        <div class="stat"><div class="label">Open Action Items</div><div class="value">{{ total_open_actions }}</div></div>
        <div class="stat"><div class="label">Open Maintenance</div><div class="value">{{ maintenance_open }}</div></div>
    </div>

    <div class="card" style="margin-top:18px;">
        <h2>Recent Visit Activity</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Date</th><th>Store</th><th>Supervisor</th><th>MOD</th><th>Fails</th><th></th></tr></thead>
            <tbody>
                {% for row in report_cards %}
                <tr>
                    <td>{{ row.visit_date }}</td>
                    <td>{{ row.store_number }}</td>
                    <td>{{ row.supervisor_name }}</td>
                    <td>{{ row.manager_on_duty or '—' }}</td>
                    <td>{{ row.fails }}</td>
                    <td><a class="btn secondary" href="{{ url_for('view_report', report_id=row.id) }}">Open</a></td>
                </tr>
                {% else %}
                <tr><td colspan="6">No active reports yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>

    <div class="two-col">
        <div class="card"><h2>Supervisor Visits</h2><div class="table-wrap"><table>
            <thead><tr><th>Supervisor</th><th>Visits</th></tr></thead>
            <tbody>
                {% for row in supervisor_visits %}
                <tr><td>{{ row['supervisor_name'] }}</td><td>{{ row['count'] }}</td></tr>
                {% else %}
                <tr><td colspan="2">No data yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div></div>

        <div class="card"><h2>Top Recurring Action Items</h2><div class="table-wrap"><table>
            <thead><tr><th>Issue</th><th>Count</th></tr></thead>
            <tbody>
                {% for row in issue_counts %}
                <tr><td>{{ row['title'] }}</td><td>{{ row['count'] }}</td></tr>
                {% else %}
                <tr><td colspan="2">No data yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div></div>
    </div>

    <div class="card">
        <h2>Store Health</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Store</th><th>Last Visit</th><th>Fails</th><th>Health</th><th></th></tr></thead>
            <tbody>
                {% for row in store_summary %}
                {% set last = namespace(fails=0) %}
                {% for r in report_cards %}
                    {% if r.store_number == row['store_number'] %}
                        {% set last.fails = r.fails %}
                    {% endif %}
                {% endfor %}
                <tr>
                    <td>{{ row['store_number'] }}</td>
                    <td>{{ row['last_visit'] }}</td>
                    <td>{{ last.fails }}</td>
                    <td>{% if last.fails >= 5 %}🔴 Critical{% elif last.fails >= 2 %}🟡 Watch{% else %}🟢 Good{% endif %}</td>
                    <td><a class="btn secondary" href="{{ url_for('store_history', store_number=row['store_number']) }}">History</a></td>
                </tr>
                {% else %}
                <tr><td colspan="5">No data yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(
        content,
        title="Dashboard",
        total_reports=total_reports,
        total_open_actions=total_open_actions,
        stores_visited=stores_visited,
        supervisor_visits=supervisor_visits,
        issue_counts=issue_counts,
        store_summary=store_summary,
        report_cards=report_cards,
        maintenance_open=maintenance_open,
    )


@app.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_users():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "create_user":
            display_name = request.form.get("display_name", "").strip()
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "supervisor").strip()

            if not display_name or not username or not password:
                flash("Display name, username, and password are required.", "error")
                return redirect(url_for("manage_users"))

            if role not in {"admin", "supervisor", "maintenance"}:
                flash("Invalid role selected.", "error")
                return redirect(url_for("manage_users"))

            existing = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing:
                flash("That username already exists.", "error")
                return redirect(url_for("manage_users"))

            create_user(username, password, role, display_name)
            flash("User created successfully.", "success")
            return redirect(url_for("manage_users"))

        if action == "change_password":
            user_id = request.form.get("user_id", "").strip()
            new_password = request.form.get("new_password", "")
            if not user_id or not new_password:
                flash("User and new password are required.", "error")
                return redirect(url_for("manage_users"))
            update_user_password(int(user_id), new_password)
            flash("Password updated.", "success")
            return redirect(url_for("manage_users"))

        if action == "update_name":
            user_id = request.form.get("user_id", "").strip()
            display_name = request.form.get("new_display_name", "").strip()
            if not user_id or not display_name:
                flash("User and display name are required.", "error")
                return redirect(url_for("manage_users"))
            update_user_display_name(int(user_id), display_name)
            flash("Display name updated.", "success")
            return redirect(url_for("manage_users"))

    users = db.execute(
        "SELECT id, username, role, display_name FROM users ORDER BY role ASC, display_name ASC"
    ).fetchall()

    content = """
    <div class="two-col">
        <div class="card">
            <h2>Add User</h2>
            <form method="post">
                <input type="hidden" name="action" value="create_user">
                <div style="margin-bottom:12px;"><label>Display name</label><input type="text" name="display_name" required></div>
                <div style="margin-bottom:12px;"><label>Username</label><input type="text" name="username" required></div>
                <div style="margin-bottom:12px;"><label>Password</label><input type="text" name="password" required></div>
                <div style="margin-bottom:12px;"><label>Role</label>
                    <select name="role">
                        <option value="supervisor">Supervisor</option>
                        <option value="admin">Admin</option>
                        <option value="maintenance">Maintenance</option>
                    </select>
                </div>
                <button class="btn" type="submit">Create User</button>
            </form>
        </div>

        <div class="card">
            <h2>Change Password</h2>
            <form method="post">
                <input type="hidden" name="action" value="change_password">
                <div style="margin-bottom:12px;"><label>User</label><select name="user_id">{% for user in users %}<option value="{{ user['id'] }}">{{ user['display_name'] }} ({{ user['username'] }})</option>{% endfor %}</select></div>
                <div style="margin-bottom:12px;"><label>New password</label><input type="text" name="new_password" required></div>
                <button class="btn secondary" type="submit">Update Password</button>
            </form>

            <hr style="margin:18px 0; border:none; border-top:1px solid #e5e7eb;">

            <h2>Change Display Name</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_name">
                <div style="margin-bottom:12px;"><label>User</label><select name="user_id">{% for user in users %}<option value="{{ user['id'] }}">{{ user['display_name'] }} ({{ user['username'] }})</option>{% endfor %}</select></div>
                <div style="margin-bottom:12px;"><label>New display name</label><input type="text" name="new_display_name" required></div>
                <button class="btn secondary" type="submit">Update Name</button>
            </form>
        </div>
    </div>

    <div class="card">
        <h2>Current Users</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Name</th><th>Username</th><th>Role</th></tr></thead>
            <tbody>
                {% for user in users %}
                <tr><td>{{ user['display_name'] }}</td><td>{{ user['username'] }}</td><td>{{ user['role'].title() }}</td></tr>
                {% else %}
                <tr><td colspan="3">No users found.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(content, title="Manage Users", users=users)
@app.route("/store-contacts", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_store_contacts():
    db = get_db()

    if request.method == "POST":
        store_number = request.form.get("store_number", "").strip()
        manager_name = request.form.get("manager_name", "").strip()
        manager_email = request.form.get("manager_email", "").strip()
        now = datetime.now().isoformat(timespec="seconds")

        if not store_number:
            flash("Store number is required.", "error")
            return redirect(url_for("manage_store_contacts"))

        existing = db.execute(
            "SELECT id FROM store_contacts WHERE store_number = ?",
            (store_number,),
        ).fetchone()

        if existing:
            db.execute(
                """
                UPDATE store_contacts
                SET manager_name = ?, manager_email = ?, updated_at = ?
                WHERE store_number = ?
                """,
                (manager_name, manager_email, now, store_number),
            )
            flash("Store contact updated.", "success")
        else:
            db.execute(
                """
                INSERT INTO store_contacts (store_number, manager_name, manager_email, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (store_number, manager_name, manager_email, now),
            )
            flash("Store contact added.", "success")

        db.commit()
        return redirect(url_for("manage_store_contacts"))

    contacts = db.execute(
        "SELECT * FROM store_contacts ORDER BY store_number ASC"
    ).fetchall()

    content = """
    <div class="two-col">
        <div class="card">
            <h2>Add / Update Store Manager Contact</h2>
            <form method="post">
                <div style="margin-bottom:12px;"><label>Store #</label><input type="text" name="store_number" required></div>
                <div style="margin-bottom:12px;"><label>Manager name</label><input type="text" name="manager_name"></div>
                <div style="margin-bottom:12px;"><label>Manager email</label><input type="text" name="manager_email" placeholder="manager@email.com"></div>
                <button class="btn" type="submit">Save Contact</button>
            </form>
        </div>
        <div class="card">
            <h2>How it works</h2>
            <p class="muted">Once a store has a manager email saved, supervisors will see an Email Manager button on the Manager Summary page.</p>
        </div>
    </div>

    <div class="card">
        <h2>Store Contacts</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Store</th><th>Manager</th><th>Email</th><th>Updated</th></tr></thead>
            <tbody>
                {% for row in contacts %}
                <tr>
                    <td>{{ row['store_number'] }}</td>
                    <td>{{ row['manager_name'] or '—' }}</td>
                    <td>{{ row['manager_email'] or '—' }}</td>
                    <td>{{ row['updated_at'][:10] }}</td>
                </tr>
                {% else %}
                <tr><td colspan="4">No store contacts yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(content, title="Store Contacts", contacts=contacts)


@app.route("/verification/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "supervisor")
def new_verification():
    db = get_db()
    today = datetime.now().date().isoformat()
    current_week = request.form.get("week_label", today) if request.method == "POST" else today

    active_questions = db.execute(
        "SELECT id, question_text, week_label FROM verification_questions WHERE is_active = 1 ORDER BY id ASC"
    ).fetchall()

    if request.method == "POST":
        week_label = request.form.get("week_label", "").strip() or today
        store_number = request.form.get("store_number", "").strip()
        visit_date = request.form.get("visit_date", "").strip() or today
        notes = request.form.get("notes", "").strip()
        now = datetime.now().isoformat(timespec="seconds")

        if not store_number:
            flash("Store number is required.", "error")
            return redirect(url_for("new_verification"))

        existing = db.execute(
            "SELECT id FROM verification_forms WHERE week_label = ? AND store_number = ?",
            (week_label, store_number),
        ).fetchone()
        if existing:
            flash("A verification for that store already exists for this week.", "error")
            return redirect(url_for("new_verification"))

        cur = db.execute(
            """
            INSERT INTO verification_forms (week_label, visit_date, store_number, supervisor_username, supervisor_name, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                week_label,
                visit_date,
                store_number,
                session.get("username"),
                session.get("display_name"),
                notes,
                now,
            ),
        )
        form_id = cur.lastrowid

        for question in active_questions:
            answer = request.form.get(f"verification_answer_{question['id']}", "N/A")
            if answer not in {"Yes", "No", "N/A"}:
                answer = "N/A"
            note = request.form.get(f"verification_note_{question['id']}", "").strip()

            db.execute(
                """
                INSERT INTO verification_answers (form_id, question_id, question_text, answer, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    form_id,
                    question["id"],
                    question["question_text"],
                    answer,
                    note,
                    now,
                ),
            )

        db.commit()
        flash("Verification submitted successfully.", "success")
        return redirect(url_for("view_verification", form_id=form_id))

    content = """
    <div class="card">
        <h2>New Verification</h2>
        <p class="muted">One verification per store per week. Admin can change the questions anytime.</p>
        <form method="post">
            <div class="three-col">
                <div><label>Week label</label><input type="text" name="week_label" value="{{ current_week }}"></div>
                <div><label>Visit date</label><input type="date" name="visit_date" value="{{ today }}"></div>
                <div><label>Store #</label><input type="text" name="store_number" required></div>
            </div>

            <div class="card" style="margin-top:16px; background:#fbfdff;">
                <h3>Verification Questions</h3>
                {% for question in active_questions %}
                <div class="check-item" style="margin-bottom:12px;">
                    <label>{{ question['question_text'] }}</label>
                    <select name="verification_answer_{{ question['id'] }}">
                        <option value="Yes">Yes</option>
                        <option value="No">No</option>
                        <option value="N/A">N/A</option>
                    </select>
                    <div style="margin-top:10px;">
                        <label>Note</label>
                        <input type="text" name="verification_note_{{ question['id'] }}" placeholder="Optional note">
                    </div>
                </div>
                {% else %}
                <p>No active verification questions yet.</p>
                {% endfor %}
            </div>

            <div><label>Overall notes</label><textarea name="notes"></textarea></div>
            <div style="margin-top:18px;"><button class="btn" type="submit">Submit Verification</button></div>
        </form>
    </div>
    """
    return render_page(
        content,
        title="New Verification",
        today=today,
        current_week=current_week,
        active_questions=active_questions,
    )


@app.route("/verification/<int:form_id>")
@login_required
@role_required("admin", "supervisor")
def view_verification(form_id):
    db = get_db()
    form = db.execute(
        "SELECT * FROM verification_forms WHERE id = ?",
        (form_id,),
    ).fetchone()

    if not form:
        flash("Verification not found.", "error")
        return redirect(url_for("home"))

    if session.get("role") == "supervisor" and form["supervisor_username"] != session.get("username"):
        flash("You do not have access to that verification.", "error")
        return redirect(url_for("home"))

    answers = db.execute(
        "SELECT * FROM verification_answers WHERE form_id = ? ORDER BY id ASC",
        (form_id,),
    ).fetchall()

    content = """
    <div class="card">
        <h2>Verification</h2>
        <div class="grid">
            <div class="stat"><div class="label">Week</div><div class="value">{{ form['week_label'] }}</div></div>
            <div class="stat"><div class="label">Visit Date</div><div class="value">{{ form['visit_date'] }}</div></div>
            <div class="stat"><div class="label">Store</div><div class="value">{{ form['store_number'] }}</div></div>
            <div class="stat"><div class="label">Supervisor</div><div class="value">{{ form['supervisor_name'] }}</div></div>
        </div>
    </div>

    <div class="card">
        <h3>Answers</h3>
        <div class="table-wrap"><table>
            <thead><tr><th>Question</th><th>Answer</th><th>Note</th></tr></thead>
            <tbody>
                {% for answer in answers %}
                <tr><td>{{ answer['question_text'] }}</td><td>{{ yes_no_badge(answer['answer'])|safe }}</td><td>{{ answer['note'] or '—' }}</td></tr>
                {% else %}
                <tr><td colspan="3">No answers found.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>

    <div class="card"><h3>Overall Notes</h3><p style="white-space:pre-wrap;">{{ form['notes'] or '—' }}</p></div>

    {% if session.get('role') == 'admin' %}
    <div class="card">
        {% if form['is_archived'] == 0 %}
            <a class="btn secondary" href="{{ url_for('archive_verification', form_id=form['id']) }}">Archive Verification</a>
        {% else %}
            <a class="btn secondary" href="{{ url_for('restore_verification', form_id=form['id']) }}">Restore Verification</a>
        {% endif %}
    </div>
    <div class="card danger-zone">
        <h3>Delete Verification</h3>
        <p class="muted">This permanently deletes the verification and its answers.</p>
        <a class="btn red" href="{{ url_for('delete_verification', form_id=form['id']) }}">Delete Verification</a>
    </div>
    {% endif %}
    """
    return render_page(content, title="Verification", form=form, answers=answers)


@app.route("/verification-dashboard")
@login_required
@role_required("admin")
def verification_dashboard():
    db = get_db()
    forms = db.execute(
        "SELECT * FROM verification_forms WHERE is_archived = 0 ORDER BY created_at DESC LIMIT 50"
    ).fetchall()

    summaries = []
    for form in forms:
        fail_count = db.execute(
            "SELECT COUNT(*) AS count FROM verification_answers WHERE form_id = ? AND answer = 'No'",
            (form["id"],),
        ).fetchone()["count"]

        summaries.append(
            {
                "id": form["id"],
                "week_label": form["week_label"],
                "visit_date": form["visit_date"],
                "store_number": form["store_number"],
                "supervisor_name": form["supervisor_name"],
                "fail_count": fail_count,
            }
        )

    content = """
    <div class="card">
        <h2>Verification Dashboard</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Week</th><th>Date</th><th>Store</th><th>Supervisor</th><th>No Answers</th><th>Health</th><th></th></tr></thead>
            <tbody>
                {% for row in summaries %}
                <tr>
                    <td>{{ row.week_label }}</td>
                    <td>{{ row.visit_date }}</td>
                    <td>{{ row.store_number }}</td>
                    <td>{{ row.supervisor_name }}</td>
                    <td>{{ row.fail_count }}</td>
                    <td>{% if row.fail_count >= 2 %}🔴 Risk{% elif row.fail_count == 1 %}🟡 Watch{% else %}🟢 Good{% endif %}</td>
                    <td><a class="btn secondary" href="{{ url_for('view_verification', form_id=row.id) }}">Open</a></td>
                </tr>
                {% else %}
                <tr><td colspan="7">No active verifications yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(content, title="Verification Dashboard", summaries=summaries)


@app.route("/verification-questions", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_verification_questions():
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        now = datetime.now().isoformat(timespec="seconds")

        if action == "add_question":
            week_label = request.form.get("week_label", "").strip() or datetime.now().date().isoformat()
            question_text = request.form.get("question_text", "").strip()

            if not question_text:
                flash("Question text is required.", "error")
                return redirect(url_for("manage_verification_questions"))

            db.execute(
                """
                INSERT INTO verification_questions (week_label, question_text, is_active, created_at)
                VALUES (?, ?, 1, ?)
                """,
                (week_label, question_text, now),
            )
            db.commit()
            flash("Verification question added.", "success")
            return redirect(url_for("manage_verification_questions"))

        if action == "toggle_question":
            question_id = int(request.form.get("question_id", "0") or 0)
            row = db.execute(
                "SELECT is_active FROM verification_questions WHERE id = ?",
                (question_id,),
            ).fetchone()

            if row:
                new_value = 0 if row["is_active"] == 1 else 1
                db.execute(
                    "UPDATE verification_questions SET is_active = ? WHERE id = ?",
                    (new_value, question_id),
                )
                db.commit()
                flash("Question updated.", "success")

            return redirect(url_for("manage_verification_questions"))

    questions = db.execute(
        "SELECT * FROM verification_questions ORDER BY is_active DESC, id DESC"
    ).fetchall()

    content = """
    <div class="two-col">
        <div class="card">
            <h2>Add Verification Question</h2>
            <form method="post">
                <input type="hidden" name="action" value="add_question">
                <div style="margin-bottom:12px;"><label>Week label</label><input type="text" name="week_label" value="{{ today }}"></div>
                <div style="margin-bottom:12px;"><label>Question text</label><textarea name="question_text" required></textarea></div>
                <button class="btn" type="submit">Add Question</button>
            </form>
        </div>
        <div class="card">
            <h2>How this works</h2>
            <p class="muted">Active questions show up on the supervisor verification form.</p>
        </div>
    </div>

    <div class="card">
        <h2>Current Verification Questions</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Week</th><th>Question</th><th>Status</th><th></th></tr></thead>
            <tbody>
                {% for question in questions %}
                <tr>
                    <td>{{ question['week_label'] }}</td>
                    <td>{{ question['question_text'] }}</td>
                    <td>{% if question['is_active'] == 1 %}<span class="badge badge-yes">Active</span>{% else %}<span class="badge badge-na">Inactive</span>{% endif %}</td>
                    <td>
                        <form method="post" style="margin:0;">
                            <input type="hidden" name="action" value="toggle_question">
                            <input type="hidden" name="question_id" value="{{ question['id'] }}">
                            {% if question['is_active'] == 1 %}
                                <button class="btn red" type="submit">Deactivate</button>
                            {% else %}
                                <button class="btn green" type="submit">Activate</button>
                            {% endif %}
                        </form>
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="4">No questions yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(
        content,
        title="Verification Questions",
        questions=questions,
        today=datetime.now().date().isoformat(),
    )
@app.route("/maintenance")
@login_required
@role_required("admin", "maintenance")
def maintenance_dashboard():
    db = get_db()
    items = db.execute(
        """
        SELECT ai.id, ai.report_id, ai.store_number, ai.title, ai.status, ai.created_at, ai.closed_at,
               sr.maintenance_needs
        FROM action_items ai
        LEFT JOIN svr_reports sr ON ai.report_id = sr.id
        ORDER BY ai.status ASC, ai.created_at DESC
        """
    ).fetchall()

    maintenance_items = []
    for row in items:
        maintenance_lines = set(parse_action_items(row["maintenance_needs"] or ""))
        if row["title"] in maintenance_lines:
            maintenance_items.append(row)

    content = """
    <div class="card">
        <h2>Maintenance Dashboard</h2>
        <p class="muted">Maintenance-related items pulled from the Maintenance Needs field.</p>
        <div class="table-wrap"><table>
            <thead><tr><th>Store</th><th>Item</th><th>Status</th><th>Created</th><th>Closed</th><th></th></tr></thead>
            <tbody>
                {% for row in maintenance_items %}
                <tr>
                    <td>{{ row['store_number'] }}</td>
                    <td>{{ row['title'] }}</td>
                    <td>
                        {% if row['status'] == 'open' %}
                            <span class="badge badge-open">Open</span>
                        {% else %}
                            <span class="badge badge-closed">Closed</span>
                        {% endif %}
                    </td>
                    <td>{{ row['created_at'][:10] }}</td>
                    <td>{{ row['closed_at'][:10] if row['closed_at'] else '—' }}</td>
                    <td>
                        {% if row['status'] == 'open' %}
                            <a class="btn green" href="{{ url_for('close_action_item', item_id=row['id']) }}">Close</a>
                        {% else %}
                            <a class="btn secondary" href="{{ url_for('reopen_action_item', item_id=row['id']) }}">Reopen</a>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="6">No maintenance items yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(content, title="Maintenance Dashboard", maintenance_items=maintenance_items)


@app.route("/action-items")
@login_required
@role_required("admin")
def action_dashboard():
    db = get_db()
    items = db.execute(
        "SELECT id, report_id, store_number, title, status, created_at, closed_at FROM action_items ORDER BY status ASC, created_at DESC"
    ).fetchall()

    content = """
    <div class="card">
        <h2>Action Items</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Store</th><th>Action Item</th><th>Status</th><th>Created</th><th>Closed</th><th></th></tr></thead>
            <tbody>
                {% for row in items %}
                <tr>
                    <td>{{ row['store_number'] }}</td>
                    <td>{{ row['title'] }}</td>
                    <td>
                        {% if row['status'] == 'open' %}
                            <span class="badge badge-open">Open</span>
                        {% else %}
                            <span class="badge badge-closed">Closed</span>
                        {% endif %}
                    </td>
                    <td>{{ row['created_at'][:10] }}</td>
                    <td>{{ row['closed_at'][:10] if row['closed_at'] else '—' }}</td>
                    <td>
                        {% if row['status'] == 'open' %}
                            <a class="btn green" href="{{ url_for('close_action_item', item_id=row['id']) }}">Close</a>
                        {% else %}
                            <a class="btn secondary" href="{{ url_for('reopen_action_item', item_id=row['id']) }}">Reopen</a>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="6">No action items yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(content, title="Action Items", items=items)


@app.route("/action-items/<int:item_id>/close")
@login_required
@role_required("admin", "maintenance")
def close_action_item(item_id):
    db = get_db()
    item = db.execute(
        """
        SELECT ai.*, sr.maintenance_needs
        FROM action_items ai
        LEFT JOIN svr_reports sr ON ai.report_id = sr.id
        WHERE ai.id = ?
        """,
        (item_id,),
    ).fetchone()

    if not item:
        flash("Action item not found.", "error")
        return redirect(url_for("home"))

    maintenance_lines = set(parse_action_items(item["maintenance_needs"] or ""))
    is_maintenance_item = item["title"] in maintenance_lines

    if session.get("role") == "maintenance" and not is_maintenance_item:
        flash("Maintenance can only close maintenance items.", "error")
        return redirect(url_for("maintenance_dashboard"))

    db.execute(
        "UPDATE action_items SET status = 'closed', closed_at = ? WHERE id = ?",
        (datetime.now().isoformat(timespec="seconds"), item_id),
    )
    db.commit()
    flash("Action item closed.", "success")

    if session.get("role") == "maintenance":
        return redirect(url_for("maintenance_dashboard"))
    return redirect(url_for("action_dashboard"))


@app.route("/action-items/<int:item_id>/reopen")
@login_required
@role_required("admin", "maintenance")
def reopen_action_item(item_id):
    db = get_db()
    item = db.execute(
        """
        SELECT ai.*, sr.maintenance_needs
        FROM action_items ai
        LEFT JOIN svr_reports sr ON ai.report_id = sr.id
        WHERE ai.id = ?
        """,
        (item_id,),
    ).fetchone()

    if not item:
        flash("Action item not found.", "error")
        return redirect(url_for("home"))

    maintenance_lines = set(parse_action_items(item["maintenance_needs"] or ""))
    is_maintenance_item = item["title"] in maintenance_lines

    if session.get("role") == "maintenance" and not is_maintenance_item:
        flash("Maintenance can only reopen maintenance items.", "error")
        return redirect(url_for("maintenance_dashboard"))

    db.execute(
        "UPDATE action_items SET status = 'open', closed_at = NULL WHERE id = ?",
        (item_id,),
    )
    db.commit()
    flash("Action item reopened.", "success")

    if session.get("role") == "maintenance":
        return redirect(url_for("maintenance_dashboard"))
    return redirect(url_for("action_dashboard"))


@app.route("/report/new", methods=["GET", "POST"])
@login_required
@role_required("admin", "supervisor")
def new_report():
    if request.method == "POST":
        db = get_db()
        now = datetime.now().isoformat(timespec="seconds")

        report_data = {
            "visit_date": safe_text("visit_date") or datetime.now().date().isoformat(),
            "store_number": safe_text("store_number"),
            "supervisor_username": session.get("username"),
            "supervisor_name": session.get("display_name"),
            "manager_on_duty": safe_text("manager_on_duty"),
            "checklist_book_use": clean_yes_no("checklist_book_use"),
            "restroom_notes": safe_text("restroom_notes"),
            "pizza_quality_notes": safe_text("pizza_quality_notes"),
            "last_week_svr_review": safe_text("last_week_svr_review"),
            "outside_store_condition_notes": safe_text("outside_store_condition_notes"),
            "carryout_notes": safe_text("carryout_notes"),
            "store_condition_notes": safe_text("store_condition_notes"),
            "refrigeration_units_notes": safe_text("refrigeration_units_notes"),
            "bake_wares_notes": safe_text("bake_wares_notes"),
            "oven_heatrack_notes": safe_text("oven_heatrack_notes"),
            "callout_calendar_notes": safe_text("callout_calendar_notes"),
            "deposit_log_notes": safe_text("deposit_log_notes"),
            "pest_control_status": safe_text("pest_control_status"),
            "cleaning_list": safe_text("cleaning_list"),
            "goals_for_week": safe_text("goals_for_week"),
            "maintenance_needs": safe_text("maintenance_needs"),
            "complete_solution": safe_text("complete_solution"),
            "parking_lot_clean": clean_yes_no("parking_lot_clean"),
            "carryout_clean": clean_yes_no("carryout_clean"),
            "customer_area_condition": clean_yes_no("customer_area_condition"),
            "uniforms_proper": clean_yes_no("uniforms_proper"),
            "hot_bags_clean": clean_yes_no("hot_bags_clean"),
            "hot_bags_condition": clean_yes_no("hot_bags_condition"),
            "production_area_clean": clean_yes_no("production_area_clean"),
            "ceiling_tiles_clean": clean_yes_no("ceiling_tiles_clean"),
            "walls_floors_not_broken": clean_yes_no("walls_floors_not_broken"),
            "walkin_makeline_clean": clean_yes_no("walkin_makeline_clean"),
            "bakeware_clean": clean_yes_no("bakeware_clean"),
            "oven_area_clean": clean_yes_no("oven_area_clean"),
            "thermometers_available": clean_yes_no("thermometers_available"),
            "scales_available": clean_yes_no("scales_available"),
            "caller_id_working": clean_yes_no("caller_id_working"),
            "callout_calendar_present": clean_yes_no("callout_calendar_present"),
            "created_at": now,
        }

        if not report_data["store_number"]:
            flash("Store number is required.", "error")
            return redirect(url_for("new_report"))

        columns = ", ".join(report_data.keys())
        placeholders = ", ".join(["?"] * len(report_data))
        values = tuple(report_data.values())

        cur = db.execute(
            f"INSERT INTO svr_reports ({columns}) VALUES ({placeholders})",
            values,
        )
        report_id = cur.lastrowid

        auto_items = []

        goals_items = parse_action_items(report_data["goals_for_week"])
        clean_items = parse_action_items(report_data["cleaning_list"])
        maintenance_items = parse_action_items(report_data["maintenance_needs"])

        for item in goals_items + clean_items:
            if item not in auto_items:
                auto_items.append(item)

        for item in maintenance_items:
            if item not in auto_items:
                auto_items.append(item)

        fail_map = {
            "hot_bags_clean": "Clean hot bags",
            "production_area_clean": "Deep clean production area",
            "walkin_makeline_clean": "Clean walk-in and makeline",
            "bakeware_clean": "Clean or replace bakeware",
            "parking_lot_clean": "Clean parking lot / sidewalk entry",
            "uniforms_proper": "Correct uniform and grooming standards",
            "callout_calendar_present": "Update callout calendar",
        }
        for field, label in fail_map.items():
            if report_data[field] == "No" and label not in auto_items:
                auto_items.append(label)

        for item in auto_items:
            db.execute(
                """
                INSERT INTO action_items (report_id, store_number, title, status, created_at)
                VALUES (?, ?, ?, 'open', ?)
                """,
                (report_id, report_data["store_number"], item, now),
            )

        files = request.files.getlist("photos")
        for file in files:
            if not file or not file.filename or not allowed_image(file.filename):
                continue

            original_name = secure_filename(file.filename)
            ext = Path(original_name).suffix.lower()
            new_filename = f"{uuid4().hex}{ext}"
            file.save(UPLOAD_FOLDER / new_filename)

            db.execute(
                """
                INSERT INTO svr_photos (report_id, filename, original_filename, uploaded_at)
                VALUES (?, ?, ?, ?)
                """,
                (report_id, new_filename, original_name, now),
            )

        db.commit()
        flash("SVR submitted successfully.", "success")
        return redirect(url_for("view_report", report_id=report_id))

    checks = [
        ("checklist_book_use", "Checklist book use"),
        ("parking_lot_clean", "Parking lot / sidewalk entry clean"),
        ("carryout_clean", "Carry out clean, seating counter, and surfaces"),
        ("customer_area_condition", "Customer area condition okay"),
        ("uniforms_proper", "Uniforms / aprons worn properly"),
        ("hot_bags_clean", "Hot bags clean"),
        ("hot_bags_condition", "Hot bags in good condition / sufficient #"),
        ("production_area_clean", "Production area walls / floors / baseboards / windows clean"),
        ("ceiling_tiles_clean", "Ceiling tiles, t-bars, vents clean and not broken"),
        ("walls_floors_not_broken", "Walls, floors, baseboards not broken"),
        ("walkin_makeline_clean", "Walk-in / makeline clean"),
        ("bakeware_clean", "Bakeware clean and free of carbon build-up"),
        ("oven_area_clean", "Oven area clean"),
        ("thermometers_available", "Calibrated thermometers in use / available"),
        ("scales_available", "Calibrated working scales and job aids available"),
        ("caller_id_working", "Caller ID installed and working"),
        ("callout_calendar_present", "Callout calendar present"),
    ]

    content = """
    <div class="card">
        <h2>New Supervisor Visit Report</h2>
        <p class="muted">Fill out the visit details below. Photos are optional.</p>
        <form method="post" enctype="multipart/form-data">
            <div class="three-col">
                <div><label>Date</label><input type="date" name="visit_date" value="{{ today }}"></div>
                <div><label>Store #</label><input type="text" name="store_number" placeholder="3216" required></div>
                <div><label>Manager on duty</label><input type="text" name="manager_on_duty" placeholder="Tyler"></div>
            </div>

            <div class="card" style="margin-top:16px; background:#fbfdff;">
                <h3>Yes / No / N/A Checks</h3>
                <div class="check-grid">
                    {% for field, label in checks %}
                    <div class="check-item">
                        <label>{{ label }}</label>
                        <select name="{{ field }}">
                            <option value="Yes">Yes</option>
                            <option value="No">No</option>
                            <option value="N/A">N/A</option>
                        </select>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="two-col"><div><label>Restroom notes</label><textarea name="restroom_notes"></textarea></div><div><label>Pizza quality notes</label><textarea name="pizza_quality_notes"></textarea></div></div>
            <div class="two-col"><div><label>Last week's SVR review</label><textarea name="last_week_svr_review"></textarea></div><div><label>Outside store condition notes</label><textarea name="outside_store_condition_notes"></textarea></div></div>
            <div class="two-col"><div><label>Carryout notes</label><textarea name="carryout_notes"></textarea></div><div><label>Store condition notes</label><textarea name="store_condition_notes"></textarea></div></div>
            <div class="two-col"><div><label>Refrigeration units notes</label><textarea name="refrigeration_units_notes"></textarea></div><div><label>Bake wares notes</label><textarea name="bake_wares_notes"></textarea></div></div>
            <div class="two-col"><div><label>Oven / heatrack notes</label><textarea name="oven_heatrack_notes"></textarea></div><div><label>Callout calendar notes</label><textarea name="callout_calendar_notes"></textarea></div></div>
            <div class="two-col"><div><label>Deposit log notes</label><textarea name="deposit_log_notes"></textarea></div><div><label>Pest control status</label><input type="text" name="pest_control_status" placeholder="Up to date"></div></div>
            <div><label>Cleaning list for the week</label><textarea name="cleaning_list" placeholder="One item per line"></textarea></div>
            <div><label>Goals for the week</label><textarea name="goals_for_week" placeholder="One item per line"></textarea></div>
            <div class="two-col"><div><label>Maintenance needs</label><textarea name="maintenance_needs" placeholder="One item per line"></textarea></div><div><label>The complete solution</label><textarea name="complete_solution"></textarea></div></div>
            <div style="margin-top:14px;"><label>Upload photos</label><input type="file" name="photos" multiple accept="image/*"></div>
            <div style="margin-top:18px;"><button class="btn" type="submit">Submit SVR</button></div>
        </form>
    </div>
    """
    return render_page(
        content,
        title="New SVR",
        today=datetime.now().date().isoformat(),
        checks=checks,
    )
@app.route("/report/<int:report_id>")
@login_required
@role_required("admin", "supervisor")
def view_report(report_id):
    db = get_db()
    report = db.execute(
        "SELECT * FROM svr_reports WHERE id = ?",
        (report_id,),
    ).fetchone()

    if not report:
        flash("Report not found.", "error")
        return redirect(url_for("home"))

    if session.get("role") == "supervisor" and report["supervisor_username"] != session.get("username"):
        flash("You do not have access to that report.", "error")
        return redirect(url_for("home"))

    photos = db.execute(
        "SELECT * FROM svr_photos WHERE report_id = ? ORDER BY uploaded_at ASC",
        (report_id,),
    ).fetchall()

    actions = db.execute(
        "SELECT * FROM action_items WHERE report_id = ? ORDER BY created_at ASC",
        (report_id,),
    ).fetchall()

    contact = get_store_contact(report["store_number"])
    email_link = build_manager_email_link(report, actions, contact)

    checks = [
        ("checklist_book_use", "Checklist book use"),
        ("parking_lot_clean", "Parking lot / sidewalk entry clean"),
        ("carryout_clean", "Carry out clean, seating counter, and surfaces"),
        ("customer_area_condition", "Customer area condition okay"),
        ("uniforms_proper", "Uniforms / aprons worn properly"),
        ("hot_bags_clean", "Hot bags clean"),
        ("hot_bags_condition", "Hot bags in good condition / sufficient #"),
        ("production_area_clean", "Production area clean"),
        ("ceiling_tiles_clean", "Ceiling tiles, t-bars, vents clean and not broken"),
        ("walls_floors_not_broken", "Walls, floors, baseboards not broken"),
        ("walkin_makeline_clean", "Walk-in / makeline clean"),
        ("bakeware_clean", "Bakeware clean and free of carbon build-up"),
        ("oven_area_clean", "Oven area clean"),
        ("thermometers_available", "Calibrated thermometers in use / available"),
        ("scales_available", "Calibrated working scales and job aids available"),
        ("caller_id_working", "Caller ID installed and working"),
        ("callout_calendar_present", "Callout calendar present"),
    ]

    content = """
    <div class="card">
        <h2>SVR Report</h2>
        <div class="grid">
            <div class="stat"><div class="label">Date</div><div class="value">{{ report['visit_date'] }}</div></div>
            <div class="stat"><div class="label">Store</div><div class="value">{{ report['store_number'] }}</div></div>
            <div class="stat"><div class="label">Supervisor</div><div class="value">{{ report['supervisor_name'] }}</div></div>
            <div class="stat"><div class="label">MOD</div><div class="value">{{ report['manager_on_duty'] or '—' }}</div></div>
        </div>
    </div>

    <div class="card">
        <h3>Checklist Results</h3>
        <div class="table-wrap"><table>
            <thead><tr><th>Item</th><th>Status</th></tr></thead>
            <tbody>
                {% for field, label in checks %}
                <tr><td>{{ label }}</td><td>{{ yes_no_badge(report[field])|safe }}</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>

    <div class="two-col"><div class="card"><h3>Restroom notes</h3><p>{{ report['restroom_notes'] or '—' }}</p></div><div class="card"><h3>Pizza quality notes</h3><p>{{ report['pizza_quality_notes'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Last week's SVR review</h3><p>{{ report['last_week_svr_review'] or '—' }}</p></div><div class="card"><h3>Outside store condition notes</h3><p>{{ report['outside_store_condition_notes'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Carryout notes</h3><p>{{ report['carryout_notes'] or '—' }}</p></div><div class="card"><h3>Store condition notes</h3><p>{{ report['store_condition_notes'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Refrigeration notes</h3><p>{{ report['refrigeration_units_notes'] or '—' }}</p></div><div class="card"><h3>Bake wares notes</h3><p>{{ report['bake_wares_notes'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Oven / heatrack notes</h3><p>{{ report['oven_heatrack_notes'] or '—' }}</p></div><div class="card"><h3>Callout calendar notes</h3><p>{{ report['callout_calendar_notes'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Deposit log notes</h3><p>{{ report['deposit_log_notes'] or '—' }}</p></div><div class="card"><h3>Pest control</h3><p>{{ report['pest_control_status'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Cleaning list</h3><p style="white-space:pre-wrap;">{{ report['cleaning_list'] or '—' }}</p></div><div class="card"><h3>Goals for the week</h3><p style="white-space:pre-wrap;">{{ report['goals_for_week'] or '—' }}</p></div></div>
    <div class="two-col"><div class="card"><h3>Maintenance needs</h3><p style="white-space:pre-wrap;">{{ report['maintenance_needs'] or '—' }}</p></div><div class="card"><h3>The complete solution</h3><p style="white-space:pre-wrap;">{{ report['complete_solution'] or '—' }}</p></div></div>

    <div class="card">
        <h3>Action Items</h3>
        <div class="table-wrap"><table>
            <thead><tr><th>Item</th><th>Status</th></tr></thead>
            <tbody>
                {% for item in actions %}
                <tr>
                    <td>{{ item['title'] }}</td>
                    <td>
                        {% if item['status'] == 'open' %}
                            <span class="badge badge-open">Open</span>
                        {% else %}
                            <span class="badge badge-closed">Closed</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="2">No action items.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>

    {% if photos %}
    <div class="card">
        <h3>Photos</h3>
        <div class="photo-grid">
            {% for photo in photos %}
            <div>
                <a href="{{ url_for('uploaded_file', filename=photo['filename']) }}" target="_blank">
                    <img src="{{ url_for('uploaded_file', filename=photo['filename']) }}" alt="SVR photo">
                </a>
                <div class="small muted">{{ photo['original_filename'] }}</div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <div class="card">
        <h3>Send to Manager</h3>
        <p class="muted">Use the clean manager summary page to copy or send the report to the manager.</p>
        <a class="btn secondary" href="{{ url_for('manager_summary', report_id=report['id']) }}">Open Manager Summary</a>
        {% if email_link %}
            <a class="btn" href="{{ email_link }}">Email Manager</a>
        {% else %}
            <p class="small muted">No manager email saved for store {{ report['store_number'] }}. Add it in Store Contacts.</p>
        {% endif %}
    </div>

    {% if session.get('role') == 'admin' %}
    <div class="card">
        {% if report['is_archived'] == 0 %}
            <a class="btn secondary" href="{{ url_for('archive_report', report_id=report['id']) }}">Archive SVR</a>
        {% else %}
            <a class="btn secondary" href="{{ url_for('restore_report', report_id=report['id']) }}">Restore SVR</a>
        {% endif %}
    </div>
    <div class="card danger-zone">
        <h3>Delete SVR</h3>
        <p class="muted">This permanently deletes the SVR, photos, and linked action items.</p>
        <a class="btn red" href="{{ url_for('delete_report', report_id=report['id']) }}">Delete SVR</a>
    </div>
    {% endif %}
    """
    return render_page(
        content,
        title="View Report",
        report=report,
        photos=photos,
        actions=actions,
        checks=checks,
        email_link=email_link,
    )


@app.route("/manager-summary/<int:report_id>")
@login_required
@role_required("admin", "supervisor")
def manager_summary(report_id):
    db = get_db()
    report = db.execute(
        "SELECT * FROM svr_reports WHERE id = ?",
        (report_id,),
    ).fetchone()

    if not report:
        flash("Report not found.", "error")
        return redirect(url_for("home"))

    if session.get("role") == "supervisor" and report["supervisor_username"] != session.get("username"):
        flash("You do not have access to that report.", "error")
        return redirect(url_for("home"))

    all_actions = db.execute(
        "SELECT * FROM action_items WHERE report_id = ? ORDER BY created_at ASC",
        (report_id,),
    ).fetchall()

    maintenance_lines = set(parse_action_items(report["maintenance_needs"]))
    manager_actions = [item for item in all_actions if item["title"] not in maintenance_lines]

    contact = get_store_contact(report["store_number"])
    email_link = build_manager_email_link(report, all_actions, contact)

    content = """
    <div class="card">
        <h2>Manager Summary</h2>
        <p class="muted">This is the clean version to send to the store manager.</p>

        <div class="card" style="background:#fbfdff;">
            <p><strong>Store:</strong> {{ report['store_number'] }}</p>
            <p><strong>Date:</strong> {{ report['visit_date'] }}</p>
            <p><strong>Supervisor:</strong> {{ report['supervisor_name'] }}</p>
            <p><strong>Manager on Duty:</strong> {{ report['manager_on_duty'] or '—' }}</p>

            <p><strong>Store Condition Notes:</strong></p>
            <p style="white-space:pre-wrap;">{{ report['store_condition_notes'] or '—' }}</p>

            <p><strong>Goals for the Week:</strong></p>
            <p style="white-space:pre-wrap;">{{ report['goals_for_week'] or '—' }}</p>

            <p><strong>Action Items:</strong></p>
            <ul>
                {% for item in manager_actions %}
                <li>{{ item['title'] }}</li>
                {% else %}
                <li>No non-maintenance action items.</li>
                {% endfor %}
            </ul>

            <p><strong>Maintenance Needs:</strong></p>
            <p style="white-space:pre-wrap;">{{ report['maintenance_needs'] or '—' }}</p>
        </div>

        <div style="margin-top:12px;">
            {% if email_link %}
                <a class="btn" href="{{ email_link }}">Email Manager</a>
            {% else %}
                <p class="small muted">No manager email saved for this store. Add it in Store Contacts.</p>
            {% endif %}
        </div>
    </div>
    """
    return render_page(
        content,
        title="Manager Summary",
        report=report,
        manager_actions=manager_actions,
        email_link=email_link,
    )


@app.route("/verification/<int:form_id>/archive")
@login_required
@role_required("admin")
def archive_verification(form_id):
    db = get_db()
    db.execute(
        "UPDATE verification_forms SET is_archived = 1 WHERE id = ?",
        (form_id,),
    )
    db.commit()
    flash("Verification archived.", "success")
    return redirect(url_for("view_verification", form_id=form_id))


@app.route("/verification/<int:form_id>/restore")
@login_required
@role_required("admin")
def restore_verification(form_id):
    db = get_db()
    db.execute(
        "UPDATE verification_forms SET is_archived = 0 WHERE id = ?",
        (form_id,),
    )
    db.commit()
    flash("Verification restored.", "success")
    return redirect(url_for("view_verification", form_id=form_id))


@app.route("/verification/<int:form_id>/delete")
@login_required
@role_required("admin")
def delete_verification(form_id):
    db = get_db()
    db.execute(
        "DELETE FROM verification_forms WHERE id = ?",
        (form_id,),
    )
    db.commit()
    flash("Verification deleted permanently.", "success")
    return redirect(url_for("verification_dashboard"))


@app.route("/report/<int:report_id>/archive")
@login_required
@role_required("admin")
def archive_report(report_id):
    db = get_db()
    db.execute(
        "UPDATE svr_reports SET is_archived = 1 WHERE id = ?",
        (report_id,),
    )
    db.commit()
    flash("SVR archived.", "success")
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/report/<int:report_id>/restore")
@login_required
@role_required("admin")
def restore_report(report_id):
    db = get_db()
    db.execute(
        "UPDATE svr_reports SET is_archived = 0 WHERE id = ?",
        (report_id,),
    )
    db.commit()
    flash("SVR restored.", "success")
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/report/<int:report_id>/delete")
@login_required
@role_required("admin")
def delete_report(report_id):
    db = get_db()

    photos = db.execute(
        "SELECT filename FROM svr_photos WHERE report_id = ?",
        (report_id,),
    ).fetchall()

    for photo in photos:
        path = UPLOAD_FOLDER / photo["filename"]
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass

    db.execute(
        "DELETE FROM svr_reports WHERE id = ?",
        (report_id,),
    )
    db.commit()
    flash("SVR deleted permanently.", "success")
    return redirect(url_for("dashboard"))


@app.route("/store/<store_number>")
@login_required
@role_required("admin")
def store_history(store_number):
    db = get_db()
    reports = db.execute(
        "SELECT * FROM svr_reports WHERE store_number = ? ORDER BY visit_date DESC, created_at DESC",
        (store_number,),
    ).fetchall()

    rows = []
    for row in reports:
        rows.append(
            {
                "id": row["id"],
                "visit_date": row["visit_date"],
                "supervisor_name": row["supervisor_name"],
                "manager_on_duty": row["manager_on_duty"],
                "fails": count_failures(row),
                "archived": row["is_archived"],
            }
        )

    content = """
    <div class="card">
        <h2>Store {{ store_number }} History</h2>
        <div class="table-wrap"><table>
            <thead><tr><th>Date</th><th>Supervisor</th><th>MOD</th><th>Fails</th><th>Status</th><th></th></tr></thead>
            <tbody>
                {% for row in rows %}
                <tr>
                    <td>{{ row.visit_date }}</td>
                    <td>{{ row.supervisor_name }}</td>
                    <td>{{ row.manager_on_duty or '—' }}</td>
                    <td>{{ row.fails }}</td>
                    <td>{% if row.archived == 1 %}<span class="badge badge-na">Archived</span>{% else %}<span class="badge badge-yes">Active</span>{% endif %}</td>
                    <td><a class="btn secondary" href="{{ url_for('view_report', report_id=row.id) }}">Open</a></td>
                </tr>
                {% else %}
                <tr><td colspan="6">No reports for this store yet.</td></tr>
                {% endfor %}
            </tbody>
        </table></div>
    </div>
    """
    return render_page(
        content,
        title=f"Store {store_number}",
        rows=rows,
        store_number=store_number,
    )


@app.route("/archived")
@login_required
@role_required("admin")
def archived_reports():
    db = get_db()
    archived_svrs = db.execute(
        "SELECT id, visit_date, store_number, supervisor_name FROM svr_reports WHERE is_archived = 1 ORDER BY created_at DESC"
    ).fetchall()
    archived_verifications = db.execute(
        "SELECT id, week_label, visit_date, store_number, supervisor_name FROM verification_forms WHERE is_archived = 1 ORDER BY created_at DESC"
    ).fetchall()

    content = """
    <div class="two-col">
        <div class="card">
            <h2>Archived SVRs</h2>
            <div class="table-wrap"><table>
                <thead><tr><th>Date</th><th>Store</th><th>Supervisor</th><th></th></tr></thead>
                <tbody>
                    {% for row in archived_svrs %}
                    <tr>
                        <td>{{ row['visit_date'] }}</td>
                        <td>{{ row['store_number'] }}</td>
                        <td>{{ row['supervisor_name'] }}</td>
                        <td><a class="btn secondary" href="{{ url_for('view_report', report_id=row['id']) }}">Open</a></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4">No archived SVRs.</td></tr>
                    {% endfor %}
                </tbody>
            </table></div>
        </div>

        <div class="card">
            <h2>Archived Verifications</h2>
            <div class="table-wrap"><table>
                <thead><tr><th>Week</th><th>Store</th><th>Supervisor</th><th></th></tr></thead>
                <tbody>
                    {% for row in archived_verifications %}
                    <tr>
                        <td>{{ row['week_label'] }}</td>
                        <td>{{ row['store_number'] }}</td>
                        <td>{{ row['supervisor_name'] }}</td>
                        <td><a class="btn secondary" href="{{ url_for('view_verification', form_id=row['id']) }}">Open</a></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4">No archived verifications.</td></tr>
                    {% endfor %}
                </tbody>
            </table></div>
        </div>
    </div>
    """
    return render_page(
        content,
        title="Archived",
        archived_svrs=archived_svrs,
        archived_verifications=archived_verifications,
    )


@app.route("/uploads/<path:filename>")
@login_required
@role_required("admin", "supervisor")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)