import json
import os
from functools import wraps

from dotenv import load_dotenv

load_dotenv()
import queue
import secrets
import threading
from datetime import datetime

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///projecttracker.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "error"

# ---------------------------------------------------------------------------
# SSE — per-project subscriber queues
# ---------------------------------------------------------------------------

# { project_id: set of Queue }
_sse_queues: dict[int, set] = {}
_sse_lock = threading.Lock()


def _sse_push(project_id: int, event_type: str, data: dict) -> None:
    """Broadcast an event to every client watching this project."""
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_queues.get(project_id, set()):
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_queues[project_id].discard(q)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    recovery_code_hash = db.Column(db.String(256), nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owned_projects = db.relationship(
        "Project", backref="owner", lazy=True, foreign_keys="Project.owner_id"
    )
    memberships = db.relationship(
        "ProjectMember", backref="user", lazy=True, foreign_keys="ProjectMember.user_id"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_recovery_code(self):
        """Generate a new recovery code, store its hash, return the plain code (shown once)."""
        raw = secrets.token_hex(12)  # 96 bits of entropy
        # Format as xxxx-xxxx-xxxx-xxxx-xxxx-xxxx for readability
        formatted = "-".join(raw[i : i + 4] for i in range(0, 24, 4))
        self.recovery_code_hash = generate_password_hash(
            raw
        )  # store raw (no dashes) as canonical
        return formatted  # caller must show this once and discard

    def check_recovery_code(self, code):
        if not self.recovery_code_hash:
            return False
        canonical = code.replace("-", "").replace(" ", "").lower()
        return check_password_hash(self.recovery_code_hash, canonical)

    @property
    def initials(self):
        return self.username[:2].upper()


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    color = db.Column(db.String(20), default="indigo")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tasks = db.relationship(
        "Task", backref="project", lazy=True, cascade="all, delete-orphan"
    )
    members = db.relationship(
        "ProjectMember", backref="project", lazy=True, cascade="all, delete-orphan"
    )

    @property
    def task_counts(self):
        counts = {"todo": 0, "doing": 0, "done": 0}
        for task in self.tasks:
            if task.container in counts:
                counts[task.container] += 1
        return counts

    @property
    def member_count(self):
        return len(self.members)


class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(20), default="member")  # 'owner' or 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    container = db.Column(db.String(10), default="todo")  # todo | doing | done
    priority = db.Column(db.String(10), default="none")  # none | low | moderate | high
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "container": self.container,
            "priority": self.priority,
            "created_at": self.created_at.strftime("%b %d, %Y"),
        }


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _sync_admin_user():
    """Create or recreate the admin user from ADMIN_USER / ADMIN_PASS env vars.

    If either var is missing, no admin account is managed.
    If the credentials changed since last startup, the old admin is deleted
    (along with any projects they owned) and a fresh one is created.
    """
    admin_user_env = os.environ.get("ADMIN_USER", "").strip()
    admin_pass_env = os.environ.get("ADMIN_PASS", "").strip()

    if not admin_user_env or not admin_pass_env:
        return

    existing = User.query.filter_by(is_admin=True).first()

    if existing:
        if existing.username == admin_user_env and existing.check_password(admin_pass_env):
            return  # Nothing changed
        # Credentials changed — tear down the old admin account
        for project in list(existing.owned_projects):
            db.session.delete(project)
        ProjectMember.query.filter_by(user_id=existing.id).delete()
        db.session.delete(existing)
        db.session.flush()

    # Remove any regular user that would collide on username
    conflict = User.query.filter(
        User.username == admin_user_env, User.is_admin == False  # noqa: E712
    ).first()
    if conflict:
        for project in list(conflict.owned_projects):
            db.session.delete(project)
        ProjectMember.query.filter_by(user_id=conflict.id).delete()
        db.session.delete(conflict)
        db.session.flush()

    admin_email = f"__admin_{admin_user_env}__@system.local"
    admin = User(username=admin_user_env, email=admin_email, is_admin=True)
    admin.set_password(admin_pass_env)
    db.session.add(admin)
    db.session.commit()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if not username or len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(username) > 50:
            error = "Username too long (max 50 chars)."
        elif not email or "@" not in email:
            error = "Invalid email address."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif User.query.filter_by(username=username).first():
            error = "Username already taken."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."

        if error:
            flash(error, "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            plain_code = user.set_recovery_code()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            # Store plain code in session — shown once then discarded
            session["_rc"] = plain_code
            session["_rc_ctx"] = "signup"
            return redirect(url_for("show_recovery_code"))

    return render_template("auth/signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        # Accept either email or username (case-insensitive)
        user = User.query.filter(
            db.or_(
                User.email == identifier.lower(),
                db.func.lower(User.username) == identifier.lower(),
            )
        ).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get("next")
            if user.is_admin and not next_page:
                return redirect(url_for("admin_panel"))
            return redirect(next_page or url_for("dashboard"))
        flash("Invalid credentials.", "error")

    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/auth/recovery-code")
def show_recovery_code():
    """View-once page. Code is in session — popped immediately so a reload shows nothing."""
    code = session.pop("_rc", None)
    ctx = session.pop("_rc_ctx", "signup")  # 'signup' | 'reset'
    if not code:
        # Already viewed or navigated here directly — refuse to show anything
        return redirect(
            url_for("dashboard") if current_user.is_authenticated else url_for("login")
        )
    return render_template("auth/recovery_code.html", code=code, ctx=ctx)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        recovery_code = request.form.get("recovery_code", "").strip()
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        user = User.query.filter_by(email=email).first()

        error = None
        if not user or not user.check_recovery_code(recovery_code):
            # Deliberately vague — don't reveal whether email exists
            error = "Invalid email or recovery code."
        elif len(new_password) < 6:
            error = "Password must be at least 6 characters."
        elif new_password != confirm:
            error = "Passwords do not match."

        if error:
            flash(error, "error")
        else:
            user.set_password(new_password)
            # Invalidate old code and issue a fresh one
            plain_code = user.set_recovery_code()
            db.session.commit()
            # Store new code in session — shown once
            session["_rc"] = plain_code
            session["_rc_ctx"] = "reset"
            return redirect(url_for("show_recovery_code"))

    return render_template("auth/forgot_password.html")


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    if current_user.is_admin:
        flash("Admin credentials are managed via environment variables.", "error")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if not current_user.check_password(current_pw):
            error = "Current password is incorrect."
        elif len(new_pw) < 6:
            error = "New password must be at least 6 characters."
        elif new_pw == current_pw:
            error = "New password must be different from the current one."
        elif new_pw != confirm:
            error = "Passwords do not match."

        if error:
            flash(error, "error")
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            flash("Password updated successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("settings/password.html")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.route("/")
@login_required
def dashboard():
    owned = (
        Project.query.filter_by(owner_id=current_user.id)
        .order_by(Project.created_at.desc())
        .all()
    )

    member_ids = [
        m.project_id
        for m in ProjectMember.query.filter_by(user_id=current_user.id).all()
    ]
    shared = (
        Project.query.filter(
            Project.id.in_(member_ids), Project.owner_id != current_user.id
        )
        .order_by(Project.created_at.desc())
        .all()
    )

    return render_template("dashboard.html", owned=owned, shared=shared)


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------


@app.route("/project/new", methods=["POST"])
@login_required
def create_project():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    color = request.form.get("color", "indigo")

    allowed_colors = [
        "indigo",
        "violet",
        "sky",
        "emerald",
        "rose",
        "amber",
        "pink",
        "teal",
    ]
    if color not in allowed_colors:
        color = "indigo"

    if not title:
        flash("Project title is required.", "error")
        return redirect(url_for("dashboard"))

    project = Project(
        title=title, description=description, color=color, owner_id=current_user.id
    )
    db.session.add(project)
    db.session.flush()

    membership = ProjectMember(
        project_id=project.id, user_id=current_user.id, role="owner"
    )
    db.session.add(membership)
    db.session.commit()

    return redirect(url_for("project_board", project_id=project.id))


@app.route("/project/<int:project_id>")
@login_required
def project_board(project_id):
    project = db.session.get(Project, project_id)
    if project is None:
        flash("Project not found.", "error")
        return redirect(url_for("dashboard"))

    membership = ProjectMember.query.filter_by(
        project_id=project_id, user_id=current_user.id
    ).first()
    if not membership:
        flash("You do not have access to this project.", "error")
        return redirect(url_for("dashboard"))

    tasks = Task.query.filter_by(project_id=project_id).order_by(Task.created_at).all()
    member_rows = ProjectMember.query.filter_by(project_id=project_id).all()
    members = [
        {"user": db.session.get(User, m.user_id), "role": m.role} for m in member_rows
    ]

    todo = [t.to_dict() for t in tasks if t.container == "todo"]
    doing = [t.to_dict() for t in tasks if t.container == "doing"]
    done = [t.to_dict() for t in tasks if t.container == "done"]

    return render_template(
        "project.html",
        project=project,
        todo=todo,
        doing=doing,
        done=done,
        members=members,
        is_owner=(project.owner_id == current_user.id),
    )


@app.route("/project/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if project is None or project.owner_id != current_user.id:
        flash("Not found or unauthorized.", "error")
        return redirect(url_for("dashboard"))

    db.session.delete(project)
    db.session.commit()
    flash(f'"{project.title}" deleted.', "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# SSE stream endpoint
# ---------------------------------------------------------------------------


@app.route("/project/<int:project_id>/stream")
@login_required
def project_stream(project_id):
    """Server-Sent Events stream scoped to one project."""
    membership = ProjectMember.query.filter_by(
        project_id=project_id, user_id=current_user.id
    ).first()
    if not membership:
        return "", 403

    q: queue.Queue = queue.Queue(maxsize=64)
    with _sse_lock:
        _sse_queues.setdefault(project_id, set()).add(q)

    def generate():
        try:
            yield ": connected\n\n"  # initial comment keeps the connection open
            while True:
                try:
                    payload = q.get(timeout=20)
                    yield payload
                except queue.Empty:
                    yield ": heartbeat\n\n"  # keep-alive ping every 20 s
        finally:
            with _sse_lock:
                _sse_queues.get(project_id, set()).discard(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Task API
# ---------------------------------------------------------------------------


def _get_project_with_access(project_id):
    """Return (project, error_response) — only one will be non-None."""
    project = db.session.get(Project, project_id)
    if project is None:
        return None, (jsonify({"error": "Project not found"}), 404)
    membership = ProjectMember.query.filter_by(
        project_id=project_id, user_id=current_user.id
    ).first()
    if not membership:
        return None, (jsonify({"error": "Unauthorized"}), 403)
    return project, None


@app.route("/project/<int:project_id>/task", methods=["POST"])
@login_required
def add_task(project_id):
    project, err = _get_project_with_access(project_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"error": "Title is required"}), 400

    container = data.get("container", "todo")
    if container not in ("todo", "doing", "done"):
        container = "todo"

    priority = data.get("priority", "none")
    if priority not in ("none", "low", "moderate", "high"):
        priority = "none"

    task = Task(
        project_id=project_id,
        title=title[:100],
        description=str(data.get("description", "")),
        container=container,
        priority=priority,
        created_by=current_user.id,
    )
    db.session.add(task)
    db.session.commit()
    _sse_push(project_id, "task_created", {**task.to_dict(), "by": current_user.id})
    return jsonify(task.to_dict()), 201


@app.route("/project/<int:project_id>/task/<int:task_id>", methods=["PATCH", "DELETE"])
@login_required
def update_task(project_id, task_id):
    _, err = _get_project_with_access(project_id)
    if err:
        return err

    task = db.session.get(Task, task_id)
    if task is None or task.project_id != project_id:
        return jsonify({"error": "Task not found"}), 404

    if request.method == "DELETE":
        project = db.session.get(Project, project_id)
        if project.owner_id != current_user.id:
            return jsonify({"error": "Only the project owner can delete tasks"}), 403
        task_id_copy = task.id
        db.session.delete(task)
        db.session.commit()
        _sse_push(
            project_id, "task_deleted", {"id": task_id_copy, "by": current_user.id}
        )
        return jsonify({"success": True})

    data = request.get_json(silent=True) or {}
    if "container" in data and data["container"] in ("todo", "doing", "done"):
        task.container = data["container"]
    if "title" in data and str(data["title"]).strip():
        task.title = str(data["title"]).strip()[:100]
    if "description" in data:
        task.description = str(data["description"])
    if "priority" in data and data["priority"] in ("none", "low", "moderate", "high"):
        task.priority = data["priority"]

    db.session.commit()
    _sse_push(project_id, "task_updated", {**task.to_dict(), "by": current_user.id})
    return jsonify(task.to_dict())


# ---------------------------------------------------------------------------
# Member API
# ---------------------------------------------------------------------------


@app.route("/project/<int:project_id>/member", methods=["POST"])
@login_required
def add_member(project_id):
    project = db.session.get(Project, project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    if project.owner_id != current_user.id:
        return jsonify({"error": "Only the owner can add members"}), 403

    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()
    if not identifier:
        return jsonify({"error": "Username or email required"}), 400

    user = User.query.filter(
        (User.email == identifier.lower()) | (User.username == identifier)
    ).first()

    if not user:
        return jsonify({"error": "User not found. They must sign up first."}), 404
    if user.id == current_user.id:
        return jsonify({"error": "You are already the project owner."}), 400

    existing = ProjectMember.query.filter_by(
        project_id=project_id, user_id=user.id
    ).first()
    if existing:
        return jsonify({"error": f"{user.username} is already a member."}), 400

    member = ProjectMember(project_id=project_id, user_id=user.id, role="member")
    db.session.add(member)
    db.session.commit()

    payload = {
        "id": user.id,
        "username": user.username,
        "initials": user.initials,
        "email": user.email,
        "by": current_user.id,
    }
    _sse_push(project_id, "member_added", payload)
    return jsonify(payload), 201


@app.route("/project/<int:project_id>/member/<int:user_id>", methods=["DELETE"])
@login_required
def remove_member(project_id, user_id):
    project = db.session.get(Project, project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    if project.owner_id != current_user.id:
        return jsonify({"error": "Only the owner can remove members"}), 403
    if user_id == current_user.id:
        return jsonify({"error": "Cannot remove the project owner"}), 400

    member = ProjectMember.query.filter_by(
        project_id=project_id, user_id=user_id
    ).first()
    if not member:
        return jsonify({"error": "Member not found"}), 404

    db.session.delete(member)
    db.session.commit()
    _sse_push(project_id, "member_removed", {"id": user_id, "by": current_user.id})
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Admin panel
# ---------------------------------------------------------------------------


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/panel.html", users=users)


@app.route("/admin/user/<int:user_id>/edit", methods=["POST"])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))

    if user.is_admin:
        flash("Admin credentials are managed via environment variables.", "error")
        return redirect(url_for("admin_panel"))

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    new_password = request.form.get("password", "").strip()

    error = None
    if not username or len(username) < 3:
        error = "Username must be at least 3 characters."
    elif len(username) > 50:
        error = "Username too long (max 50 chars)."
    elif not email or "@" not in email:
        error = "Invalid email address."
    elif User.query.filter(User.username == username, User.id != user_id).first():
        error = "Username already taken."
    elif User.query.filter(User.email == email, User.id != user_id).first():
        error = "Email already registered."
    elif new_password and len(new_password) < 6:
        error = "Password must be at least 6 characters."

    if error:
        flash(error, "error")
    else:
        user.username = username
        user.email = email
        if new_password:
            user.set_password(new_password)
        db.session.commit()
        flash(f'User "{username}" updated.', "success")

    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        flash("User not found.", "error")
        return redirect(url_for("admin_panel"))

    if user.is_admin:
        flash("Admin account is managed via environment variables.", "error")
        return redirect(url_for("admin_panel"))

    username = user.username
    # Cascade: delete owned projects (tasks/members cascade via DB), then memberships
    for project in list(user.owned_projects):
        db.session.delete(project)
    ProjectMember.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{username}" deleted.', "success")
    return redirect(url_for("admin_panel"))


# ---------------------------------------------------------------------------
# Startup — DB init + admin sync (runs under both `python app.py` and gunicorn)
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    # Migrate existing DBs that predate the is_admin column
    with db.engine.connect() as _conn:
        try:
            _conn.execute(db.text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0"))
            _conn.commit()
        except Exception:
            pass
    _sync_admin_user()

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, threaded=True, host="0.0.0.0", port=8080)
