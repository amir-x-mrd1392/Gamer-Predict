import os, sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE-ME-BEFORE-PUBLISHING")
DB = os.environ.get("DATABASE_PATH", "gamers.db")

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS matches(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      game TEXT NOT NULL,
      title TEXT NOT NULL,
      team1 TEXT NOT NULL,
      team2 TEXT NOT NULL,
      starts_at TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      winner TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS predictions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      match_id INTEGER NOT NULL REFERENCES matches(id),
      choice TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, match_id)
    );
    """)
    # Bootstrap admin only from environment variables; never use a public default password.
    admin_name = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_name and admin_password:
        existing = con.execute("SELECT id FROM users WHERE username=?", (admin_name,)).fetchone()
        if not existing:
            con.execute("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)",
                        (admin_name, generate_password_hash(admin_password)))
    con.commit()
    con.close()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    con = db()
    user = con.execute("SELECT id,username,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    return user

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("برای ادامه وارد حساب خودت شو.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["is_admin"]:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    user = current_user()
    con = db()
    matches = con.execute("""
      SELECT m.*,
      (SELECT choice FROM predictions p WHERE p.match_id=m.id AND p.user_id=?) AS my_choice
      FROM matches m ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, starts_at, id DESC
    """, (user["id"] if user else -1,)).fetchall()
    con.close()
    return render_template("index.html", user=user, matches=matches)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(username) > 24 or len(password) < 10:
            flash("نام کاربری باید ۳ تا ۲۴ نویسه و رمز عبور حداقل ۱۰ نویسه باشد.")
        else:
            con = db()
            try:
                con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                            (username, generate_password_hash(password)))
                con.commit()
                user = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                session.clear()
                session["user_id"] = user["id"]
                flash("حساب ساخته شد؛ خوش آمدی!")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("این نام کاربری قبلاً ثبت شده است.")
            finally:
                con.close()
    return render_template("auth.html", title="ثبت‌نام", user=current_user())

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        con = db()
        user = con.execute("SELECT * FROM users WHERE username=?",
                           (request.form.get("username","").strip(),)).fetchone()
        con.close()
        if user and check_password_hash(user["password_hash"], request.form.get("password","")):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        flash("نام کاربری یا رمز عبور درست نیست.")
    return render_template("auth.html", title="ورود", user=current_user())

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/predict/<int:match_id>", methods=["POST"])
@login_required
def predict(match_id):
    user = current_user()
    choice = request.form.get("choice","")
    con = db()
    match = con.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
    if not match or match["status"] != "open" or choice not in (match["team1"], match["team2"]):
        con.close()
        flash("این پیش‌بینی معتبر نیست یا مهلتش تمام شده.")
        return redirect(url_for("index"))
    try:
        con.execute("INSERT INTO predictions(user_id,match_id,choice) VALUES(?,?,?)",
                    (user["id"], match_id, choice))
        con.commit()
        flash("پیش‌بینی ثبت شد. بعد از ثبت، قابل تغییر نیست.")
    except sqlite3.IntegrityError:
        flash("برای این مسابقه قبلاً پیش‌بینی ثبت کرده‌ای.")
    con.close()
    return redirect(url_for("index"))

@app.route("/leaderboard")
def leaderboard():
    con = db()
    rows = con.execute("""
      SELECT u.id,u.username,
      COALESCE(SUM(CASE WHEN m.status='finished' AND p.choice=m.winner THEN 10 ELSE 0 END),0) points,
      COUNT(p.id) total,
      SUM(CASE WHEN m.status='finished' AND p.choice=m.winner THEN 1 ELSE 0 END) correct
      FROM users u LEFT JOIN predictions p ON p.user_id=u.id
      LEFT JOIN matches m ON m.id=p.match_id
      GROUP BY u.id ORDER BY points DESC, correct DESC, u.username
    """).fetchall()
    con.close()
    return render_template("leaderboard.html", rows=rows, user=current_user())

@app.route("/profile/<int:user_id>")
def profile(user_id):
    con = db()
    person = con.execute("SELECT id,username FROM users WHERE id=?", (user_id,)).fetchone()
    if not person:
        con.close()
        abort(404)
    history = con.execute("""
      SELECT m.game,m.title,m.team1,m.team2,m.status,m.winner,p.choice
      FROM predictions p JOIN matches m ON m.id=p.match_id
      WHERE p.user_id=? ORDER BY p.id DESC
    """, (user_id,)).fetchall()
    points = con.execute("""
      SELECT COALESCE(SUM(CASE WHEN m.status='finished' AND p.choice=m.winner THEN 10 ELSE 0 END),0)
      FROM predictions p JOIN matches m ON m.id=p.match_id WHERE p.user_id=?
    """, (user_id,)).fetchone()[0]
    con.close()
    return render_template("profile.html", person=person, history=history, points=points, user=current_user())

@app.route("/admin")
@admin_required
def admin():
    con = db()
    matches = con.execute("SELECT * FROM matches ORDER BY id DESC").fetchall()
    users = con.execute("SELECT id,username,is_admin,created_at FROM users ORDER BY id DESC").fetchall()
    con.close()
    return render_template("admin.html", matches=matches, users=users, user=current_user())

@app.route("/admin/matches", methods=["POST"])
@admin_required
def add_match():
    game = request.form.get("game","").strip()
    title = request.form.get("title","").strip()
    team1 = request.form.get("team1","").strip()
    team2 = request.form.get("team2","").strip()
    starts_at = request.form.get("starts_at","").strip() or None
    if not all([game,title,team1,team2]) or team1 == team2:
        flash("همه فیلدها را پر کن و دو تیم متفاوت وارد کن.")
    else:
        con = db()
        con.execute("INSERT INTO matches(game,title,team1,team2,starts_at) VALUES(?,?,?,?,?)",
                    (game,title,team1,team2,starts_at))
        con.commit()
        con.close()
        flash("مسابقه اضافه شد.")
    return redirect(url_for("admin"))

@app.route("/admin/matches/<int:match_id>/finish", methods=["POST"])
@admin_required
def finish_match(match_id):
    winner = request.form.get("winner","")
    con = db()
    match = con.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
    if not match or winner not in (match["team1"],match["team2"]):
        flash("برنده انتخاب‌شده معتبر نیست.")
    else:
        con.execute("UPDATE matches SET winner=?,status='finished' WHERE id=?", (winner,match_id))
        con.commit()
        flash("نتیجه ثبت شد و امتیازها به‌صورت خودکار محاسبه شدند.")
    con.close()
    return redirect(url_for("admin"))

@app.route("/admin/matches/<int:match_id>/reopen", methods=["POST"])
@admin_required
def reopen_match(match_id):
    con = db()
    con.execute("UPDATE matches SET winner=NULL,status='open' WHERE id=?", (match_id,))
    con.commit()
    con.close()
    flash("مسابقه دوباره باز شد.")
    return redirect(url_for("admin"))

@app.errorhandler(403)
def forbidden(_):
    return "دسترسی فقط برای مدیر سایت مجاز است.", 403

if __name__ == "__main__":
    init_db()
    app.run(debug=False)
