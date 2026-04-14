
import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Dùng ổ đĩa persistent trên Render nếu có, không thì dùng local folder
DATA_DIR = os.environ.get("DATA_DIR") or os.environ.get("RENDER_DISK_PATH") or BASE_DIR
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "users.db")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-this-admin-key")
PORT = int(os.environ.get("PORT", 5000))

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def is_admin(req):
    return req.headers.get("X-Admin-Key", "") == ADMIN_KEY


@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "message": "Render auth server running",
        "db_path": DB_PATH
    })


@app.get("/health")
def health():
    return jsonify({"ok": True, "message": "healthy"})


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if len(username) < 3:
        return jsonify({"ok": False, "message": "Tên tài khoản phải từ 3 ký tự."}), 400
    if len(password) < 4:
        return jsonify({"ok": False, "message": "Mật khẩu phải từ 4 ký tự."}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        conn.close()
        return jsonify({"ok": False, "message": "Tài khoản đã tồn tại."}), 409

    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password))
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Đăng ký thành công."})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, password_hash, is_active FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"ok": False, "message": "Sai tài khoản hoặc mật khẩu."}), 401
    if int(user["is_active"]) != 1:
        return jsonify({"ok": False, "message": "Tài khoản đã bị khóa."}), 403
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "message": "Sai tài khoản hoặc mật khẩu."}), 401

    return jsonify({
        "ok": True,
        "message": "Đăng nhập thành công.",
        "username": user["username"],
        "user_id": user["id"]
    })


@app.get("/admin/users")
def admin_users():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "Admin key không hợp lệ."}), 403

    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, is_active, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "users": [
            {
                "id": row["id"],
                "username": row["username"],
                "is_active": int(row["is_active"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    })


@app.post("/admin/set-active")
def admin_set_active():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "Admin key không hợp lệ."}), 403

    data = request.get_json(silent=True) or {}
    user_id = int(data.get("user_id", 0))
    is_active = int(data.get("is_active", 1))

    conn = get_db()
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Đã cập nhật trạng thái tài khoản."})


@app.post("/admin/reset-password")
def admin_reset_password():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "Admin key không hợp lệ."}), 403

    data = request.get_json(silent=True) or {}
    user_id = int(data.get("user_id", 0))
    new_password = str(data.get("new_password", "")).strip()

    if len(new_password) < 4:
        return jsonify({"ok": False, "message": "Mật khẩu mới phải từ 4 ký tự."}), 400

    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Đã đặt lại mật khẩu."})


@app.post("/admin/delete-user")
def admin_delete_user():
    if not is_admin(request):
        return jsonify({"ok": False, "message": "Admin key không hợp lệ."}), 403

    data = request.get_json(silent=True) or {}
    user_id = int(data.get("user_id", 0))

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": "Đã xóa tài khoản."})


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
