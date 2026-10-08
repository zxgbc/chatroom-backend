# -*- coding: utf-8 -*-
"""
畅聊ChatRoom 后端（单文件版，兼容 PythonAnywhere WSGI 部署）
================================================================

本文件是与「畅聊ChatRoom_1.0.apk」客户端完全对口的后端实现：
所有接口、字段名、错误码与客户端反编译契约一一对应，包含：

  注册/登录/邮箱验证码、公共聊天（含违禁词过滤、撤回）、私聊（含撤回）、
  好友（搜索 QQ 号加好友/同意/拒绝/删除/会话列表）、心跳在线状态、
  账号注销（申请/取消/管理员审核）、管理后台（统计/用户/消息/私聊/
  功能入口/违禁词/注销审核）。

-------------------------------
一、依赖（requirements.txt）
-------------------------------
  flask

-------------------------------
二、PythonAnywhere 部署步骤
-------------------------------
1) 把本文件 app.py 上传到 PythonAnywhere 的某个目录（如 /home/你的账号/chatroom/）。
2) 在同目录添加 requirements.txt（内容：flask），并在 Bash 控制台创建虚拟环境并安装：
       mkvirtualenv --python=python3.10 chatroom-venv
       pip install -r requirements.txt
3) 配置环境变量（PythonAnywhere 的 Web 标签页 -> WSGI 配置文件里，或 .env 方式，见下节）。
4) Web 页新建一个 Web 应用：选 Manual configuration -> Python 3.10，然后编辑 WSGI 文件，
   建议内容（把路径换成你自己的）：
       import sys
       sys.path.insert(0, '/home/你的账号/chatroom')
       from app import application
5) Reload 即可。首次请求会自动建表并创建管理员账号。
6) 手机上：在 APK 登录页点「服务器地址设置」，填   https://你的账号.pythonanywhere.com

-------------------------------
三、环境变量配置（均在 PythonAnywhere 的 WSGI 配置文件中用 os.environ 设置）
-------------------------------
  MAIL_USER    QQ 邮箱账号，默认  3664129075@qq.com（与 APK 内置管理员一致）
  MAIL_PASS    QQ 邮箱 SMTP 授权码（在 QQ 邮箱设置->账号->开启 SMTP 时生成）
               【注意】授权码属于敏感凭据，只放在环境变量里，本文件不会写入任何文件。
  MAIL_HOST    默认 smtp.qq.com        MAIL_PORT  默认 465（SSL）
  MAIL_USE_SSL 默认 1
  ADMIN_PASSWORD  管理员初始密码，默认 admin123456（部署后请立刻修改）
  REQUIRE_VERIFY_CODE  设为 1 时注册必须校验邮箱验证码（默认 0，与客户端行为一致）
  CCR_FAKE_SMTP       设为 1 时跳过真实发信，验证码直接回填到客户端（本地联调用）

未配置 MAIL_USER/MAIL_PASS 时，后端自动进入「联调模式」：
不再尝试发信，/api/send_code 会在响应里返回 code_val 字段，客户端会自动填入验证码。

-------------------------------
四、数据库
-------------------------------
  默认使用与本文件同目录的 chatroom.db（SQLite 3，WAL 模式），
  可用环境变量 DB_PATH 指定其它路径。
  建表逻辑会在「模块被导入时」和「每个请求前」各执行一次（幂等 CREATE TABLE IF NOT EXISTS），
  因此无论 PythonAnywhere 的 WSGI 导入方式还是本地 python app.py 都能正确初始化数据库，
  不会出现"首次请求表不存在"的问题。建表全程有线程锁保护，避免多线程并发重复建表/死锁。
"""

import os
import re
import smtplib
import sqlite3
import secrets
import string
import threading
from datetime import datetime, timedelta, timezone
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# 0. 配置
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "chatroom.db"))

CST = timezone(timedelta(hours=8))
ONLINE_WINDOW = 90      # 心跳视为在线的秒数
RECALL_WINDOW = 120     # 允许撤回的秒数
MAX_MSG_LEN = 1000      # 消息最大长度（客户端同款限制）
SEND_CODE_INTERVAL = 60 # 验证码发送间隔（秒）
VERIFY_CODE_TTL = 300   # 验证码有效期（秒）

ADMIN_EMAIL = (os.environ.get("ADMIN_EMAIL") or "3664129075@qq.com").lower().strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "admin1234"
ADMIN_NICKNAME = os.environ.get("ADMIN_NICKNAME") or "管理员"
REQUIRE_VERIFY_CODE = os.environ.get("REQUIRE_VERIFY_CODE", "1") == "1"
FAKE_SMTP = os.environ.get("CCR_FAKE_SMTP", "0") == "1"

MAIL_HOST = os.environ.get("MAIL_HOST", "smtp.qq.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "465"))
# 已内置 QQ 邮箱 SMTP 凭据（环境变量 MAIL_USER / MAIL_PASS 可覆盖）
MAIL_USER = (os.environ.get("MAIL_USER") or "3664129075@qq.com").strip()
MAIL_PASS = os.environ.get("MAIL_PASS") or "clpzgwgndckacjdh"
MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "1") == "1"

QQ_EMAIL_RE = re.compile(r"^[A-Za-z0-9]+@qq\.com$")

# --------------------------------------------------------------------------
# 1. Flask 应用与数据库
# --------------------------------------------------------------------------
app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
application = app  # PythonAnywhere WSGI 兼容别名

CREATE_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT NOT NULL,
    qq TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',      -- user / admin
    status TEXT NOT NULL DEFAULT 'active',  -- active / pending / approved / rejected
    created_at TEXT NOT NULL,
    last_seen TEXT DEFAULT '',
    delete_requested_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verify_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    sender_role TEXT DEFAULT 'user',
    content TEXT NOT NULL,          -- 过滤后的展示内容
    original_content TEXT NOT NULL, -- 原始内容（仅管理后台可见）
    filtered INTEGER DEFAULT 0,     -- 是否命中违禁词
    status TEXT NOT NULL DEFAULT 'normal', -- normal / recalled
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    sender_role TEXT DEFAULT 'user',
    receiver_email TEXT NOT NULL,
    content TEXT NOT NULL,
    original_content TEXT NOT NULL,
    filtered INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'normal',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS friends (
    user_email TEXT NOT NULL,
    friend_email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_email, friend_email)
);
CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_email TEXT NOT NULL,
    from_nickname TEXT NOT NULL,
    to_email TEXT NOT NULL,
    status TEXT DEFAULT 'pending', -- pending / accepted / rejected
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bad_words (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    action TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
CREATE INDEX IF NOT EXISTS idx_pm_pair ON private_messages(sender_email, receiver_email, id);
CREATE INDEX IF NOT EXISTS idx_fr_to ON friend_requests(to_email, status);
CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens(email);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=8000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_db():
    """幂等建表 + 管理员引导账号；模块导入与每个请求前都会调用（线程安全）。"""
    with CREATE_LOCK:
        conn = _connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            # 轻量迁移：为旧库补充缺失列（幂等）
            cols = [r[1] for r in conn.execute(
                "PRAGMA table_info(private_messages)").fetchall()]
            if "sender_role" not in cols:
                conn.execute("ALTER TABLE private_messages "
                             "ADD COLUMN sender_role TEXT DEFAULT 'user'")
            now = now_str()
            # 引导管理员账号：保证 ADMIN_EMAIL 始终是管理员，可被 APK 管理员页登录
            row = conn.execute(
                "SELECT role FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO users(email,password_hash,nickname,qq,role,created_at,last_seen,delete_requested_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD),
                     ADMIN_NICKNAME, local_part(ADMIN_EMAIL), "admin",
                     now, "", ""))
                if not os.environ.get("ADMIN_PASSWORD"):
                    print("[WARN] 未设置 ADMIN_PASSWORD，管理员初始密码为默认值，"
                          "请部署后立即在环境变量中修改！", flush=True)
            elif row["role"] != "admin":
                conn.execute("UPDATE users SET role='admin' WHERE email=?",
                             (ADMIN_EMAIL,))
            conn.commit()
        finally:
            conn.close()


def get_db():
    """每个请求独立的连接（避免多线程共享连接的问题）。"""
    if "db" not in g:
        g.db = _connect()
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def _before_request():
    ensure_db()


# --------------------------------------------------------------------------
# 2. 工具函数
# --------------------------------------------------------------------------
def now_dt():
    return datetime.now(CST)


def now_str():
    return now_dt().strftime("%Y-%m-%dT%H:%M:%S+08:00")


def ts_age(ts_text):
    """时间字符串距现在的秒数（无法解析时返回一个很大的数）。"""
    try:
        return (now_dt() - datetime.fromisoformat(ts_text)).total_seconds()
    except Exception:
        return 1e18


def local_part(email):
    return (email or "").split("@", 1)[0]


def is_qq_email(email):
    return bool(email) and bool(QQ_EMAIL_RE.match(email.strip().lower()))


def ok(**fields):
    body = {"code": 0}
    body.update(fields)
    return jsonify(body)


def err(code, message):
    return jsonify({"code": code, "msg": message, "message": message})


def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def req_token():
    if request.method in ("GET", "DELETE"):
        return (request.args.get("token") or "").strip()
    return str(json_body().get("token") or "").strip()


def find_user_by_token(token):
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT u.* FROM tokens t JOIN users u ON u.email=t.email "
        "WHERE t.token=? AND t.expires_at>?",
        (token, now_str())).fetchone()
    return row


def require_user():
    """鉴权：token 无效/过期 -> 401；账号已注销 -> 401（客户端据此强制回登录页）。"""
    token = req_token()
    u = find_user_by_token(token)
    if u is None:
        raise ApiError(401, "登录已失效，请重新登录")
    if u["status"] == "approved":
        raise ApiError(401, "账号已注销，无法登录")
    return u


def require_admin():
    u = require_user()
    if u["role"] != "admin":
        raise ApiError(1, "无权限，请以管理员身份登录")
    return u


def is_online(ts_text):
    return bool(ts_text) and ts_age(ts_text) <= ONLINE_WINDOW


def user_public(u, me_email=None):
    """好友/搜索用户的展示结构。"""
    return {
        "id": u["id"],
        "email": u["email"],
        "nickname": u["nickname"],
        "qq": u["qq"],
        "online": is_online(u["last_seen"]),
        "status": u["status"],
    }


def msg_json(row, me_email=None):
    can_recall = False
    if me_email and row["sender_email"] == me_email and row["status"] == "normal":
        can_recall = ts_age(row["created_at"]) <= RECALL_WINDOW
    return {
        "id": row["id"],
        "sender_email": row["sender_email"],
        "sender_name": row["sender_name"],
        "sender_role": row["sender_role"],
        "content": row["content"],
        "filtered": bool(row["filtered"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "can_recall": can_recall,
    }


def record_json(row):
    """管理后台消息记录结构（RecordItem）。"""
    return {
        "id": row["id"],
        "sender_name": row["sender_name"],
        "sender_role": row["sender_role"],
        "email": row["sender_email"],
        "sender_email": row["sender_email"],
        "content": row["content"],
        "original_content": row["original_content"],
        "filtered": bool(row["filtered"]),
        "status": row["status"],
        "created_at": row["created_at"],
    }


def make_token(db, email):
    token = secrets.token_hex(24)
    now = now_dt()
    db.execute(
        "INSERT INTO tokens(token,email,created_at,expires_at) VALUES(?,?,?,?)",
        (token, email, now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
         (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+08:00")))
    return token


def touch_last_seen(db, email):
    db.execute("UPDATE users SET last_seen=? WHERE email=?",
               (now_str(), email))


def are_friends(db, a, b):
    return db.execute(
        "SELECT 1 FROM friends WHERE user_email=? AND friend_email=?",
        (a, b)).fetchone() is not None


def filter_badwords(db, text):
    """违禁词过滤：命中词替换为等长 * ，并返回 (过滤后文本, 是否命中)。"""
    words = [r["word"] for r in db.execute("SELECT word FROM bad_words")]
    hit = False
    for w in words:
        if not w:
            continue
        pat = re.compile(re.escape(w), re.IGNORECASE if w.isascii() else 0)
        if pat.search(text):
            hit = True
            text = pat.sub("*" * len(w), text)
    return text, hit


class ApiError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@app.errorhandler(ApiError)
def _api_error(e):
    return err(e.code, str(e))


@app.errorhandler(404)
def _not_found(_e):
    return err(404, "接口不存在")


@app.errorhandler(Exception)
def _internal_error(e):
    app.logger.exception(e)
    return err(-1, "服务器内部错误")


# --------------------------------------------------------------------------
# 3. 邮件发送（QQ 邮箱 SMTP；未配置或 CCR_FAKE_SMTP=1 时进入联调模式）
# --------------------------------------------------------------------------
def send_mail(receiver, subject, text):
    if FAKE_SMTP or not MAIL_USER or not MAIL_PASS:
        return False
    msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = formataddr((str(Header("畅聊ChatRoom", "utf-8")), MAIL_USER))
    msg["To"] = receiver
    server = None
    try:
        if MAIL_USE_SSL:
            server = smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT, timeout=20)
        else:
            server = smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=20)
            server.starttls()
        server.login(MAIL_USER, MAIL_PASS)
        server.sendmail(MAIL_USER, [receiver], msg.as_string())
        return True
    except Exception:
        return False
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


# --------------------------------------------------------------------------
# 4. 认证接口
# --------------------------------------------------------------------------
@app.route("/api/send_code", methods=["POST"])
def api_send_code():
    email = str(json_body().get("email") or "").strip().lower()
    if not is_qq_email(email):
        raise ApiError(1, "仅支持纯 QQ 邮箱（格式：xxx@qq.com）")
    db = get_db()
    last = db.execute(
        "SELECT created_at FROM verify_codes WHERE email=? ORDER BY id DESC LIMIT 1",
        (email,)).fetchone()
    if last and ts_age(last["created_at"]) < SEND_CODE_INTERVAL:
        left = int(SEND_CODE_INTERVAL - ts_age(last["created_at"]))
        raise ApiError(1, "获取过于频繁，请 %d 秒后再试" % left)
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    now = now_dt()
    db.execute(
        "INSERT INTO verify_codes(email,code,created_at,expires_at,used) VALUES(?,?,?,?,0)",
        (email, code, now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
         (now + timedelta(seconds=VERIFY_CODE_TTL)).strftime("%Y-%m-%dT%H:%M:%S+08:00")))
    db.commit()

    sent = send_mail(
        email, "畅聊ChatRoom 注册验证码",
        "你的注册验证码是：%s\n验证码 5 分钟内有效，请勿泄露给他人。" % code)
    if sent:
        # 真实发送成功：验证码只发到邮箱，不返回给客户端
        return ok(msg="验证码已发送到邮箱，请查收（5 分钟内有效）")
    # 发送失败（如 PythonAnywhere 免费版禁止 SMTP 出站）：兜底回填 code_val，客户端自动填入
    return ok(code_val=code, msg="邮件发送失败（服务器限制），验证码：" + code + "（5 分钟内有效，请直接输入）")


@app.route("/api/register", methods=["POST"])
def api_register():
    email = str(json_body().get("email") or "").strip().lower()
    password = str(json_body().get("password") or "")
    code = str(json_body().get("code") or "").strip()
    if not is_qq_email(email):
        raise ApiError(1, "仅支持纯 QQ 邮箱注册（格式：xxx@qq.com）")
    if len(password) < 6:
        raise ApiError(1, "密码至少需要 6 个字符")
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        raise ApiError(1, "该邮箱已注册，请直接登录")
    if code:
        vc = db.execute(
            "SELECT * FROM verify_codes WHERE email=? AND code=? AND used=0 "
            "AND expires_at>? ORDER BY id DESC LIMIT 1",
            (email, code, now_str())).fetchone()
        if vc is None:
            raise ApiError(1, "验证码错误或已过期")
        db.execute("UPDATE verify_codes SET used=1 WHERE id=?", (vc["id"],))
    elif REQUIRE_VERIFY_CODE:
        raise ApiError(1, "请先点击获取验证码")
    qq = local_part(email)
    nickname = "QQ" + qq
    role = "admin" if email == ADMIN_EMAIL else "user"
    db.execute(
        "INSERT INTO users(email,password_hash,nickname,qq,role,status,created_at,last_seen,delete_requested_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (email, generate_password_hash(password), nickname, qq, role,
         "active", now_str(), now_str(), ""))
    db.commit()
    return ok(email=email)


@app.route("/api/login", methods=["POST"])
def api_login():
    email = str(json_body().get("email") or "").strip().lower()
    password = str(json_body().get("password") or "")
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u is None or not check_password_hash(u["password_hash"], password):
        raise ApiError(1, "邮箱或密码错误")
    if u["status"] == "approved":
        raise ApiError(1, "账号已注销，无法登录")
    token = make_token(db, email)
    touch_last_seen(db, email)
    db.commit()
    # del_status 字段与「注册验证码版」APK 契约一致
    del_status = {"active": "active", "pending": "pending",
                  "approved": "agreed", "rejected": "rejected"}.get(u["status"], u["status"])
    return ok(token=token, email=email, nickname=u["nickname"],
              role=u["role"], qq=u["qq"], status=u["status"], del_status=del_status)


# --------------------------------------------------------------------------
# 5. 公共聊聊天接口
# --------------------------------------------------------------------------
@app.route("/api/send_message", methods=["POST"])
def api_send_message():
    u = require_user()
    content = str(json_body().get("content") or "")
    if not content.strip():
        raise ApiError(1, "消息内容不能为空")
    if len(content) > MAX_MSG_LEN:
        raise ApiError(1, "消息长度不能超过 1000 字")
    db = get_db()
    filtered_text, hit = filter_badwords(db, content)
    cur = db.execute(
        "INSERT INTO messages(sender_email,sender_name,sender_role,content,"
        "original_content,filtered,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (u["email"], u["nickname"], u["role"], filtered_text, content,
         1 if hit else 0, "normal", now_str()))
    db.commit()
    row = db.execute(
        "SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    return ok(data=msg_json(row, u["email"]))


@app.route("/api/messages", methods=["GET"])
def api_messages():
    u = require_user()
    try:
        after_id = int(request.args.get("after_id") or 0)
    except ValueError:
        after_id = 0
    db = get_db()
    rows = db.execute(
        "SELECT * FROM messages WHERE id>? ORDER BY id ASC LIMIT 200",
        (after_id,)).fetchall()
    data = [msg_json(r, u["email"]) for r in rows]
    touch_last_seen(db, u["email"])
    db.commit()
    return ok(data=data)


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    u = require_user()
    db = get_db()
    touch_last_seen(db, u["email"])
    db.commit()
    members = []
    for row in db.execute(
            "SELECT email,nickname,role,last_seen FROM users WHERE last_seen!=''"):
        if is_online(row["last_seen"]):
            members.append({"kind": row["role"], "name": row["nickname"],
                            "email": row["email"]})
    total = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    return ok(members=members, online_count=len(members),
              offline_count=total - len(members))


@app.route("/api/recall_message", methods=["POST"])
def api_recall_message():
    u = require_user()
    try:
        mid = int(json_body().get("message_id") or 0)
    except ValueError:
        mid = 0
    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if row is None:
        raise ApiError(1, "消息不存在")
    if row["sender_email"] != u["email"]:
        raise ApiError(1, "只能撤回自己的消息")
    if row["status"] == "recalled":
        raise ApiError(1, "消息已被撤回")
    if ts_age(row["created_at"]) > RECALL_WINDOW:
        raise ApiError(1, "消息已超过撤回时限")
    db.execute("UPDATE messages SET status='recalled' WHERE id=?", (mid,))
    db.commit()
    return ok(id=mid)


# --------------------------------------------------------------------------
# 6. 好友接口
# --------------------------------------------------------------------------
@app.route("/api/search_user", methods=["GET"])
def api_search_user():
    u = require_user()
    q = str(request.args.get("qq") or "").strip()
    if not q:
        raise ApiError(1, "请输入 QQ 号")
    db = get_db()
    if "@" in q:
        target = db.execute("SELECT * FROM users WHERE email=?",
                            (q.lower(),)).fetchone()
    else:
        target = db.execute("SELECT * FROM users WHERE qq=? COLLATE NOCASE",
                            (q,)).fetchone()
    if target is None or target["status"] == "approved":
        raise ApiError(1, "未找到该 QQ 用户")
    is_friend = are_friends(db, u["email"], target["email"])
    pending_sent = db.execute(
        "SELECT 1 FROM friend_requests WHERE from_email=? AND to_email=? AND status='pending'",
        (u["email"], target["email"])).fetchone() is not None
    pending_incoming = db.execute(
        "SELECT 1 FROM friend_requests WHERE from_email=? AND to_email=? AND status='pending'",
        (target["email"], u["email"])).fetchone() is not None
    data = user_public(target)
    data.update({"is_friend": is_friend,
                 "pending_sent": pending_sent,
                 "pending_incoming": pending_incoming})
    return ok(data=data)


@app.route("/api/friend_request", methods=["POST"])
def api_friend_request():
    u = require_user()
    to_email = str(json_body().get("to_email") or "").strip().lower()
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE email=?",
                        (to_email,)).fetchone()
    if target is None or target["status"] == "approved":
        raise ApiError(1, "对方不存在或账号已注销")
    if to_email == u["email"]:
        raise ApiError(1, "不能添加自己为好友")
    if are_friends(db, u["email"], to_email):
        raise ApiError(1, "你们已经是好友了")
    if db.execute(
            "SELECT 1 FROM friend_requests WHERE from_email=? AND to_email=? AND status='pending'",
            (u["email"], to_email)).fetchone():
        raise ApiError(1, "已发送过申请，请等待对方处理")
    if db.execute(
            "SELECT 1 FROM friend_requests WHERE from_email=? AND to_email=? AND status='pending'",
            (to_email, u["email"])).fetchone():
        raise ApiError(1, "对方已向你发送申请，请先处理")
    db.execute(
        "INSERT INTO friend_requests(from_email,from_nickname,to_email,status,created_at) "
        "VALUES(?,?,?,?,?)",
        (u["email"], u["nickname"], to_email, "pending", now_str()))
    db.commit()
    return ok()


@app.route("/api/friend_requests", methods=["GET"])
def api_friend_requests():
    u = require_user()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM friend_requests WHERE to_email=? AND status='pending' "
        "ORDER BY id DESC", (u["email"],)).fetchall()
    data = [{"id": r["id"], "from_email": r["from_email"],
             "from_nickname": r["from_nickname"], "created_at": r["created_at"],
             "status": r["status"]} for r in rows]
    return ok(data=data)


@app.route("/api/friend_handle", methods=["POST"])
def api_friend_handle():
    u = require_user()
    body = json_body()
    try:
        rid = int(body.get("request_id") or 0)
    except ValueError:
        rid = 0
    action = str(body.get("action") or "")
    db = get_db()
    req_row = db.execute(
        "SELECT * FROM friend_requests WHERE id=? AND to_email=?",
        (rid, u["email"])).fetchone()
    if req_row is None:
        raise ApiError(1, "好友申请不存在")
    if req_row["status"] != "pending":
        raise ApiError(1, "该申请已处理")
    if action == "accept":
        db.execute("UPDATE friend_requests SET status='accepted' WHERE id=?",
                   (rid,))
        now = now_str()
        db.execute("INSERT OR IGNORE INTO friends(user_email,friend_email,created_at) VALUES(?,?,?)",
                   (u["email"], req_row["from_email"], now))
        db.execute("INSERT OR IGNORE INTO friends(user_email,friend_email,created_at) VALUES(?,?,?)",
                   (req_row["from_email"], u["email"], now))
    elif action == "reject":
        db.execute("UPDATE friend_requests SET status='rejected' WHERE id=?",
                   (rid,))
    else:
        raise ApiError(1, "无效操作")
    db.commit()
    return ok()


@app.route("/api/friends", methods=["GET"])
def api_friends():
    u = require_user()
    db = get_db()
    rows = db.execute(
        "SELECT u.* FROM friends f JOIN users u ON u.email=f.friend_email "
        "WHERE f.user_email=? ORDER BY u.nickname COLLATE NOCASE",
        (u["email"],)).fetchall()
    data = [user_public(r) for r in rows if r["status"] != "approved"]
    return ok(data=data)


@app.route("/api/del_friend", methods=["POST"])
def api_del_friend():
    u = require_user()
    peer = str(json_body().get("peer_email") or "").strip().lower()
    db = get_db()
    db.execute("DELETE FROM friends WHERE user_email=? AND friend_email=?",
               (u["email"], peer))
    db.execute("DELETE FROM friends WHERE user_email=? AND friend_email=?",
               (peer, u["email"]))
    db.commit()
    return ok()


# --------------------------------------------------------------------------
# 7. 私聊接口
# --------------------------------------------------------------------------
@app.route("/api/send_private", methods=["POST"])
def api_send_private():
    u = require_user()
    body = json_body()
    peer = str(body.get("to_email") or "").strip().lower()
    content = str(body.get("content") or "")
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE email=?",
                        (peer,)).fetchone()
    if target is None or target["status"] == "approved":
        raise ApiError(1, "对方不存在或账号已注销")
    if not are_friends(db, u["email"], peer):
        raise ApiError(1, "你们还不是好友，无法私聊")
    if not content.strip():
        raise ApiError(1, "消息内容不能为空")
    if len(content) > MAX_MSG_LEN:
        raise ApiError(1, "消息长度不能超过 1000 字")
    filtered_text, hit = filter_badwords(db, content)
    cur = db.execute(
        "INSERT INTO private_messages(sender_email,sender_name,sender_role,receiver_email,"
        "content,original_content,filtered,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (u["email"], u["nickname"], u["role"], peer, filtered_text, content,
         1 if hit else 0, "normal", now_str()))
    db.commit()
    row = db.execute(
        "SELECT * FROM private_messages WHERE id=?", (cur.lastrowid,)).fetchone()
    return ok(data=msg_json(row, u["email"]))


@app.route("/api/private_messages", methods=["GET"])
def api_private_messages():
    u = require_user()
    peer = str(request.args.get("peer_email") or "").strip().lower()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM private_messages WHERE "
        "(sender_email=? AND receiver_email=?) OR (sender_email=? AND receiver_email=?) "
        "ORDER BY id ASC",
        (u["email"], peer, peer, u["email"])).fetchall()
    data = [msg_json(r, u["email"]) for r in rows]
    return ok(messages=data)


@app.route("/api/recall_private", methods=["POST"])
def api_recall_private():
    u = require_user()
    try:
        mid = int(json_body().get("message_id") or 0)
    except ValueError:
        mid = 0
    db = get_db()
    row = db.execute("SELECT * FROM private_messages WHERE id=?", (mid,)).fetchone()
    if row is None:
        raise ApiError(1, "消息不存在")
    if row["sender_email"] != u["email"]:
        raise ApiError(1, "只能撤回自己的消息")
    if row["status"] == "recalled":
        raise ApiError(1, "消息已被撤回")
    if ts_age(row["created_at"]) > RECALL_WINDOW:
        raise ApiError(1, "消息已超过撤回时限")
    db.execute("UPDATE private_messages SET status='recalled' WHERE id=?", (mid,))
    db.commit()
    return ok(id=mid)


@app.route("/api/conversations", methods=["GET"])
def api_conversations():
    u = require_user()
    db = get_db()
    rows = db.execute(
        "SELECT p.peer, p.last_id, u.nickname AS peer_nickname, pm.content AS last_content "
        "FROM ("
        "  SELECT CASE WHEN sender_email=? THEN receiver_email ELSE sender_email END AS peer,"
        "         MAX(id) AS last_id"
        "  FROM private_messages WHERE sender_email=? OR receiver_email=?"
        "  GROUP BY peer"
        ") p "
        "JOIN private_messages pm ON pm.id=p.last_id "
        "LEFT JOIN users u ON u.email=p.peer "
        "ORDER BY p.last_id DESC",
        (u["email"], u["email"], u["email"])).fetchall()
    data = [{
        "peer_email": r["peer"],
        "peer_nickname": r["peer_nickname"] or local_part(r["peer"]),
        "last_content": r["last_content"] or "",
    } for r in rows]
    return ok(data=data)


# --------------------------------------------------------------------------
# 8. 账号注销接口
# --------------------------------------------------------------------------
def delete_message_by_status(status):
    return {
        "active": "",
        "pending": "注销申请已提交，等待管理员审核",
        "approved": "注销申请已通过，账号不可再登录",
        "rejected": "注销申请被驳回，账号仍可正常使用",
    }.get(status, "")


@app.route("/api/delete_request", methods=["POST"])
def api_delete_request():
    u = require_user()
    db = get_db()
    if u["status"] == "pending":
        raise ApiError(1, "已提交注销申请，请等待审核")
    if u["status"] == "approved":
        raise ApiError(1, "账号已注销")
    db.execute(
        "UPDATE users SET status='pending', delete_requested_at=? WHERE email=?",
        (now_str(), u["email"]))
    db.commit()
    return ok()


@app.route("/api/delete_status", methods=["GET"])
def api_delete_status():
    u = require_user()
    return ok(status=u["status"], msg=delete_message_by_status(u["status"]))


@app.route("/api/cancel_delete", methods=["POST"])
def api_cancel_delete():
    u = require_user()
    db = get_db()
    if u["status"] != "pending":
        raise ApiError(1, "当前没有待处理的注销申请")
    db.execute(
        "UPDATE users SET status='active', delete_requested_at='' WHERE email=?",
        (u["email"],))
    db.commit()
    return ok()


# --------------------------------------------------------------------------
# 9. 管理后台接口
# --------------------------------------------------------------------------
@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    require_admin()
    db = get_db()
    today = now_dt().strftime("%Y-%m-%d")
    total_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    today_users = db.execute(
        "SELECT COUNT(*) c FROM users WHERE substr(created_at,1,10)=?",
        (today,)).fetchone()["c"]
    total_messages = db.execute(
        "SELECT COUNT(*) c FROM messages").fetchone()["c"]
    filtered_messages = db.execute(
        "SELECT COUNT(*) c FROM messages WHERE filtered=1").fetchone()["c"]
    private_messages = db.execute(
        "SELECT COUNT(*) c FROM private_messages").fetchone()["c"]
    private_chats = db.execute(
        "SELECT COUNT(DISTINCT "
        "CASE WHEN sender_email<receiver_email THEN sender_email||'|'||receiver_email "
        "ELSE receiver_email||'|'||sender_email END) c FROM private_messages"
    ).fetchone()["c"]
    bad_words = db.execute("SELECT COUNT(*) c FROM bad_words").fetchone()["c"]
    online_users = 0
    for row in db.execute("SELECT last_seen FROM users WHERE last_seen!=''"):
        if is_online(row["last_seen"]):
            online_users += 1
    pending_deletes = db.execute(
        "SELECT COUNT(*) c FROM users WHERE status='pending'").fetchone()["c"]
    return ok(data={
        "total_users": total_users,
        "today_users": today_users,
        "total_messages": total_messages,
        "filtered_messages": filtered_messages,
        "private_chats": private_chats,
        "private_messages": private_messages,
        "bad_words": bad_words,
        "online_users": online_users,
        "offline_users": total_users - online_users,
        "pending_deletes": pending_deletes,
    })


@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    require_admin()
    db = get_db()
    rows = db.execute(
        "SELECT u.*, "
        " (SELECT COUNT(*) FROM messages m WHERE m.sender_email=u.email) + "
        " (SELECT COUNT(*) FROM private_messages pm WHERE pm.sender_email=u.email) AS msg_count "
        "FROM users u ORDER BY u.id DESC").fetchall()
    data = [{
        "id": r["id"],
        "email": r["email"],
        "nickname": r["nickname"],
        "created_at": r["created_at"],
        "msg_count": r["msg_count"],
        "last_seen": r["last_seen"],
    } for r in rows]
    return ok(data=data)


@app.route("/api/admin/user/<int:uid>", methods=["DELETE"])
def admin_delete_user(uid):
    require_admin()
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if row is None:
        raise ApiError(1, "用户不存在")
    email = row["email"]
    db.execute("DELETE FROM tokens WHERE email=?", (email,))
    db.execute("DELETE FROM friends WHERE user_email=? OR friend_email=?",
               (email, email))
    db.execute("DELETE FROM friend_requests WHERE from_email=? OR to_email=?",
               (email, email))
    db.execute("DELETE FROM verify_codes WHERE email=?", (email,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    return ok()


@app.route("/api/admin/messages", methods=["GET"])
def admin_messages():
    require_admin()
    db = get_db()
    keyword = str(request.args.get("keyword") or "").strip()
    email = str(request.args.get("email") or "").strip().lower()
    status = str(request.args.get("status") or "").strip()
    sql = ("SELECT * FROM messages WHERE 1=1")
    args = []
    if keyword:
        sql += " AND content LIKE ?"
        args.append("%" + keyword + "%")
    if email:
        sql += " AND sender_email=?"
        args.append(email)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY id DESC LIMIT 500"
    rows = db.execute(sql, args).fetchall()
    return ok(data=[record_json(r) for r in rows])


@app.route("/api/admin/private_messages", methods=["GET"])
def admin_private_messages():
    require_admin()
    db = get_db()
    email = str(request.args.get("email") or "").strip().lower()
    if email:
        rows = db.execute(
            "SELECT * FROM private_messages WHERE sender_email=? OR receiver_email=? "
            "ORDER BY id DESC LIMIT 500", (email, email)).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM private_messages ORDER BY id DESC LIMIT 500").fetchall()
    return ok(data=[record_json(r) for r in rows])


@app.route("/api/admin/recall", methods=["POST"])
def admin_recall():
    require_admin()
    try:
        mid = int(json_body().get("message_id") or 0)
    except ValueError:
        mid = 0
    db = get_db()
    if db.execute("SELECT 1 FROM messages WHERE id=?", (mid,)).fetchone() is None:
        raise ApiError(1, "消息不存在")
    db.execute("UPDATE messages SET status='recalled' WHERE id=?", (mid,))
    db.commit()
    return ok()


@app.route("/api/admin/recall_private", methods=["POST"])
def admin_recall_private():
    require_admin()
    try:
        mid = int(json_body().get("message_id") or 0)
    except ValueError:
        mid = 0
    db = get_db()
    if db.execute("SELECT 1 FROM private_messages WHERE id=?",
                  (mid,)).fetchone() is None:
        raise ApiError(1, "消息不存在")
    db.execute("UPDATE private_messages SET status='recalled' WHERE id=?", (mid,))
    db.commit()
    return ok()


@app.route("/api/admin/features", methods=["GET"])
def admin_features():
    require_admin()
    db = get_db()
    rows = db.execute("SELECT * FROM features ORDER BY id DESC").fetchall()
    return ok(data=[{"id": r["id"], "name": r["name"],
                     "action": r["action"]} for r in rows])


@app.route("/api/admin/features", methods=["POST"])
def admin_add_feature():
    require_admin()
    body = json_body()
    name = str(body.get("name") or "").strip()
    action = str(body.get("action") or "").strip()
    if not name or not action:
        raise ApiError(1, "名称与动作不能为空")
    db = get_db()
    db.execute("INSERT INTO features(name,action) VALUES(?,?)", (name, action))
    db.commit()
    return ok()


@app.route("/api/admin/features/<int:fid>", methods=["DELETE"])
def admin_del_feature(fid):
    require_admin()
    db = get_db()
    db.execute("DELETE FROM features WHERE id=?", (fid,))
    db.commit()
    return ok()


@app.route("/api/admin/bad_words", methods=["GET"])
def admin_bad_words():
    require_admin()
    db = get_db()
    rows = db.execute("SELECT * FROM bad_words ORDER BY id DESC").fetchall()
    return ok(data=[{"id": r["id"], "word": r["word"]} for r in rows])


@app.route("/api/admin/bad_words", methods=["POST"])
def admin_add_bad_word():
    require_admin()
    word = str(json_body().get("word") or "").strip()
    if not word:
        raise ApiError(1, "违禁词不能为空")
    db = get_db()
    db.execute("INSERT OR IGNORE INTO bad_words(word) VALUES(?)", (word,))
    db.commit()
    return ok()


@app.route("/api/admin/bad_words/<int:wid>", methods=["DELETE"])
def admin_del_bad_word(wid):
    require_admin()
    db = get_db()
    db.execute("DELETE FROM bad_words WHERE id=?", (wid,))
    db.commit()
    return ok()


@app.route("/api/admin/delete_requests", methods=["GET"])
def admin_delete_requests():
    require_admin()
    db = get_db()
    rows = db.execute(
        "SELECT id,email,qq,nickname,status,delete_requested_at "
        "FROM users WHERE status!='active' ORDER BY delete_requested_at DESC"
    ).fetchall()
    data = [{
        "id": r["id"],
        "email": r["email"],
        "qq": r["qq"],
        "nickname": r["nickname"],
        "status": r["status"],
        "requested_at": r["delete_requested_at"],
    } for r in rows]
    return ok(data=data)


@app.route("/api/admin/delete_decide", methods=["POST"])
def admin_delete_decide():
    require_admin()
    body = json_body()
    email = str(body.get("email") or "").strip().lower()
    action = str(body.get("action") or "")
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u is None:
        raise ApiError(1, "用户不存在")
    if u["status"] != "pending":
        raise ApiError(1, "该用户当前没有待处理的注销申请")
    if action == "approve":
        db.execute("UPDATE users SET status='approved' WHERE email=?", (email,))
        # 保留 token：鉴权层会对已注销账号统一返回 401「账号已注销」，
        # 客户端据此强制下线，提示比直接删 token 更明确
    elif action == "reject":
        db.execute("UPDATE users SET status='rejected', delete_requested_at='' "
                   "WHERE email=?", (email,))
    else:
        raise ApiError(1, "无效操作")
    db.commit()
    return ok()


# --------------------------------------------------------------------------
# 10. 启动入口
# --------------------------------------------------------------------------
ensure_db()  # 模块导入时即建表：无论 WSGI 还是直接运行都能初始化

if __name__ == "__main__":
    print("畅聊ChatRoom 后端启动 (PORT=" + os.environ.get("PORT", "8000") + ")")
    print("数据库:", DB_PATH)
    print("管理员邮箱:", ADMIN_EMAIL)
    print("邮件模式:", "真实发送(QQ SMTP)" if (MAIL_USER and MAIL_PASS and not FAKE_SMTP)
          else ("联调模式(不真实发信, 验证码回填)" if FAKE_SMTP else "联调模式(未配置邮箱凭据, 验证码回填)"))
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False, threaded=True)