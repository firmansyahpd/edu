"""EduTask: FastAPI + SQLite, tanpa dependensi frontend build.
Jalankan: uvicorn app:app --reload --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Form, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR', str(ROOT))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / 'edutask.db'
UPLOAD_DIR = DATA_DIR / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = 25
MAX_UPLOAD = MAX_UPLOAD_MB * 1024 * 1024
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
SESSION_AGE = 7 * 24 * 60 * 60
EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.png', '.jpg', '.jpeg', '.txt'}

app = FastAPI(title='EduTask', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().isoformat()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000)
    return f'pbkdf2_sha256$260000${salt.hex()}${dk.hex()}'


def password_verify(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, expected = stored.split('$')
        if algo != 'pbkdf2_sha256':
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def init_db():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','student')),
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL, subject TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '', due_at TEXT NOT NULL,
          created_at TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          stored_file TEXT NOT NULL, original_name TEXT NOT NULL,
          file_size INTEGER NOT NULL, submitted_at TEXT NOT NULL,
          feedback TEXT NOT NULL DEFAULT '', review_status TEXT NOT NULL DEFAULT 'submitted'
            CHECK(review_status IN ('submitted','revision','accepted'))
        );
        CREATE INDEX IF NOT EXISTS idx_submissions_task_user ON submissions(task_id,user_id,id DESC);
        ''')
        email = os.getenv('ADMIN_EMAIL', 'admin@edutask.local').strip().lower()
        pw = os.getenv('ADMIN_PASSWORD', 'GantiPasswordAdmin123!')
        if not conn.execute('SELECT id FROM users WHERE role = ?', ('admin',)).fetchone():
            conn.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                         ('Administrator', email, password_hash(pw), 'admin', iso_now()))


init_db()


@app.get('/health')
def health():
    return {'ok': True}


class AuthIn(BaseModel):
    email: str
    password: str


class RegisterIn(AuthIn):
    name: str


class TaskIn(BaseModel):
    title: str = Field(min_length=3, max_length=150)
    subject: str = Field(min_length=2, max_length=100)
    description: str = Field(default='', max_length=3000)
    due_at: str


class FeedbackIn(BaseModel):
    feedback: str = Field(min_length=2, max_length=3000)
    review_status: str


# Rate limit sederhana per IP untuk login lokal; untuk skala besar gunakan Redis/reverse proxy.
LOGIN_ATTEMPTS = {}


def auth_user(request: Request):
    token = request.cookies.get('edutask_session')
    if not token:
        raise HTTPException(401, 'Silakan login terlebih dahulu.')
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute('''SELECT u.id,u.name,u.email,u.role,s.csrf FROM sessions s
                             JOIN users u ON u.id=s.user_id
                             WHERE s.token_hash=? AND s.expires_at>?''',
                           (token_hash, int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, 'Sesi berakhir. Silakan login kembali.')
    return dict(row)


def require_csrf(request: Request, user=Depends(auth_user)):
    sent = request.headers.get('X-CSRF-Token', '')
    if not sent or not hmac.compare_digest(sent, user['csrf']):
        raise HTTPException(403, 'Token keamanan tidak valid. Refresh halaman.')
    return user


def admin_only(user=Depends(require_csrf)):
    if user['role'] != 'admin':
        raise HTTPException(403, 'Hanya admin yang dapat melakukan tindakan ini.')
    return user


def set_session(response: Response, user_id: int):
    token = secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    csrf = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute('DELETE FROM sessions WHERE expires_at < ?', (int(time.time()),))
        conn.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',
                     (token_hash, user_id, csrf, int(time.time()) + SESSION_AGE))
    response.set_cookie('edutask_session', token, max_age=SESSION_AGE,
                        httponly=True, secure=COOKIE_SECURE, samesite='lax', path='/')
    return csrf


def valid_email(email: str):
    return bool(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email)) and len(email) <= 254


@app.get('/')
def home():
    return FileResponse(ROOT / 'static' / 'index.html')


@app.post('/api/auth/register', status_code=201)
def register(data: RegisterIn, response: Response):
    name = data.name.strip()
    email = data.email.strip().lower()
    if not (2 <= len(name) <= 80) or not valid_email(email) or len(data.password) < 10:
        raise HTTPException(400, 'Nama 2–80 karakter, email valid, password minimal 10 karakter.')
    with db() as conn:
        try:
            cur = conn.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                               (name, email, password_hash(data.password), 'student', iso_now()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'Email sudah terdaftar.')
        user_id = cur.lastrowid
    csrf = set_session(response, user_id)
    return {'user': {'id': user_id, 'name': name, 'email': email, 'role': 'student'}, 'csrf': csrf}


@app.post('/api/auth/login')
def login(data: AuthIn, response: Response, request: Request):
    ip = request.client.host if request.client else 'unknown'
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 600]
    if len(attempts) >= 12:
        raise HTTPException(429, 'Terlalu banyak percobaan login. Coba lagi dalam 10 menit.')
    email = data.email.strip().lower()
    with db() as conn:
        user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user or not password_verify(data.password, user['password_hash']):
        attempts.append(now)
        LOGIN_ATTEMPTS[ip] = attempts
        raise HTTPException(401, 'Email atau password salah.')
    LOGIN_ATTEMPTS.pop(ip, None)
    csrf = set_session(response, user['id'])
    return {'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}, 'csrf': csrf}


@app.get('/api/auth/me')
def me(user=Depends(auth_user)):
    return {'user': {k: user[k] for k in ('id', 'name', 'email', 'role')}, 'csrf': user['csrf']}


@app.post('/api/auth/logout')
def logout(response: Response, request: Request, user=Depends(require_csrf)):
    token = request.cookies.get('edutask_session')
    with db() as conn:
        conn.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie('edutask_session', path='/')
    return {'ok': True}


def latest_submissions(conn, uid: int):
    rows = conn.execute('''SELECT s.* FROM submissions s
                           JOIN (SELECT task_id,MAX(id) AS max_id FROM submissions
                                 WHERE user_id=? GROUP BY task_id) x ON s.id=x.max_id''', (uid,)).fetchall()
    return {r['task_id']: dict(r) for r in rows}


def get_task_rows(user):
    with db() as conn:
        tasks = [dict(r) for r in conn.execute('SELECT t.*,u.name AS creator_name FROM tasks t JOIN users u ON u.id=t.created_by ORDER BY due_at ASC')]
        subs = latest_submissions(conn, user['id']) if user['role'] == 'student' else {}
        if user['role'] == 'admin':
            totals = {r['task_id']: r['num'] for r in conn.execute('SELECT task_id,COUNT(DISTINCT user_id) AS num FROM submissions GROUP BY task_id')}
            students = conn.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0]
    now = utc_now()
    for t in tasks:
        sub = subs.get(t['id'])
        t['submission'] = {k: sub[k] for k in ('id','original_name','file_size','submitted_at','feedback','review_status')} if sub else None
        if user['role'] == 'admin':
            t['submitted_count'] = totals.get(t['id'], 0)
            t['student_count'] = students
            t['status'] = 'admin'
        else:
            t['status'] = (sub['review_status'] if sub else ('overdue' if datetime.fromisoformat(t['due_at'].replace('Z','+00:00')) < now else 'pending'))
    return tasks


@app.get('/api/tasks')
def tasks(user=Depends(auth_user)):
    return {'tasks': get_task_rows(user)}


@app.post('/api/tasks', status_code=201)
def create_task(data: TaskIn, user=Depends(admin_only)):
    try:
        due = datetime.fromisoformat(data.due_at.replace('Z', '+00:00'))
        if due.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise HTTPException(400, 'Tanggal deadline tidak valid.')
    if due <= utc_now():
        raise HTTPException(400, 'Deadline harus di masa depan.')
    with db() as conn:
        cur = conn.execute('INSERT INTO tasks(title,subject,description,due_at,created_at,created_by) VALUES(?,?,?,?,?,?)',
                           (data.title.strip(), data.subject.strip(), data.description.strip(), due.astimezone(timezone.utc).isoformat(), iso_now(), user['id']))
    return {'id': cur.lastrowid}


@app.delete('/api/tasks/{task_id}')
def delete_task(task_id: int, user=Depends(admin_only)):
    with db() as conn:
        old_files = [r['stored_file'] for r in conn.execute('SELECT stored_file FROM submissions WHERE task_id=?', (task_id,))]
        cur = conn.execute('DELETE FROM tasks WHERE id=?', (task_id,))
    if cur.rowcount == 0:
        raise HTTPException(404, 'Tugas tidak ditemukan.')
    for f in old_files:
        (UPLOAD_DIR / f).unlink(missing_ok=True)
    return {'ok': True}


@app.post('/api/tasks/{task_id}/submit', status_code=201)
async def submit_task(task_id: int, file: UploadFile = File(...), user=Depends(require_csrf)):
    if user['role'] != 'student':
        raise HTTPException(403, 'Pengumpulan hanya untuk peserta.')
    with db() as conn:
        task = conn.execute('SELECT id,due_at FROM tasks WHERE id=?', (task_id,)).fetchone()
    if not task:
        raise HTTPException(404, 'Tugas tidak ditemukan.')
    original = Path((file.filename or 'file').replace('\\', '/')).name[:180]
    ext = Path(original).suffix.lower()
    if ext not in EXTENSIONS:
        raise HTTPException(400, 'Jenis file tidak didukung.')
    # Boleh revisi setelah deadline bila sudah pernah submit; submission pertama ditutup ketika terlambat.
    with db() as conn:
        prev = conn.execute('SELECT id FROM submissions WHERE task_id=? AND user_id=? LIMIT 1', (task_id, user['id'])).fetchone()
    if not prev and datetime.fromisoformat(task['due_at']) < utc_now():
        raise HTTPException(400, 'Deadline sudah berlalu; pengumpulan pertama ditutup.')
    name = f'{uuid.uuid4().hex}{ext}'
    target = UPLOAD_DIR / name
    size = 0
    try:
        with target.open('wb') as handle:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, f'File melebihi batas {MAX_UPLOAD // (1024 * 1024)} MB.')
                handle.write(chunk)
        if size == 0:
            raise HTTPException(400, 'File kosong.')
        with db() as conn:
            cur = conn.execute('INSERT INTO submissions(task_id,user_id,stored_file,original_name,file_size,submitted_at) VALUES(?,?,?,?,?,?)',
                               (task_id, user['id'], name, original, size, iso_now()))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return {'id': cur.lastrowid, 'ok': True}


@app.get('/api/tasks/{task_id}/submissions')
def list_submissions(task_id: int, user=Depends(auth_user)):
    if user['role'] != 'admin':
        raise HTTPException(403, 'Hanya admin.')
    with db() as conn:
        if not conn.execute('SELECT id FROM tasks WHERE id=?', (task_id,)).fetchone():
            raise HTTPException(404, 'Tugas tidak ditemukan.')
        rows = conn.execute('''SELECT s.id,s.task_id,s.original_name,s.file_size,s.submitted_at,
                                     s.feedback,s.review_status,u.name,u.email
                              FROM submissions s JOIN users u ON u.id=s.user_id
                              JOIN (SELECT user_id,MAX(id) AS newest FROM submissions
                                    WHERE task_id=? GROUP BY user_id) x ON x.newest=s.id
                              ORDER BY s.submitted_at DESC''', (task_id,)).fetchall()
    return {'submissions': [dict(r) for r in rows]}


@app.post('/api/submissions/{submission_id}/feedback')
def submit_feedback(submission_id: int, data: FeedbackIn, user=Depends(admin_only)):
    if data.review_status not in ('revision', 'accepted'):
        raise HTTPException(400, 'Status harus revision atau accepted.')
    with db() as conn:
        cur = conn.execute('UPDATE submissions SET feedback=?,review_status=? WHERE id=?',
                           (data.feedback.strip(), data.review_status, submission_id))
    if cur.rowcount == 0:
        raise HTTPException(404, 'Pengumpulan tidak ditemukan.')
    return {'ok': True}


@app.get('/api/submissions/{submission_id}/download')
def download_submission(submission_id: int, user=Depends(auth_user)):
    with db() as conn:
        sub = conn.execute('SELECT * FROM submissions WHERE id=?', (submission_id,)).fetchone()
    if not sub:
        raise HTTPException(404, 'File tidak ditemukan.')
    if user['role'] != 'admin' and sub['user_id'] != user['id']:
        raise HTTPException(403, 'Anda tidak memiliki akses ke file ini.')
    path = UPLOAD_DIR / sub['stored_file']
    if not path.exists():
        raise HTTPException(404, 'File tidak ada di penyimpanan.')
    return FileResponse(path, filename=sub['original_name'], media_type='application/octet-stream')
