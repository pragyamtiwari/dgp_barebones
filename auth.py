from db import get_conn_curs, commit_close
from utils import generate_password_hash
from flask import session, redirect, url_for
from functools import wraps

def authenticate_login(email, password):
    if not email or not password:
        return {
            "status": "400",
            "message": "Insufficient parameters",
            "data": None
            }
    conn, curs = get_conn_curs()
    curs.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = curs.fetchone()
    if not user:
        commit_close(conn, curs)
        return {
            "status": "404",
            "message": "User not found",
            "data": None
            }
    if user["password_hash"] != generate_password_hash(password):
        commit_close(conn, curs)
        return {
            "status": "401",
            "message": "Incorrect password",
            "data": None
            }
    commit_close(conn, curs)
    session["user"] = dict(user)
    return {
        "status": "200",
        "message": "Login successful",
        "data": dict(user)
        }
        
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['user']['is_admin']:
            return f(*args, **kwargs)
        else:
            print("403: User is not an admin.")
            return redirect(url_for('user.dashboard'))
    return wrap

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session:
            return f(*args, **kwargs)
        else:
            print("401: User is not logged in.")
            return redirect(url_for('login'))
    return wrap

