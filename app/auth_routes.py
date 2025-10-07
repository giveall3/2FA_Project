# app/auth_routes.py
# routes for register/login/2FA with simple comments (so it's easy to follow)

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from .security import hash_pw, verify_pw, issue_game_token   # hashing + jwt helper
from .models import (
    find_user_by_email, find_user_by_id,
    create_user, list_recovery_codes, consume_recovery_code,
    log_recovery_code_use  # NEW: write an audit row when a recovery code is used
)  # db helpers
from .rate_limiter import rate_limiter, rate_key_login, rate_key_token  # anti-bruteforce
from .twofa import verify_totp  # check TOTP code
import jwt  # used to catch specific JWT errors when issuing token

auth_bp = Blueprint('auth_bp', __name__)

# register new user
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    # take form values
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    confirm  = request.form.get('confirm') or ''
    # check if all fields are filled
    if not email or not password:
        flash('Email and password are required.', 'error')
        return render_template('register.html'), 400
    # check password length
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return render_template('register.html'), 400
    # check if both passwords match
    if password != confirm:
        flash('Passwords are not the same.', 'error')
        return render_template('register.html'), 400
    # check if account already exists
    if find_user_by_email(email):
        flash('Account with this email already exists.', 'error')
        return render_template('register.html'), 400
    # create new user
    create_user(email, hash_pw(password))
    flash('Account created. Please log in.', 'success')
    return redirect(url_for('auth_bp.login'))

# login user
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    # rate limiting (stop too many tries)
    key = rate_key_login(request, email)
    allowed, retry_after = rate_limiter.allow('login', key, limit=5, window_s=300)
    if not allowed:
        flash(f'Too many attempts. Try again in {retry_after}s.', 'error')
        return render_template('login.html'), 429
    user = find_user_by_email(email)
    # wrong email or password
    if not user or not verify_pw(user['password_hash'], password):
        flash('Invalid email or password.', 'error')
        return render_template('login.html'), 401
    # if 2FA enabled
    if user['totp_secret']:
        session.clear()
        session['2fa_pending_user_id'] = user['id']
        session['2fa_pending_email'] = user['email']
        flash('Enter 2FA app code or recovery code.', 'info')
        return redirect(url_for('auth_bp.token'))
    # normal login without 2FA
    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    rate_limiter.clear('login', key)
    flash('Logged in.', 'success')
    return redirect(url_for('account_bp.index'))

# page where user enters 2FA code
@auth_bp.route('/token', methods=['GET', 'POST'])
def token():
    pending_id = session.get('2fa_pending_user_id')
    if not pending_id:
        flash('2FA session expired.', 'error')
        return redirect(url_for('auth_bp.login'))
    if request.method == 'GET':
        return render_template('token.html')
    code = (request.form.get('token') or '').strip()
    # rate limiting for 2FA attempts
    key = rate_key_token(pending_id)
    allowed, retry_after = rate_limiter.allow('token', key, limit=6, window_s=120)
    if not allowed:
        flash(f'Too many code attempts. Try again in {retry_after}s.', 'error')
        return render_template('token.html'), 429
    user = find_user_by_id(pending_id)
    if not user:
        flash('User does not exist.', 'error')
        return redirect(url_for('auth_bp.login'))
    ok = False
    # check normal TOTP 2FA code
    if user['totp_secret'] and code.isdigit():
        ok = verify_totp(user['totp_secret'], code)
    # check recovery codes if totp failed
    if not ok:
        rows = list_recovery_codes(user['id']) or []
        for row in rows:
            if verify_pw(row['code_hash'], code):
                # NEW: log that a recovery code was used (time/IP/User-Agent)
                ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or request.remote_addr
                ua = request.headers.get("User-Agent", "")
                log_recovery_code_use(user['id'], row['id'], ip, ua)

                # then invalidate the code so it can't be reused
                consume_recovery_code(user['id'], row['id'])
                ok = True
                break
    # if success
    if ok:
        session.clear()
        session['user_id'] = user['id']
        session['email'] = user['email']
        rate_limiter.clear('token', key)
        try:
            session['last_game_jwt'] = issue_game_token(user['id'], user['email'])
        except (KeyError, jwt.PyJWTError, TypeError, ValueError):
            # if JWT secret missing or payload not encodable, just skip issuing the token
            pass
        return redirect(url_for('account_bp.game_page'))
    # if fail
    flash('Invalid 2FA or recovery code.', 'error')
    return render_template('token.html'), 401

# logout user (API endpoint)
@auth_bp.post('/api/session/logout')
def api_logout():
    session.clear()
    return jsonify({'ok': True})
