# app/account_routes.py
# Account routes (simple comments)
# - account page
# - 2FA (enable/confirm/disable/regenerate)
# - change password
# - recovery codes (show once)
# - game token + API verify

from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify, current_app
from .models import (
    set_totp_secret, find_user_by_id, find_user_by_email, replace_password,
    delete_recovery_codes, insert_recovery_codes, count_recovery_codes
)
from .twofa import new_totp_secret, qr_data_url, verify_totp, encrypt_secret
from .security import issue_game_token, decode_jwt, verify_pw
import secrets, string

# one blueprint for account stuff
account_bp = Blueprint('account_bp', __name__)

# quick check: logged in?
def _require_login():
    return 'user_id' in session


# home page
@account_bp.route('/')
def index():
    return render_template('index.html')


# account page (needs login)
@account_bp.route('/account', methods=['GET'])
def account():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    user = find_user_by_id(session['user_id'])
    qr = session.get('pending_qr')                 # QR only when setting up 2FA
    available = count_recovery_codes(user['id'])   # number of stored recovery codes
    pending = bool(session.get('pending_totp_secret'))

    return render_template('account.html', user=user, qr=qr, available=available, pending_2fa=pending)


# 2FA (TOTP)
# start 2FA: create secret + QR (pending)
@account_bp.route('/account/2fa/enable', methods=['POST'])
def enable_2fa():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    user = find_user_by_id(session['user_id'])
    secret, uri = new_totp_secret('YourApp', user['email'])

    session['pending_totp_secret'] = secret        # keep secret until confirm
    session['pending_qr'] = qr_data_url(uri)       # show QR on account page

    flash('Two-factor is now pending. Confirm it in your authenticator app.', 'info')
    return redirect(url_for('account_bp.account'))


# confirm 2FA with code from app
@account_bp.route('/account/2fa/confirm', methods=['POST'])
def confirm_2fa():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    code = (request.form.get('token') or '').strip()
    secret = session.get('pending_totp_secret')
    if not secret:
        flash('No pending 2FA. Enable it again.', 'error')
        return redirect(url_for('account_bp.account'))

    if verify_totp(secret, code):
        set_totp_secret(session['user_id'], encrypt_secret(secret))  # save encrypted
        session.pop('pending_totp_secret', None)
        session.pop('pending_qr', None)
        flash('2FA confirmed!', 'success')
    else:
        flash('Wrong code. Try again.', 'error')

    return redirect(url_for('account_bp.account'))


# turn off 2FA
@account_bp.route('/account/2fa/disable', methods=['POST'])
def disable_2fa():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    set_totp_secret(session['user_id'], None)
    session.pop('pending_totp_secret', None)
    session.pop('pending_qr', None)
    flash('2FA disabled.', 'success')
    return redirect(url_for('account_bp.account'))


# new secret + QR (must confirm again)
@account_bp.route('/account/2fa/regenerate', methods=['POST'])
def regenerate_2fa():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    user = find_user_by_id(session['user_id'])
    secret, uri = new_totp_secret('YourApp', user['email'])
    session['pending_totp_secret'] = secret
    session['pending_qr'] = qr_data_url(uri)

    flash('New 2FA secret generated. Confirm it again.', 'success')
    return redirect(url_for('account_bp.account'))


# change password
@account_bp.route('/account/password', methods=['POST'])
def change_password():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    user = find_user_by_id(session['user_id'])
    curr = request.form.get('current_password') or ''
    new  = request.form.get('new_password') or ''
    new2 = request.form.get('confirm_password') or ''

    if not verify_pw(user['password_hash'], curr):
        flash('Current password is wrong.', 'error')
        return redirect(url_for('account_bp.account'))

    if len(new) < 8 or new != new2:
        flash('New password must be >= 8 chars and match.', 'error')
        return redirect(url_for('account_bp.account'))

    from .security import hash_pw as _h
    replace_password(user['id'], _h(new))
    flash('Password updated.', 'success')
    return redirect(url_for('account_bp.account'))


# recovery codes
# make N codes like ABC123

def _generate_codes(n=10, length=10):
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]


# create + store hashed codes, show once
@account_bp.route('/account/recovery-codes', methods=['POST'])
def recovery_codes():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    user = find_user_by_id(session['user_id'])
    codes = _generate_codes()

    from .security import hash_pw as _h
    delete_recovery_codes(user['id'])
    insert_recovery_codes(user['id'], [_h(c) for c in codes])

    flash('New recovery codes generated. Save them now (shown once).', 'success')

    qr = session.get('pending_qr')
    available = len(codes)
    return render_template('account.html', user=user, qr=qr, available=available, codes=codes, pending_2fa=bool(session.get('pending_totp_secret')))


# game page + token
@account_bp.route('/game', methods=['GET'])
def game_page():
    if not _require_login():
        return redirect(url_for('auth_bp.login'))

    prefill = session.pop('last_game_jwt', None)
    return render_template('game_token.html', prefill=prefill)


@account_bp.route('/account/game-token', methods=['POST'])
def account_game_token():
    if not _require_login():
        return jsonify({"ok": False, "error": "not_authenticated"}), 401

    user = find_user_by_id(session['user_id'])
    token = issue_game_token(user['id'], user['email'])
    return jsonify({"ok": True, "token": token})


# verify TOTP or JWT
@account_bp.route('/api/verify-token', methods=['POST'])
def api_verify_token():
    # read API key from headers (many common names)
    def _extract_api_key():
        h = request.headers
        for k in ('api_key','apiKey','API_KEY','x-api-key','X-API-Key','X-Api-Key'):
            if k in h:
                return h.get(k)
        auth = h.get('Authorization','')
        if auth.startswith('Bearer '):
            return auth.split(' ',1)[1]
        return ''

    api_key = _extract_api_key()
    expected = (current_app.config.get('GAME_PLUGIN_API_KEY')
                or current_app.config.get('API_KEY')
                or 'CHANGE_ME')

    if not expected or expected == 'CHANGE_ME' or api_key != expected:
        return jsonify({"ok": False, "error": "forbidden", "valid": False}), 403

    data = request.get_json(silent=True) or {}
    token = (data.get('token') or '').strip()
    email = (data.get('email') or '').strip().lower()

    # if looks like TOTP (6–8 digits)
    if token.isdigit() and 6 <= len(token) <= 8:
        if not email:
            return jsonify({"ok": False, "error":"email_required_for_totp", "valid": False}), 400
        user = find_user_by_email(email)
        if not user or not user['totp_secret']:
            return jsonify({"ok": False, "error":"user_not_found_or_2fa_off", "valid": False}), 400
        if verify_totp(user['totp_secret'], token):
            return jsonify({"ok": True, "mode":"totp", "email": user['email'], "user_id": int(user['id']), "valid": True})
        return jsonify({"ok": False, "error":"invalid_code", "valid": False}), 401

    # else try JWT
    claims = decode_jwt(token)
    if not claims:
        return jsonify({"ok": False, "error": "invalid_token", "valid": False}), 400

    user_id = claims.get('user_id') or claims.get('sub')
    return jsonify({"ok": True, "mode":"jwt", "email": claims.get('email'), "user_id": int(user_id), "valid": True})
