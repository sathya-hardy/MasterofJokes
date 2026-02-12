"""Authentication blueprint: register, login, logout, and session management."""

import functools
import logging
from re import match

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

logger = logging.getLogger(__name__)

bp = Blueprint('auth', __name__, url_prefix='/auth')

# Email regex: local-part @ domain . tld
EMAIL_REGEX = r'^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+[@]\w+[.]\w+$'


def is_valid_email(email):
    """Return True if *email* matches a basic email format."""
    return bool(match(EMAIL_REGEX, email))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route('/register', methods=('GET', 'POST'))
def register():
    """Register a new user with nickname, email, and password."""
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None

        if not nickname:
            error = 'Nickname is required.'
        elif not email:
            error = 'Email Address is required.'
        elif not is_valid_email(email):
            error = 'Valid Email Address format (e.g. user@company.com) is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (nickname, email, password, jokebalance, userRole)"
                    " VALUES (?, ?, ?, 0, 0)",
                    (nickname, email, generate_password_hash(password)),
                )
                db.commit()
                logger.info("New user registered: %s", nickname)
                return redirect(url_for("auth.login"))
            except db.IntegrityError:
                error = f"Nickname {nickname} is already registered."
                logger.warning("Duplicate nickname on register: %s", nickname)

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    """Authenticate a user by nickname or email plus password."""
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        user = None

        if not nickname and not email:
            error = 'Enter either your Nickname or Email Address.'
        elif nickname:
            # Nickname takes priority when both are provided
            user = db.execute(
                'SELECT * FROM user WHERE nickname = ?', (nickname,)
            ).fetchone()
        else:
            # Email-only login: email is not unique, so check password against all matches
            candidates = db.execute(
                'SELECT * FROM user WHERE email = ?', (email,)
            ).fetchall()
            for candidate in candidates:
                if check_password_hash(candidate['password'], password):
                    user = candidate
                    break
            if user is None and candidates:
                error = 'Incorrect password.'

        if error is None and user is None:
            error = 'Incorrect Nickname or Email Address.'

        if error is None and not nickname and not email:
            pass  # already handled above
        elif error is None and nickname and not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            logger.info("User %s logged in", user['id'])
            if user['userRole'] == 1:
                return redirect(url_for('jokes.moderator'))
            return redirect(url_for('jokes.create'))

        flash(error)

    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    """Load the current user from the session into g.user before each request."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    """Clear the session and redirect to the login page."""
    session.clear()
    logger.info("User logged out")
    return redirect(url_for('auth.login'))


def login_required(view):
    """Decorator that redirects unauthenticated users to the login page."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view
