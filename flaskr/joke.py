"""Joke blueprint: browsing, creating, rating, editing, deleting jokes,
plus moderator tools for user/joke management and logging configuration."""

import logging
from re import match

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash

from flaskr.auth import login_required
from flaskr.db import get_db
from flaskr import set_log_level

logger = logging.getLogger(__name__)

bp = Blueprint('jokes', __name__)

# Email regex (same as auth.py -- kept here because the moderator create-user
# form needs it and the original cross-import was problematic)
EMAIL_REGEX = r'^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+[@]\w+[.]\w+$'

# Common SQL fragment used to fetch jokes joined with their author
_JOKES_SQL = (
    'SELECT j.id, title, body, created, author_id, nickname,'
    ' ratings, numberOfRatings, userRole'
    ' FROM jokes j JOIN user u ON j.author_id = u.id'
    ' ORDER BY created DESC'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_moderator():
    """Return True if the current user has the moderator role."""
    return g.user['userRole'] == 1


def _moderator_context():
    """Return the template variables needed by the moderator dashboard."""
    db = get_db()
    users = db.execute(
        'SELECT id, nickname, email, jokebalance, userRole FROM user'
    ).fetchall()
    jokes = db.execute(_JOKES_SQL).fetchall()
    is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
    return dict(users=users, jokes=jokes, is_debug=is_debug)


def _render_moderator():
    """Convenience: render the moderator dashboard with current data."""
    return render_template('jokes/moderator.html', **_moderator_context())


def _redirect_if_moderator():
    """If the current user is a moderator, redirect to the moderator dashboard.
    Returns None for regular users so the caller can continue normally."""
    if _is_moderator():
        flash("Access denied. This page is for Users only.")
        return redirect(url_for('jokes.moderator'))
    return None


def _get_joke_or_404(joke_id):
    """Fetch a single joke by id, or abort 404."""
    joke = get_db().execute(
        'SELECT j.id, title, body, created, author_id, nickname,'
        ' ratings, numberOfRatings, u.id as user_id, userRole'
        ' FROM jokes j JOIN user u ON j.author_id = u.id'
        ' WHERE j.id = ?',
        (joke_id,),
    ).fetchone()
    if joke is None:
        abort(404, f"Joke id {joke_id} doesn't exist.")
    return joke


def _is_valid_email(email):
    """Return True if *email* matches a basic email format."""
    return bool(match(EMAIL_REGEX, email))


# ---------------------------------------------------------------------------
# User-facing routes
# ---------------------------------------------------------------------------

@bp.route('/')
@login_required
def takeAJoke():
    """Browse jokes from other users, or show the moderator dashboard."""
    redir = _redirect_if_moderator()
    if redir:
        return _render_moderator()

    db = get_db()
    jokes = db.execute(_JOKES_SQL).fetchall()
    return render_template('jokes/takeAJoke.html', jokes=jokes)


@bp.route('/myjokes', methods=('GET', 'POST'))
@login_required
def myjokes():
    """List the current user's own jokes."""
    redir = _redirect_if_moderator()
    if redir:
        return redir

    db = get_db()
    jokes = db.execute(
        _JOKES_SQL.replace('ORDER BY', 'WHERE j.author_id = ? ORDER BY'),
        (g.user['id'],),
    ).fetchall()
    return render_template('jokes/myjokes.html', jokes=jokes)


@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    """Post a new joke (title + body). Moderators are redirected away."""
    if _is_moderator():
        return _render_moderator()

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = 'Title is required.'
        elif len(title.split()) > 10:
            error = 'Title must be 10 words or less.'

        if error:
            flash(error)
        else:
            db = get_db()
            # Prevent duplicate titles per author
            exists = db.execute(
                'SELECT EXISTS(SELECT 1 FROM jokes WHERE title = ? AND author_id = ?)',
                (title, g.user['id']),
            ).fetchone()[0]

            if exists:
                flash('You have already written a joke with this title.')
            else:
                db.execute(
                    'INSERT INTO jokes (author_id, title, body, ratings, numberOfRatings)'
                    ' VALUES (?, ?, ?, 0, 0)',
                    (g.user['id'], title, body),
                )
                db.commit()
                logger.info("Joke created: '%s' by user %s", title, g.user['id'])
                return redirect(url_for('jokes.myjokes'))

    return render_template('jokes/create.html')


@bp.route('/viewSingle/<int:id>')
@login_required
def viewSingle(id):
    """View a single joke. Deducts from joke balance on first view of
    another user's joke; enforces the 'take a penny' credit system."""
    joke = _get_joke_or_404(id)
    db = get_db()

    if not _is_moderator():
        balance = db.execute(
            'SELECT jokebalance FROM user WHERE id = ?', (g.user['id'],)
        ).fetchone()['jokebalance']

        already_viewed = db.execute(
            'SELECT EXISTS(SELECT 1 FROM jokesViewed WHERE joke_id = ? AND user_id = ?)',
            (id, g.user['id']),
        ).fetchone()[0]

        is_own_joke = joke['author_id'] == g.user['id']

        # Block viewing new jokes from others when balance is zero
        if balance <= 0 and not is_own_joke and not already_viewed:
            flash('Your joke balance is 0. Post a joke first to earn credit.')
            return redirect(url_for('jokes.myjokes'))

        # Record the view and deduct balance for a new joke from another user
        if not is_own_joke and not already_viewed:
            db.execute(
                'INSERT INTO jokesViewed(user_id, joke_id, has_rated) VALUES (?, ?, 0)',
                (g.user['id'], id),
            )
            db.execute(
                'UPDATE user SET jokebalance = jokebalance - 1 WHERE id = ?',
                (g.user['id'],),
            )
            db.commit()

    return render_template('jokes/viewSingle.html', joke=joke)


@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    """Edit a joke's body (title is read-only after creation)."""
    joke = _get_joke_or_404(id)

    if request.method == 'POST':
        body = request.form['body']
        db = get_db()
        db.execute('UPDATE jokes SET body = ? WHERE id = ?', (body, id))
        db.commit()
        logger.info("Joke %s updated", id)

        if _is_moderator():
            return redirect(url_for('jokes.moderator'))
        return redirect(url_for('jokes.takeAJoke'))

    return render_template('jokes/update.html', joke=joke)


@bp.route('/<int:id>/delete', methods=('GET', 'POST'))
@login_required
def delete(id):
    """Delete a joke and its associated view records."""
    _get_joke_or_404(id)
    db = get_db()

    # Get author before deleting so we can adjust their balance
    author_row = db.execute(
        'SELECT author_id FROM jokes WHERE id = ?', (id,)
    ).fetchone()

    # Clean up related records and delete the joke in one transaction
    db.execute('DELETE FROM jokesViewed WHERE joke_id = ?', (id,))
    db.execute('DELETE FROM jokes WHERE id = ?', (id,))

    # Decrement the author's balance (only for regular users, skip if already 0)
    if not _is_moderator() and g.user['jokebalance'] > 0:
        db.execute(
            'UPDATE user SET jokebalance = jokebalance - 1 WHERE id = ?',
            (author_row['author_id'],),
        )

    db.commit()
    logger.info("Joke %s deleted", id)

    if _is_moderator():
        return _render_moderator()
    return redirect(url_for('jokes.takeAJoke'))


@bp.route('/viewSingle/<int:joke_id>', methods=['POST'])
@login_required
def rate_joke(joke_id):
    """Submit a rating (1-10) for a joke the current user has viewed."""
    if _is_moderator():
        return _render_moderator()

    rating = int(request.form['rating'])
    if not (1 <= rating <= 10):
        flash("Rating must be between 1 and 10.")
        return redirect(url_for('jokes.viewSingle', id=joke_id))

    db = get_db()
    viewed = db.execute(
        'SELECT has_rated FROM jokesViewed WHERE user_id = ? AND joke_id = ?',
        (g.user['id'], joke_id),
    ).fetchone()

    if viewed is None or viewed['has_rated'] != 0:
        flash("Error. You have already rated this joke.")
    else:
        db.execute(
            'UPDATE jokes SET ratings = ratings + ?, numberOfRatings = numberOfRatings + 1'
            ' WHERE id = ?',
            (rating, joke_id),
        )
        db.execute(
            'UPDATE jokesViewed SET has_rated = 1 WHERE joke_id = ? AND user_id = ?',
            (joke_id, g.user['id']),
        )
        db.commit()
        logger.info("Joke %s rated %s by user %s", joke_id, rating, g.user['id'])
        flash("Successfully rated joke.")

    return redirect(url_for('jokes.viewSingle', id=joke_id))


# ---------------------------------------------------------------------------
# Moderator routes
# ---------------------------------------------------------------------------

@bp.route('/moderator')
@login_required
def moderator():
    """Render the moderator dashboard (users, jokes, logging config)."""
    if not _is_moderator():
        flash("Access denied. This page is for moderators only.")
        return redirect(url_for('jokes.takeAJoke'))
    return _render_moderator()


@bp.route('/moderator', methods=['GET', 'POST'])
@login_required
def update_userRole():
    """Promote or demote a user (moderator only)."""
    if not _is_moderator():
        flash('You do not have permission to access this page.')
        return redirect(url_for('jokes.takeAJoke'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        action = request.form['action']
        db = get_db()

        if action == 'promote':
            db.execute('UPDATE user SET userRole = 1 WHERE id = ?', (user_id,))
            flash('User promoted to moderator.')
            logger.info("User %s promoted to moderator", user_id)
        elif action == 'demote':
            db.execute('UPDATE user SET userRole = 0 WHERE id = ?', (user_id,))
            flash('User demoted to regular user.')
            logger.info("User %s demoted", user_id)

        db.commit()
        return redirect(url_for('jokes.update_userRole'))

    return _render_moderator()


@bp.route('/moderator.update_balance', methods=['GET', 'POST'])
@login_required
def modUpdate_jokeBalance():
    """Adjust a user's joke balance (moderator only)."""
    if not _is_moderator():
        flash('You do not have permission to access this page.')
        return redirect(url_for('jokes.takeAJoke'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        new_balance = request.form['user_jokebalance']
        db = get_db()
        db.execute('UPDATE user SET jokebalance = ? WHERE id = ?', (new_balance, user_id))
        db.commit()
        flash(f'Joke balance for user {user_id} updated to {new_balance}.')
        logger.info("Balance for user %s set to %s", user_id, new_balance)
        return redirect(url_for('jokes.modUpdate_jokeBalance'))

    return _render_moderator()


@bp.route('/moderator.initializeUser', methods=['GET', 'POST'])
@login_required
def initializeUser():
    """Create a new user account (moderator only)."""
    if not _is_moderator():
        flash('You do not have permission to access this page.')
        return redirect(url_for('jokes.takeAJoke'))

    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        joke_balance = request.form['jokeBalance']
        user_role = request.form['userRole']
        error = None

        if not nickname:
            error = 'Nickname is required.'
        elif not email:
            error = 'Email Address is required.'
        elif not _is_valid_email(email):
            error = 'Valid Email Address format (e.g. user@company.com) is required.'
        elif not request.form['password']:
            error = 'Password is required.'

        if error is None:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO user (nickname, email, password, jokebalance, userRole)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (nickname, email, password, joke_balance, user_role),
                )
                db.commit()
                flash(f'User "{nickname}" created successfully.')
                logger.info("Moderator created user: %s", nickname)
            except db.IntegrityError:
                flash(f'Nickname "{nickname}" is already registered.')
                logger.warning("initializeUser duplicate nickname: %s", nickname)
        else:
            flash(error)

    return _render_moderator()


@bp.route('/moderator.updateLoggingLevel', methods=['GET', 'POST'])
@login_required
def update_loggingLevel():
    """Toggle between INFO and DEBUG logging (moderator only)."""
    if not _is_moderator():
        flash('You do not have permission to access this page.')
        return redirect(url_for('jokes.takeAJoke'))

    if request.method == 'POST':
        level = request.form.get('action')
        if level in ('INFO', 'DEBUG'):
            set_log_level(level)
            logger.info("Logging level changed to %s by moderator", level)
        else:
            logger.warning("Invalid logging level requested: %s", level)

    return _render_moderator()
