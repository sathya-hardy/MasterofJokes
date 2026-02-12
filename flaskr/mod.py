import functools
import re
import inspect
from werkzeug.exceptions import abort
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
import logging
import os
from flaskr.auth import login_required

log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=log_level, 
                    format='%(asctime)s - %(levelname)s - %(message)s', 
                    handlers=[logging.FileHandler("moj.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)


def set_log_level(level):
    """Dynamically set the logging level."""
    numeric_level = getattr(logging, level.upper(), None)
    if isinstance(numeric_level, int):
        logger.setLevel(numeric_level)
        for handler in logger.handlers:
            handler.setLevel(numeric_level)
        logger.info("Log level set to %s", level)
    else:
        logger.warning("Invalid log level: %s", level)

bp = Blueprint('moderator', __name__, url_prefix='/moderator')


@bp.route('/moderator', methods=['GET', 'POST'])
@bp.after_app_request
def log_response_status(response):
    if response.status_code != 200:
        logger.warning("HTTP %s returned for path %s", response.status_code, request.path)
    else:
        logger.info("HTTP %s returned for path %s", response.status_code, request.path)
    return response

@login_required
def update_userRole():
    logger.debug("Entered update_userRole function")
    try:
        if g.user['userRole'] != 1:
            logger.warning("Access denied for user %s to update user roles", g.user['id'])
            flash('You do not have permission to access this page.')
            logger.debug("Exiting update_userRole function and redirecting user %s to takeAJoke page", g.user['id'])
            return redirect(url_for('jokes.takeAJoke'))

        db = get_db()
        logger.debug("Database connection established for user role update")
        
        if request.method == 'POST':
            user_id = request.form['user_id']
            action = request.form['roleAction']
            logger.debug("Received POST data with user_id: %s and roleAction: %s", user_id, action)
            
            if action == 'promote':
                logger.debug("Executing SQL query to promote user %s to moderator", user_id)
                db.execute('UPDATE user SET userRole = 1 WHERE id = ?', (user_id,))
                logger.warning("Role change: User %s promoted to moderator", user_id)
                # logger.info("User %s promoted to moderator", user_id)
                flash('User promoted to moderator.')
            elif action == 'demote':
                logger.debug("Executing SQL query to demote user %s to regular user", user_id)
                db.execute('UPDATE user SET userRole = 0 WHERE id = ?', (user_id,))
                logger.warning("Role change: User %s demoted to regular user", user_id)
                # logger.info("User %s demoted to regular user", user_id)
                flash('User demoted to user.')
            else:
                logger.warning("Invalid action %s received for user %s", action, user_id)
                flash('Invalid')
            
            db.commit()
            logger.debug("Database changes committed for user role update")
            logger.debug("Exiting update_userRole function and redirecting to update_userRole view")
            return redirect(url_for('moderator.update_userRole'))

        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    
    logger.debug("Exiting update_userRole function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users)


@bp.route('/moderator', methods=['GET', 'POST'])
@login_required
def update_jokeBalance():
    logger.debug("Entered update_jokeBalance function")
    try:
        if g.user['userRole'] != 1:
            logger.warning("Access denied for user %s to update joke balance", g.user['id'])
            flash('You do not have permission to access this page.')
            logger.debug("Exiting update_jokeBalance function and redirecting user %s to takeAJoke page", g.user['id'])
            return redirect(url_for('jokes.takeAJoke'))

        db = get_db()
        logger.debug("Database connection established for joke balance update")
        
        if request.method == 'POST':
            user_id = request.form['user_id']
            new_jokebalance = request.form['user_jokebalance']
            action = request.form['jokeAction']
            logger.debug("Received POST data with user_id: %s, new_jokebalance: %s, and jokeAction: %s", user_id, new_jokebalance, action)
            
            if action == 'ChangeBalance':
                logger.debug("Executing SQL query to update jokebalance for user %s to %s", user_id, new_jokebalance)
                db.execute('UPDATE user SET jokebalance = ? WHERE id = ?', (new_jokebalance, user_id))
                logger.info("Jokebalance for user %s updated to %s", user_id, new_jokebalance)
                flash('User ' + user_id + 's jokeBalance changed successfully')
            else:
                logger.warning("Invalid action %s received for user %s", action, user_id)
                flash('Invalid')

            db.commit()
            logger.debug("Database changes committed for joke balance update")
            logger.debug("Exiting update_jokeBalance function and redirecting to update_jokeBalance view")
            return redirect(url_for('moderator.update_jokeBalance'))

        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    
    logger.debug("Exiting update_jokeBalance function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users)



    