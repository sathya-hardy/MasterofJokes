#Create a Blueprint step
"""
This creates a Blueprint named 'auth'. Like the application object, the blueprint needs to know where its defined, so __name__ is
passed as the second argument. The url_prefix will be prepended to all the URLs associated with the blueprint
"""

import functools
import re
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
import logging
import os
from re import match

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

bp = Blueprint('auth', __name__, url_prefix='/auth')
@bp.after_app_request
def log_response_status(response):
    if response.status_code != 200:
        logger.warning("HTTP %s returned for path %s", response.status_code, request.path)
    else:
        logger.info("HTTP %s returned for path %s", response.status_code, request.path)
    return response

#The first view: register step
"""
While having a knowledge of RegEx, I am not skilled enough to write an email validation
myself. So I turned to the internet. I obtained this is_valid_email from:
https://www.zerobounce.net/email-guides/python-email-verification/#:~:text=The%20quickest%20way%20to%20check,a%2Dz0%2D9%5D%2B%5B.
And I will be using it to validate the email addresses entered.
The explanation for the RegEx:
^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+[@]\w+[.]\w+$
^ - just the beginning of the string
[a-zA-Z0-9] - the brackets are the character set, which means that as long as the character
        being evaluated matches a character listed within the brackets its fine.
        the a-z means it can be any character from a-z, A-Z, or 0-9.
+ - This quantifier means it can be more than just one character, as long as each character
        matches those brackets.
[\._] - This matches for a period or an underline, but are not needed for a valid address
? - This quantifier ensures that it is optional for the period or underline
[a-zA-Z0-9] - Same as before
+ - same as before
[@] - ensures that there must be an @ symbol after the characters
\w - matches any word character, which is almost the same as the long [a-zA-z.., but this
        includes underscores
+ - Same, makes it so your company name can be multiple characters
[.] - Ensures the . to be detected, allowing .com/.net/etc
\w - Same as before
+ - Same as before
$ - End, terminating the string
"""
def is_valid_email(email):
    """Check if the email is a valid format."""
    logger.debug("Entering is_valid_email function with email: %s", email)
    regex = r'^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+[@]\w+[.]\w+$'
    valid = bool(match(regex, email))
    logger.debug("Exiting is_valid_email function with result: %s", valid)
    return valid

"""Register Function:
1. @bp.route assocaites the URL/register with the register view function. When flask receives a request to /auth/register, it will call
the register view and use the return value as the response
2. If the user submitted the form, request.method will be 'Post'. In this case, start validating the input. 
3. request.form is a special type of dict mapping submitted from keys and valeus. The user will input their nickname, email, and password
4. Validate that nickname, email, and password are not empty
5. If validation succeeds, insert the new user data into the database
    An sqlite3.IntegrityError will occur if the nickname already exists, which should be shown to the user as another validation error
6. After storing the user, they are redirected to the login page. url_for() generates the URL for the login view vased on its name. This is
preferable to writing the URL directly as it allows you to change the URL later without changing all code that links to it. redirect()
generates a redirect response to the generated URL.
7. If validation fails, the error is shown to the user. flash() stores messages that can be retrieved when rendering the template.
8. When the user initially navigates to auth/register, or there was a validation error, an HTML page with the registration form should
be shown. 
"""
@bp.route('/register', methods=('GET', 'POST'))
def register():
    logger.debug("Entered register function")
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None

        if not nickname:
            error = 'Nickname is required.'
            logger.warning("Nickname validation failed")
        elif not email:
            error = 'Email Address is required.'
            logger.warning("Email address validation failed")
        elif not is_valid_email(email):
            error = 'Valid Email Address format (xxx@company.yyy or xxx.xxx@company.yyy) is required.'
            logger.warning("Email format validation failed for email: %s", email)
        elif not password:
            error = 'Password is required.'
            logger.warning("Password validation failed")

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (nickname, email, password, jokebalance, userRole) VALUES (?, ?, ?, ?, ?)",
                    (nickname, email, generate_password_hash(password), 0, 0),
                )
                db.commit()
                logger.info("User registered successfully with nickname: %s", nickname)
            except db.IntegrityError:
                error = f"Nickname {nickname} is already registered."
                logger.warning("Registration failed due to duplicate nickname: %s", nickname)
            else:
                return redirect(url_for("auth.login"))
    return render_template('auth/register.html')

#Login
"""
This view follows the same pattern as the register view
There are a few differences though.
1. The user is queried first and stored in a variable for later user
    fetchone() returns one row from the query. If the query returned no results, it returns None. Later, fetchall() will be used, returns all results
2. check_password_hash() hashes the submitted password in the same way as the stored hash and securely compares them. If they match, password is valid
3. session is a dict that stores data across requests. When validation succeeds, the user's id is stored in a new session. The data is stored
in a cookie that is sent to the browser, and the browser the sends it back with subsequent requests. Flask securely signs the data so that it
can't be tampered with.
Now that the user's id is stored in the session, it will be available on subsequent requests. At the beginning of each request, if a user is
logged in their information should be loaded and made available to other viewers.
In addition to this, the user can choose to login with either their nickname or email, and the password.
For some weird reason, validating nickname as None was not working, so that is why the value is checked with an empty string
The flag boolean variables and extra steps to logging in with only email are there because the email does
not have to be unique, so you have to verify you are logging in the correct user
"""
@bp.route('/login', methods=('GET', 'POST'))
def login():
    logger.debug("Entered login function")
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        emailOnly = False
        emailLoginSuccess = False
        error = None
        
        if nickname is None and email is None:
            error = 'You need to enter either the Nickname or Email Address associated with your account.'
            logger.warning("Login failed: Nickname and email not provided")
        elif email is None:
            user = db.execute('SELECT * FROM user WHERE nickname = ?', (nickname,)).fetchone()
        elif nickname == "":
            user = db.execute('SELECT * FROM user WHERE email = ?', (email,)).fetchall()
            emailOnly = True
        else:
            user = db.execute('SELECT * FROM user WHERE nickname = ?', (nickname,)).fetchone()
        
        if error is not None:
            flash(error)

        if user is None:
            error = 'Incorrect Nickname or Email Address'
            logger.warning("Login failed: User not found for nickname: %s or email: %s", nickname, email)
        elif emailOnly:
            for users in user:
                if check_password_hash(users['password'], password):
                    emailLoginSuccess = True
                    user = users
                    break
            if not emailLoginSuccess:
                error = 'Incorrect password.'
                logger.warning("Login failed: Incorrect password for email: %s", email)
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
            logger.warning("Login failed: Incorrect password for nickname: %s", nickname)

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            logger.info("User logged in successfully with id: %s", user['id'])
            if user['userRole'] == 1:
                return redirect(url_for('jokes.moderator'))
            else:
                return redirect(url_for('jokes.create'))

        flash(error)
    logger.debug("Exiting login function")
    return render_template('auth/login.html')

"""
bp.before_app_request() registers a function that runs before the view function, no matter what URL is requested. load_logged_in_user
checks if a user id is stored in the session and gets that user's data from the database, storing it on g.user, which lasts for the 
length of the request. If there is no user id, or if the id doesn't exist, g.user will be None
"""
@bp.before_app_request
def load_logged_in_user():
    logger.debug("Entered load_logged_in_user function")
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
        logger.debug("No user logged in")
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
        logger.debug("User loaded with id: %s", user_id)
    logger.debug("Exiting load_logged_in_user function")

#Logout
@bp.route('/logout')
def logout():
    logger.debug("Entered logout function")
    session.clear()
    logger.info("User logged out successfully")
    logger.debug("Exiting logout function")
    return redirect(url_for('auth.login'))

#require authentication in other views
"""
This decorator returns a new view function that wraps the original view its applied to. The new function checks if a user is loaded
and redirects to the login page otherwise. If a user is loaded the original view is called and continues normally. 
"""
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        logger.debug("Entered login_required decorator")
        if g.user is None:
            logger.warning("Unauthorized access attempt to protected route")
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    logger.debug("Exiting login_required decorator")
    return wrapped_view



    