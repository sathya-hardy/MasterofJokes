import logging
import os
import inspect
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from flaskr.auth import login_required
from flaskr.db import get_db
from re import match
from werkzeug.security import check_password_hash, generate_password_hash
#from auth import is_valid_email



log_level = os.getenv('LOG_LEVEL', 'DEBUG').upper()
print(f"Log Level: {log_level}") 
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
    


bp = Blueprint('jokes', __name__)

@bp.after_app_request
def log_response_status(response):
    if response.status_code != 200:
        logger.warning("HTTP %s returned for path %s", response.status_code, request.path)
    else:
        logger.info("HTTP %s returned for path %s", response.status_code, request.path)
    return response

#For some reason I could not get the import to work with this function so its here now.
def is_valid_email(email):
    """Check if the email is a valid format."""
    logger.debug("Entering is_valid_email function with email: %s", email)
    regex = r'^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+[@]\w+[.]\w+$'
    valid = bool(match(regex, email))
    logger.debug("Exiting is_valid_email function with result: %s", valid)
    return valid

@bp.route('/')
@login_required
def takeAJoke():
    logger.debug("Entered takeAJoke function")
    
    try:
        if g.user['userRole'] != 0:
            logger.warning("Access denied for user %s to takeAJoke page", g.user['id'])
            flash("Access denied. This page is for Users only.")
            db = get_db()
            
            users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
            logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
            
            jokes = db.execute(
                'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
                ' FROM jokes j JOIN user u ON j.author_id = u.id'
                ' ORDER BY created DESC'
            ).fetchall()
            logger.debug("SQL Query Executed: SELECT jokes and users data")
            logging.debug("Getting current log level to pass into moderator")
            is_debug = logging.getLevelName(logger.level).upper == "DEBUG"
            logging.debug("is_debug set to: %s", is_debug)
            logger.debug("Exiting takeAJoke function as a moderator view")
            return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)
        
        db = get_db()
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes data")
    
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    
    logger.debug("Exiting takeAJoke function as a user view")
    return render_template('jokes/takeAJoke.html', jokes=jokes)



@bp.route('/myjokes', methods=('GET', 'POST'))
@login_required
def myjokes():
    logger.debug("Entered myjokes function")

    try: 
        if g.user['userRole'] != 0:
            logger.warning("Access denied for user %s to myjokes page", g.user['id'])
            flash("Access denied. This page is for Users only.")
            logger.debug("Exiting myjokes function due to access denial")
            return redirect(url_for('jokes.takeAJoke'))
        
        db = get_db()
        logger.debug("Executing SQL query to fetch jokes for user %s", g.user['id'])
        
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' WHERE ? = j.author_id'
            ' ORDER BY created DESC', 
            (g.user['id'],)
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes for user %s", g.user['id'])
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    
    logger.debug("Exiting myjokes function successfully")
    return render_template('jokes/myjokes.html', jokes=jokes)

"""
This one is actually the leaveAJoke page, but by the time I figured out the naming conventions
I had already modified the create html and then kept using the name elsewhere so I just kept it
"""
@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    logger.debug("Entered create function")
    
    if g.user['userRole'] != 0:
        logger.warning("Access denied for user %s to create page", g.user['id'])
        flash("Access denied. This page is for Users only.")
        
        db = get_db()
        logger.debug("Executing SQL query to fetch user list")
        
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes and users data for moderator view")
        logging.debug("Getting current log level to pass into moderator")
        is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
        logging.debug("is_debug set to: %s", is_debug)
        logger.debug("Exiting create function as a moderator view")
        return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        logger.debug("Received POST data with title: %s", title)
        error = None

        if not title:
            error = 'Title is required.'
            logger.warning("Title validation failed: Title is empty")
        else:
            splitTitle = title.split()
            if len(splitTitle) > 10:
                error = 'Title must be 10 words or less'
                logger.warning("Title validation failed: Title contains more than 10 words")

        if error is not None:
            logger.warning("Form validation failed with error: %s", error)
            flash(error)
        else:
            db = get_db()
            logger.debug("Checking if the joke with title '%s' already exists for user %s", title, g.user['id'])
            
            uniqueJoke = db.execute(
                'SELECT EXISTS(SELECT * FROM jokes WHERE title = ? AND author_id = ?)',
                (title, g.user['id'])
            ).fetchone()[0]
            logger.debug("SQL Query Executed: SELECT EXISTS for unique joke title check")

            if uniqueJoke == 0:
                try:
                    logger.debug("Inserting new joke into the database for user %s", g.user['id'])
                    db.execute(
                        'INSERT INTO jokes (author_id, title, body, ratings, numberOfRatings)'
                        ' VALUES (?, ?, ?, ?, ?)',
                        (g.user['id'], title, body, 0, 0)
                    )
                    db.commit()
                    logger.info("New joke created successfully with title: %s by user %s", title, g.user['id'])
                    return redirect(url_for('jokes.myjokes'))
                except Exception as e:
                    logger.critical("Critical error occurred while inserting joke for user %s: %s", g.user['id'], e, exc_info=True)
                    flash('Critical error occurred while saving your joke. Please try again later.')
                    return redirect(url_for('jokes.takeAJoke'))
            else:
                error = 'You have already written a joke with this title.'
                logger.warning("Duplicate joke title detected for user %s with title: %s", g.user['id'], title)
                flash(error)


    logger.debug("Exiting create function with errors")
    return render_template('jokes/create.html')


@bp.route('/viewSingle/<int:id>')
@login_required
def viewSingle(id):
    logger.debug("Entered viewSingle function with joke id: %s", id)
    try: 
        db = get_db()
        logger.debug("Executing SQL query to fetch joke with id: %s", id)
        
        joke = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, u.id as id, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' WHERE j.id = ?',
            (id,)
        ).fetchone()
        logger.debug("SQL Query Executed: SELECT joke details for id %s", id)

        if joke is None:
            logger.error("Joke with id %s does not exist", id)
            abort(404, f"Joke id {id} doesn't exist.")
        
        if g.user['userRole'] == 0:
            logger.debug("User %s has userRole 0 (regular user)", g.user['id'])
            
            logger.debug("Executing SQL query to fetch user's joke balance for user id: %s", g.user['id'])
            userJokeBalance = db.execute(
                'SELECT jokebalance FROM user WHERE id = ?', (g.user['id'],)
            ).fetchone()
            logger.debug("SQL Query Executed: SELECT jokebalance for user id %s", g.user['id'])
            
            logger.debug("Executing SQL query to check if joke %s has been viewed by user %s", id, g.user['id'])
            jokeViewed = db.execute(
                'SELECT EXISTS(SELECT * FROM jokesViewed WHERE joke_id = ? AND user_id = ?)', (id, g.user['id'])
            ).fetchone()[0]
            logger.debug("SQL Query Executed: Check if joke %s is viewed by user %s", id, g.user['id'])
            
            if userJokeBalance['jokebalance'] <= 0:
                logger.debug("User %s has a joke balance of 0", g.user['id'])
                
                if joke['author_id'] == g.user['id']:
                    logger.info("User %s is the author of joke %s, viewing allowed", g.user['id'], id)
                    logger.debug("Exiting viewSingle function after rendering view for author's joke")
                    return render_template('jokes/viewSingle.html', joke=joke)
                else:
                    if jokeViewed == 0:
                        error = 'You have a jokebalance of 0 and need to first author a joke and you have not previously viewed that joke.'
                        logger.warning("Access denied for user %s due to insufficient jokebalance to view joke %s", g.user['id'], id)
                        flash(error)
                        logger.debug("Exiting viewSingle function with redirect to myjokes page")
                        return redirect(url_for('jokes.myjokes'))
                    else:
                        logger.info("User %s has already viewed joke %s", g.user['id'], id)
                        logger.debug("Exiting viewSingle function after rendering view for previously viewed joke")
                        return render_template('jokes/viewSingle.html', joke=joke)

            if joke['author_id'] != g.user['id']:
                logger.debug("User %s is not the author of joke %s", g.user['id'], id)
                
                if jokeViewed == 0:
                    logger.debug("Inserting new view record into jokesViewed for user %s and joke %s", g.user['id'], id)
                    
                    db.execute(
                        'INSERT INTO jokesViewed(user_id, joke_id, has_rated) VALUES (?, ?, 0)',
                        (g.user['id'], id)
                    )
                    db.commit()
                    logger.info("View record inserted successfully for user %s and joke %s", g.user['id'], id)
                    
                    logger.debug("Updating jokebalance for user %s", g.user['id'])
                    db.execute(
                        'UPDATE user SET jokebalance = jokebalance - 1 WHERE id = ?',
                        (g.user['id'],)
                    )
                    db.commit()
                    logger.info("Jokebalance decremented for user %s", g.user['id'])
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    logger.debug("Exiting viewSingle function after rendering view for joke id %s", id)
    return render_template('jokes/viewSingle.html', joke=joke)


def get_post(id):
    logger.debug("Entered get_post function with post id: %s", id)
    if id is None:
        logger.error("Post id is missing in %s function", inspect.currentframe().f_code.co_name)
        abort(400, "Post id is required but was not provided.")

    db = get_db()
    logger.debug("Executing SQL query to fetch joke with id: %s", id)
    
    joke = db.execute(
        'SELECT j.id, title, body, created, author_id, nickname, u.id, userRole'
        ' FROM jokes j JOIN user u ON j.author_id = u.id'
        ' WHERE j.id = ?',
        (id,)
    ).fetchone()
    logger.debug("SQL Query Executed: SELECT joke details for id %s", id)

    if joke is None:
        logger.error("Joke with id %s does not exist", id)
        abort(404, f"Post id {id} doesn't exist.")
    
    logger.debug("Exiting get_post function with retrieved joke for id %s", id)
    return joke


@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    logger.debug("Entered update function with joke id: %s", id)
    
    if id is None:
        logger.error("Post id is missing in %s function", inspect.currentframe().f_code.co_name)
        abort(400, "Post id is required but was not provided.")
    
    try:
        joke = get_post(id)
        logger.debug("Retrieved joke for update with id: %s", id)
    except Exception as e:
        logger.critical("Critical error occurred while retrieving joke with id %s: %s", id, e, exc_info=True)
        flash("An unexpected error occurred while retrieving the joke. Please try again later.")
        return redirect(url_for('jokes.takeAJoke'))

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        logger.debug("Received POST data for joke id %s with title: %s", id, title)
        error = None

        if not title:
            error = 'Title is required.'
            logger.warning("Title validation failed for joke id %s: Title is empty", id)

        if error is not None:
            logger.warning("Form validation failed with error: %s", error)
            flash(error)
        else:
            try:
                db = get_db()
                logger.debug("Executing SQL query to update joke with id: %s", id)
                
                db.execute(
                    'UPDATE jokes SET body = ?'
                    ' WHERE id = ?',
                    (body, id)
                )
                db.commit()
                logger.info("Joke with id %s updated successfully", id)
            except Exception as e:
                logger.critical("Critical error occurred while updating joke with id %s: %s", id, e, exc_info=True)
                flash("An unexpected error occurred while updating the joke. Please try again later.")
                return redirect(url_for('jokes.takeAJoke'))

            if g.user['userRole'] != 1:
                logger.debug("Exiting update function and redirecting user %s to takeAJoke page", g.user['id'])
                return redirect(url_for('jokes.takeAJoke'))
            else:
                logger.debug("Exiting update function and redirecting moderator %s to moderator page", g.user['id'])
                return redirect(url_for('jokes.moderator'))

    logger.debug("Exiting update function and rendering update page for joke id %s", id)
    return render_template('jokes/update.html', joke=joke)



@bp.route('/<int:id>/delete', methods=('GET','POST',))
@login_required
def delete(id):
    logger.debug("Entered delete function with joke id: %s", id)
    if id is None:
        logger.error("Post id is missing in %s function", inspect.currentframe().f_code.co_name)
        abort(400, "Post id is required but was not provided.")
    
    get_post(id)
    logger.debug("Verified joke with id %s exists before deletion", id)
    
    db = get_db()
    logger.debug("Executing SQL query to fetch joke_id from jokesViewed for joke id: %s", id)
    
    deletingEntries = db.execute(
        'select joke_id from jokesViewed where joke_id = ?', (id,)
    ).fetchall()
    logger.debug("SQL Query Executed: SELECT joke_id FROM jokesViewed WHERE joke_id = %s", id)
    
    for entry in deletingEntries:
        logger.debug("Deleting entry from jokesViewed for joke_id %s", entry['joke_id'])
        db.execute('DELETE FROM jokesViewed WHERE joke_id = ?', (entry['joke_id'],))
        db.commit()
        logger.info("Deleted entry from jokesViewed for joke_id %s", entry['joke_id'])
    
    logger.debug("Executing SQL query to fetch author_id from jokes for joke id: %s", id)
    userID = db.execute('SELECT author_id from jokes where id=?', (id,)).fetchone()
    logger.debug("SQL Query Executed: SELECT author_id FROM jokes WHERE id = %s", id)
    
    logger.debug("Deleting joke with id %s from jokes table", id)
    db.execute('DELETE FROM jokes WHERE id = ?', (id,))
    db.commit()
    logger.info("Joke with id %s deleted successfully from jokes table", id)
    
    if g.user['userRole'] != 1:
        logger.debug("User %s is not a moderator, checking jokebalance", g.user['id'])
        
        if g.user['jokebalance'] != 0:  # Change to make it so deleting doesn't take you to negative joke balance, but it will decrement you
            logger.debug("Updating jokebalance for user %s", userID['author_id'])
            db.execute('UPDATE user SET jokebalance = jokebalance - 1 WHERE id = ?', (userID['author_id'],))
            db.commit()
            logger.info("Jokebalance decremented for user %s after deleting joke id %s", userID['author_id'], id)
        
        logger.debug("Exiting delete function and redirecting user %s to takeAJoke page", g.user['id'])
        return redirect(url_for('jokes.takeAJoke'))
    
    logger.debug("User %s is a moderator, fetching users and jokes list", g.user['id'])
    
    users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
    logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
    
    jokes = db.execute(
        'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
        ' FROM jokes j JOIN user u ON j.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
    logging.debug("Getting current log level to pass into moderator")
    is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
    logging.debug("is_debug set to: %s", is_debug)
    logger.debug("Exiting delete function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)


    
    


@bp.route('/viewSingle/<int:joke_id>', methods=['POST',])
def rate_joke(joke_id):
    logger.debug("Entered rate_joke function with joke id: %s", joke_id)
    if id is None:
        logger.error("Joke id is missing in %s function", inspect.currentframe().f_code.co_name)
        abort(400, "Joke id is required but was not provided.")
    
    if g.user['userRole'] != 0:
        logger.warning("Access denied for user %s to rate joke %s", g.user['id'], joke_id)
        flash("Access denied. This page is for Users only.")
        
        db = get_db()
        logger.debug("Executing SQL query to fetch users list")
        
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
        logging.debug("Getting current log level to pass into moderator")
        is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
        logging.debug("is_debug set to: %s", is_debug)
        logger.debug("Exiting rate_joke function and rendering moderator view for user %s", g.user['id'])
        return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)
    
    rating = int(request.form['rating'])
    logger.debug("Received POST data with rating: %s for joke id %s", rating, joke_id)
    
    # Validate that the rating is between 1 and 10
    if not (1 <= rating <= 10):
        logger.warning("Invalid rating %s for joke id %s. Must be between 1 and 10.", rating, joke_id)
        flash("Rating must be between 1 and 10.")
        logger.debug("Exiting rate_joke function and redirecting user %s to viewSingle for joke id %s", g.user['id'], joke_id)
        return redirect(url_for('jokes.viewSingle', id=joke_id))
    
    db = get_db()
    logger.debug("Executing SQL query to check if joke %s has been rated by user %s", joke_id, g.user['id'])
    
    # Validate that a joke cannot be rated more than once
    jokeRated = db.execute(
        'SELECT has_rated FROM jokesViewed WHERE user_id = ? AND joke_id = ?', (g.user['id'], joke_id)
    ).fetchone()
    logger.debug("SQL Query Executed: SELECT has_rated FROM jokesViewed WHERE user_id = %s AND joke_id = %s", g.user['id'], joke_id)
    
    if jokeRated['has_rated'] != 0:
        logger.warning("User %s has already rated joke %s", g.user['id'], joke_id)
        flash("Error. You have already rated this joke")
    else:
        logger.debug("Updating ratings and number of ratings for joke id %s", joke_id)
        
        db.execute(
            'UPDATE jokes SET ratings = ratings + ?, numberOfRatings = numberOfRatings + 1 WHERE id = ?',
            (rating, joke_id)
        )
        logger.debug("SQL Query Executed: UPDATE jokes SET ratings and numberOfRatings for joke id %s", joke_id)
        
        logger.debug("Marking joke %s as rated by user %s", joke_id, g.user['id'])
        
        db.execute(
            'UPDATE jokesViewed SET has_rated = 1 WHERE joke_id = ? AND user_id = ?', (joke_id, g.user['id'])
        )
        logger.debug("SQL Query Executed: UPDATE jokesViewed SET has_rated = 1 for joke id %s and user id %s", joke_id, g.user['id'])
        
        db.commit()
        logger.info("Joke %s successfully rated by user %s with rating %s", joke_id, g.user['id'], rating)
        flash("Successfully rated joke.")
    
    logger.debug("Exiting rate_joke function and redirecting user %s to viewSingle for joke id %s", g.user['id'], joke_id)
    return redirect(url_for('jokes.viewSingle', id=joke_id))



"""
moderator things
"""
@bp.route('/moderator')
@login_required
def moderator():
    logger.debug("Entered moderator function")
    try:
        if g.user['userRole'] != 1:
            logger.warning("Access denied for user %s to moderator page", g.user['id'])
            flash("Access denied. This page is for moderators only.")
            logger.debug("Exiting moderator function and redirecting user %s to takeAJoke page", g.user['id'])
            return redirect(url_for('jokes.takeAJoke'))
        
        try:
            db = get_db()
            logger.debug("Executing SQL query to fetch jokes list for moderator view")
            
            jokes = db.execute(
                'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
                ' FROM jokes j JOIN user u ON j.author_id = u.id'
                ' ORDER BY created DESC'
            ).fetchall()
            logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
            
            logger.debug("Executing SQL query to fetch users list")
            users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
            logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        except Exception as e:
            logger.critical("Critical error occurred while fetching jokes or users for moderator page: %s", e, exc_info=True)
            flash("An unexpected error occurred while fetching data. Please try again later.")
            return redirect(url_for('jokes.takeAJoke'))
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s", inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    logging.debug("Getting current log level to pass into moderator")
    is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
    logging.debug("is_debug set to: %s", is_debug)
    logger.debug("Exiting moderator function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)




@bp.route('/moderator', methods=['GET', 'POST'])
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
            action = request.form['action']
            logger.debug("Received POST data with user_id: %s and action: %s", user_id, action)
            
            if action == 'promote':
                logger.debug("Executing SQL query to promote user %s to moderator", user_id)
                db.execute('UPDATE user SET userRole = 1 WHERE id = ?', (user_id,))
                logger.info("User %s promoted to moderator", user_id)
                flash('User promoted to moderator.')
            elif action == 'demote':
                logger.debug("Executing SQL query to demote user %s to regular user", user_id)
                db.execute('UPDATE user SET userRole = 0 WHERE id = ?', (user_id,))
                logger.info("User %s demoted to regular user", user_id)
                flash('User demoted to user.')
            else:
                logger.warning("Invalid action %s received for user %s", action, user_id)
                flash('Invalid')
            
            db.commit()
            logger.debug("Database changes committed for user role update")
            logger.debug("Exiting update_userRole function and redirecting to update_userRole view")
            return redirect(url_for('jokes.update_userRole'))

        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    logging.debug("Getting current log level to pass into moderator")
    is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
    logging.debug("is_debug set to: %s", is_debug)
    logger.debug("Exiting update_userRole function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)


@bp.route('/moderator.update_balance', methods=['GET', 'POST'])
@login_required
def modUpdate_jokeBalance():
    logger.debug("Entered modUpdate_jokeBalance function")
    try: 
        if g.user['userRole'] != 1:
            logger.warning("Access denied for user %s to update joke balance", g.user['id'])
            flash('You do not have permission to access this page.')
            logger.debug("Exiting modUpdate_jokeBalance function and redirecting user %s to takeAJoke page", g.user['id'])
            return redirect(url_for('jokes.takeAJoke'))

        db = get_db()
        logger.debug("Database connection established for joke balance update")
        
        if request.method == 'POST':
            user_id = request.form['user_id']
            new_jokebalance = request.form['user_jokebalance']
            action = request.form['action']
            logger.debug("Received POST data with user_id: %s, new_jokebalance: %s, and action: %s", user_id, new_jokebalance, action)
            
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
            logger.debug("Exiting modUpdate_jokeBalance function and redirecting to modUpdate_jokeBalance view")
            return redirect(url_for('jokes.modUpdate_jokeBalance'))

        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
    except Exception as e:
        logger.error("Unexpected error in %s function for user %s: %s",inspect.currentframe().f_code.co_name, g.user.get('id', 'Unknown'), e, exc_info=True)
        abort(500, "An unexpected error occurred while processing your request.")
    logging.debug("Getting current log level to pass into moderator")
    is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
    logging.debug("is_debug set to: %s", is_debug)
    logger.debug("Exiting modUpdate_jokeBalance function and rendering moderator page for user %s", g.user['id'])
    return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)


@bp.route('/moderator.initializeUser', methods=['GET', 'POST'])
@login_required
def initializeUser():
    logger.debug("Entered initializeUser function")
    
    if g.user['userRole'] != 1:
        logger.warning("Access denied for user %s to initialize new users", g.user['id'])
        flash('You do not have permission to access this page.')
        logger.debug("Exiting initializeUser function and redirecting user %s to takeAJoke page", g.user['id'])
        return redirect(url_for('jokes.takeAJoke'))
    
    db = get_db()
    logger.debug("Database connection established for user initialization")
    
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        jokeBalance = request.form['jokeBalance']
        userRole = request.form['userRole']
        
        logger.debug("Received POST data with nickname: %s, email: %s, jokeBalance: %s, userRole: %s", nickname, email, jokeBalance, userRole)
        
        error = None
        # Data checking and validation
        if not nickname:
            error = 'Nickname is required.'
            logger.warning("Nickname validation failed: Nickname is empty")
        elif not email:
            error = 'Email Address is required.'
            logger.warning("Email validation failed: Email is empty")
        elif not is_valid_email(email):
            error = 'Valid Email Address format (xxx@company.yyy or xxx.xxx@company.yyy) is required.'
            logger.warning("Email format validation failed for email: %s", email)
        elif not password:
            error = 'Password is required.'
            logger.warning("Password validation failed: Password is empty")
        elif not jokeBalance:
            error = 'JokeBalance is required'
            logger.warning("JokeBalance validation failed: JokeBalance is empty")
        elif not userRole:
            error = 'UserRole is required'
            logger.warning("UserRole validation failed: UserRole is empty")
        
        if error is None:
            try:
                logger.debug("Inserting new user with nickname: %s, email: %s", nickname, email)
                db.execute(
                    "INSERT INTO user (nickname, email, password, jokebalance, userRole) VALUES (?, ?, ?, ?, ?)",
                    (nickname, email, password, jokeBalance, userRole),
                )
                db.commit()
                logger.info("User with nickname %s successfully initialized", nickname)
            except db.IntegrityError:
                error = f"Nickname {nickname} is already registered."
                logger.warning("User initialization failed due to duplicate nickname: %s", nickname)
        else:
            logger.warning("User data validation failed with error: %s", error)
            flash(error)
        
        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
        logging.debug("Getting current log level to pass into moderator")
        is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
        logging.debug("is_debug set to: %s", is_debug)
        logger.debug("Exiting initializeUser function and rendering moderator page for user %s", g.user['id'])
        return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)


@bp.route('/moderator.updateLoggingLevel', methods=['GET', 'POST'])
@login_required
def update_loggingLevel():
    logger.debug("Entered update_loggingLevel function")
    if g.user['userRole'] != 1:
        logger.warning("Access denied for user %s to update user roles", g.user['id'])
        flash('You do not have permission to access this page.')
        logger.debug("Exiting update_loggingLevel function and redirecting user %s to takeAJoke page", g.user['id'])
        return redirect(url_for('jokes.takeAJoke'))

    db = get_db()
    logger.debug("Database connection established for user role update")
    if request.method == 'POST':
        logChange = request.form.get('action')
        logger.debug("Received POST data with logChange: %s", logChange)
        if logChange == "INFO":
            set_log_level("INFO")
            logging.info("Info logging enabled by moderator")
        elif logChange == "DEBUG":
            set_log_level("DEBUG")
            logging.info("Debug logging enabled by moderator")
        else:
            logging.warning("Error. Somehow moderator has requested to change logging level to neither INFO or DEBUG")

        logger.debug("Executing SQL query to fetch users list for moderator view")
        users = db.execute('SELECT id, nickname, email, jokebalance, userRole FROM user').fetchall()
        logger.debug("SQL Query Executed: SELECT id, nickname, email, jokebalance, userRole FROM user")
        
        logger.debug("Executing SQL query to fetch jokes list for moderator view")
        jokes = db.execute(
            'SELECT j.id, title, body, created, author_id, nickname, ratings, numberOfRatings, userRole'
            ' FROM jokes j JOIN user u ON j.author_id = u.id'
            ' ORDER BY created DESC'
        ).fetchall()
        logger.debug("SQL Query Executed: SELECT jokes list for moderator view")
        logging.debug("Getting current log level to pass into moderator")
        is_debug = logging.getLevelName(logger.level).upper() == "DEBUG"
        logging.debug("is_debug set to: %s", is_debug)

        logging.debug("Exiting update_loggingLevel function and rendering moderator page for user %s", g.user['id'])
        return render_template('jokes/moderator.html', users=users, jokes=jokes, is_debug=is_debug)

"""
This function was used for testing purposes to make sure data was actually
being inputted correctly


@bp.route('/print-data')
def print_data():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user') 
    rows = cursor.fetchall()
    db.close()
    
    for row in rows:
        print(dict(row)) 

    return "Data printed to console.'
"""