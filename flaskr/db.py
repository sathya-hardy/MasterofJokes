import sqlite3
from datetime import datetime

import click
from flask import current_app, g
import logging
import os
from werkzeug.security import check_password_hash, generate_password_hash

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
"""
g is a special object that is unique for each request. It is used to store data that might be accessed by multiple functions during
the request. The connection is stored and reused instead of creating a new connection if get_db is called a second time in the same
request

current_app is another special object that points to the Flask application handling the request. Since we used an application factory,
there is no application object when writing the rest of your code. get_db will be called when the app has been created and is handling
a request, so current_app can be used.

sqlite3.connect() establishes a connection to the file pointed at by the DATABASE configuration key. This file doesn't have to exist yet
, and won't until you initialize the database later

sqlite3.Row tells the connection to return rows that behave like dicts. This allows accessing the columns by name

close_db checks if a connection was created by checking if g.db was set. If the connection exists, it is closed. Further down we will
tell our application about the close_db function in the application factory so that it is called after each request
"""

def get_db():
    logger.debug("Entered get_db function")
    if 'db' not in g:
        logger.info("Initializing database connection")
        try:
            g.db = sqlite3.connect(
                current_app.config['DATABASE'],
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            g.db.row_factory = sqlite3.Row
            logger.info("Database connection initialized successfully")
        except Exception as e:
            logger.critical("Database connection failed: %s", e, exc_info=True)
            raise e
    logger.debug("Exiting get_db function")
    return g.db


def close_db(e=None):
    logger.debug("Entered close_db function")
    db = g.pop('db', None)
    if db is not None:
        logger.info("Closing database connection")
        try:
            db.close()
            logger.info("Database connection closed successfully")
        except Exception as e:
            logger.error("Error occurred while closing the database connection: %s", e, exc_info=True)
    logger.debug("Exiting close_db function")


#after creating schema.sql
"""
open_resource() opens a file relative to the flaskr package, which is useful since you won't necessarily know where that location is
when deploying the app later. get_db returns a database connection, which is used to execute the commands read from the file

click.command() defines a command line command called init-db that calls the init_db function and shows a success message to the user

The call to sqlite3.register_converter() tells Python how to interpret timestamp values in the database. We convert the value to a
datetime.datetime
"""
def init_db():
    logger.debug("Entered init_db function")
    try:
        db = get_db()
        logger.info("Database connection obtained for schema initialization")
        with current_app.open_resource('schema.sql') as f:
            logger.info("Executing schema.sql script for database initialization")
            db.executescript(f.read().decode('utf8'))
            logger.info("Database schema initialized successfully")
    except Exception as e:
        logger.critical("Database schema initialization failed: %s", e, exc_info=True)
        raise e
    logger.debug("Exiting init_db function")


@click.command('init-db')
def init_db_command():
    logger.debug("Entered init_db_command function")
    try:
        init_db()
        click.echo('Initialized the database.')
        logger.info("Database initialized successfully via CLI command")
    except Exception as e:
        logger.critical("Failed to initialize the database via CLI command: %s", e, exc_info=True)
    logger.debug("Exiting init_db_command function")


sqlite3.register_converter(
    "timestamp", lambda v: datetime.fromisoformat(v.decode())
)

@click.command("create-moderator")
def init_create_moderator():
    """Usage flask create-moderator"""
    logger.debug("Entered create_moderator function")
    logger.info("Getting nickname, email, and password for new moderator")
    nickname = input("Enter nickname: ")
    email = input("Enter valid email: ")
    password = generate_password_hash(input("Enter password to be hashed: "))
    logger.info("Successfully obtained nickname, email, and password for new moderator")

    try:
        db = get_db()
        logger.info("Database connection obtained for new moderator")
        
        db.execute(
            "INSERT INTO user(nickname, email, password, jokebalance, userRole) VALUES (?, ?, ?, 0, 1)",
            (nickname, email, password),
        )
        db.commit()
        logger.info("Moderator with nickname %s successfully initialized", nickname)
    except sqlite3.IntegrityError as e:
        logger.warning("Initializion of new moderator failed: %e", e)
    db.close()
    logger.info("Moderator initialization db connection closed")
    logger.debug("Exited init_create_moderator function")

#register with the application
"""
app.teardown_appcontext() tells Flask to call that function when cleaning up after returning the response
app.cli.add_command() adds a new command that can be called with the flask command
"""
def init_app(app):
    logger.debug("Entered init_app function")
    try:
        logger.info("Registering teardown, CLI, and moderator commands for the app")
        app.teardown_appcontext(close_db)
        app.cli.add_command(init_db_command)
        app.cli.add_command(init_create_moderator)
        logger.info("Teardown, CLI, and moderator commands registered successfully")
    except Exception as e:
        logger.critical("Failed to initialize the app with teardown and CLI commands: %s", e, exc_info=True)
    logger.debug("Exiting init_app function")

@click.command("create-moderator")
def init_create_moderator():
    """Usage flask create-moderator"""
    logger.debug("Entered create_moderator function")
    logger.info("Getting nickname, email, and password for new moderator")
    nickname = input("Enter nickname: ")
    email = input("Enter valid email: ")
    password = generate_password_hash(input("Enter password to be hashed: "))
    logger.info("Successfully obtained nickname, email, and password for new moderator")

    try:
        db = get_db()
        logger.info("Database connection obtained for new moderator")
        
        db.execute(
            "INSERT INTO user(nickname, email, password, jokebalance, userRole) VALUES (?, ?, ?, 0, 1)",
            (nickname, email, password),
        )
        db.commit()
        logger.info("Moderator with nickname %s successfully initialized", nickname)
    except sqlite3.IntegrityError as e:
        logger.warning("Initializion of new moderator failed: %e", e)
    db.close()
    logger.info("Moderator initialization db connection closed")
    logger.debug("Exited init_create_moderator function")





