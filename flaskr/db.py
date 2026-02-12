"""Database helpers: connection management, schema init, and CLI commands."""

import logging
import sqlite3
from datetime import datetime

import click
from flask import current_app, g
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

# Teach sqlite3 how to convert TIMESTAMP columns into Python datetime objects
sqlite3.register_converter(
    "timestamp", lambda v: datetime.fromisoformat(v.decode())
)


def get_db():
    """Return the request-scoped database connection, creating one if needed."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
        logger.debug("Opened new database connection")
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Drop and recreate all tables from schema.sql."""
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
    logger.info("Database schema initialized")


@click.command('init-db')
def init_db_command():
    """CLI: flask init-db  -- reinitialize the database."""
    init_db()
    click.echo('Initialized the database.')


@click.command("create-moderator")
def init_create_moderator():
    """CLI: flask create-moderator  -- interactively create a moderator account."""
    nickname = input("Enter nickname: ")
    email = input("Enter valid email: ")
    password = generate_password_hash(input("Enter password: "))

    try:
        db = get_db()
        db.execute(
            "INSERT INTO user(nickname, email, password, jokebalance, userRole)"
            " VALUES (?, ?, ?, 0, 1)",
            (nickname, email, password),
        )
        db.commit()
        click.echo(f'Moderator "{nickname}" created.')
        logger.info("Moderator created via CLI: %s", nickname)
    except sqlite3.IntegrityError:
        click.echo(f'Error: nickname "{nickname}" already exists.')
        logger.warning("create-moderator failed, duplicate nickname: %s", nickname)


def init_app(app):
    """Register database teardown and CLI commands with the Flask app."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(init_create_moderator)
