"""Application factory for the MasterofJokes Flask app."""

import os
import logging

from flask import Flask
from .error_register import handle_error

# Configure logging once at the module level for the entire application.
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("moj.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def set_log_level(level):
    """Dynamically change the logging level for all loggers and handlers."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        logger.warning("Invalid log level: %s", level)
        return
    root = logging.getLogger()
    root.setLevel(numeric_level)
    for handler in root.handlers:
        handler.setLevel(numeric_level)
    logger.info("Log level changed to %s", level)


def create_app(test_config=None):
    """Create and configure the Flask application instance."""
    app = Flask(__name__, instance_relative_config=True)

    # Default config; SECRET_KEY should be overridden in production via instance/config.py
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists for the SQLite database file
    os.makedirs(app.instance_path, exist_ok=True)

    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    # Register database lifecycle hooks and CLI commands
    from . import db
    db.init_app(app)

    # Register blueprints
    from . import auth
    app.register_blueprint(auth.bp)

    from . import joke
    app.register_blueprint(joke.bp)
    app.add_url_rule('/', endpoint='takeAJoke')

    # Register global error handlers
    handle_error(app)

    logger.info("Flask application initialized")
    return app
