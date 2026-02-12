"""Global error handlers for the Flask application."""

import logging
from flask import request

logger = logging.getLogger(__name__)


def handle_error(app):
    """Register error handlers that log critical failures to moj.log."""

    @app.errorhandler(500)
    def handle_500_error(error):
        logger.critical("HTTP 500 at %s: %s", request.path, error, exc_info=True)
        return "An internal server error occurred.", 500

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        logger.critical("Unhandled exception at %s: %s", request.path, error, exc_info=True)
        return "An unexpected error occurred.", 500

    @app.teardown_request
    def teardown_request(exception=None):
        if exception:
            logger.critical("Exception during teardown at %s: %s", request.path, exception, exc_info=True)
