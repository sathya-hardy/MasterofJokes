import logging
import os
from flask import request
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=log_level, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
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
def handle_error(app):
    """Register global error handlers to log non-recoverable exceptions."""
    
    @app.errorhandler(500)
    def handle_500_error(error):
        """Handle HTTP 500 Internal Server Error."""
        logger.critical("HTTP 500 Internal Server Error occurred at %s. Error: %s", request.path, error, exc_info=True)
        return "An internal server error occurred.", 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        """Handle all uncaught exceptions (global catch-all)."""
        logger.critical("Unhandled exception in request to %s: %s", request.path, error, exc_info=True)
        return "An unexpected error occurred.", 500
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Log any unhandled exceptions that occur during the request."""
        if exception:
            logger.critical("Unhandled exception during request teardown for path %s: %s", request.path, exception, exc_info=True)
