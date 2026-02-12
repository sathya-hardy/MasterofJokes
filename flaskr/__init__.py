import os

from flask import Flask
import logging
from .error_register import handle_error

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


def create_app(test_config=None):
    logger.info("Starting the Flask application")
    logger.debug("Entered create_app function")
    
    #create and configure the app
    app = Flask(__name__, instance_relative_config=True) #creates the Flask instance. __name__ is the name of the current python module.
    #the app needs to know where its set up some paths, and __name__ is a convenient way to tell it that. instance_relative_config=True
    #tells the app that configuration files are relative to the instance folder. The instance folder is located outside the flaskr package
    #and can hold local data that shouldn't be committed to version control, such as config secrets and the database file
    logger.info("Flask application instance created with instance_relative_config=True")
    # app.logger.setLevel(logging.DEBUG)
    app.config.from_mapping( #sets some default configuration that the app will use. 
        SECRET_KEY='dev', #SECRET_KEY is used by Flask and extensions to keep data safe. Its set to dev to provide a convenient value
        #during development, but it should be overridden with a random value when deploying
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'), #DATABASE is the path where the SQLite database file will be saved. Its
        #under app.instance_path, which is the path that Flask has chosen for the instance folder
    )
    logger.info("Application default configuration loaded: SECRET_KEY and DATABASE path set")

    if test_config is None:
        #load the instance config, if it exists, when not testing
        try:
            app.config.from_pyfile('config.py', silent=True) #app.config.from_pyfile() overrides the default configuration with values taken
            #from the config.py file in the instance folder if it exists. For example, when deploying, this can be used to set a real SECRET_KEY
            logger.info("Loaded instance configuration from config.py (if exists)")
        except Exception as e:
            logger.warning("Failed to load instance configuration from config.py: %s", e, exc_info=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)#test config can also be passed to the factory, and will be used instead of the instance config.
        #This is so the tests that we'll write later can be configured independently of any dev values we have configured 
        logger.info("Test configuration loaded from provided test_config")

    try:
        os.makedirs(app.instance_path) #os.makedirs() ensures that app.instance_path exists. Flask doesn't create the instance folder
        #automatically, but it needs to be created because your project will create the SQLite database file there
    except OSError:
        pass
    
    # a simple page that says hello
    @app.route('/hello') 

    def hello():
        logger.debug("Accessed /hello route")
        return 'Hello, World!'

    #Register with the application step in define and access the database
    from . import db
    logger.info("Initializing database with db.init_app()")
    db.init_app(app)

    #Create a Blueprint step
    from . import auth
    logger.info("Registering auth Blueprint")
    app.register_blueprint(auth.bp)

    from . import joke
    logger.info("Registering joke Blueprint")
    app.register_blueprint(joke.bp)
    app.add_url_rule('/', endpoint='takeAJoke')
    logger.info("Default route '/' registered to takeAJoke endpoint")

    handle_error(app)

    logger.debug("Exiting create_app function")
    logger.info("Flask application setup complete")
    
    return app
