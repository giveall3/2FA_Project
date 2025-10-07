# app/__init__.py
from flask import Flask
from .db import init_db
# blueprints for account management
from .auth_routes import auth_bp
from .account_routes import account_bp

def create_app(config_object) -> Flask:
    app = Flask(__name__)                      # make app
    app.config.from_object(config_object)      # load config
    init_db(app)
    app.register_blueprint(auth_bp)            # where auth
    app.register_blueprint(account_bp)         # where acc
    return app                                 # sends back ready app
