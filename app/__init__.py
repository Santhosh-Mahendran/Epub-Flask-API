from flask import Flask
from .config import Config
from .extensions import db, jwt, migrate, limiter, cors
from .routes import auth, files_bp, book_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    cors.init_app(app)

    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(book_bp, url_prefix='/book')
    app.register_blueprint(files_bp, url_prefix='/files')

    return app
