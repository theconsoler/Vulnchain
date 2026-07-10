import os
from pathlib import Path
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def create_app(test_config: dict = None) -> Flask:
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    app.config.update(
        SECRET_KEY     = os.environ["SECRET_KEY"],
        JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"],
        JWT_TOKEN_LOCATION       = ["cookies"],
        JWT_COOKIE_SECURE        = False,
        JWT_COOKIE_HTTPONLY      = True,
        JWT_ACCESS_TOKEN_EXPIRES = 86400,
        JWT_COOKIE_CSRF_PROTECT  = False,
        MAX_CONTENT_LENGTH       = 50 * 1024 * 1024,
        UPLOAD_FOLDER            = str(Path(__file__).parent.parent / "uploads"),
        OUTPUT_FOLDER            = str(Path(__file__).parent.parent / "output"),
        DB_PATH                  = str(Path(__file__).parent.parent / "vulnchain.db"),
    )

    if test_config:
        app.config.update(test_config)

    JWTManager(app)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[],
        storage_uri="memory://",
    )
    app.extensions["limiter"] = limiter

    CORS(app)

    from app.models import init_db
    init_db(app.config["DB_PATH"])

    from app.routes import register_routes
    register_routes(app)

    return app
