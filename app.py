from flask import Flask, request, jsonify
from functools import wraps
from models import db, User
from config import Config
from auth import hash_password, verify_password, create_jwt, decode_jwt
from markupsafe import escape
import os


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    _register_routes(app)

    return app


def _register_routes(app):
    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({
                "error": "Имя пользователя и пароль обязательны"
            }), 400

        user = User.query.filter_by(username=username).first()

        if not user or not verify_password(password, user.password_hash):
            return jsonify({
                "error": "Неверное имя пользователя или пароль"
            }), 401

        token_payload = {
            "sub": user.id,
            "username": user.username
        }
        token = create_jwt(
            payload=token_payload,
            secret=app.config["SECRET_KEY"],
            algorithm=app.config["JWT_ALGORITHM"],
            exp_delta=app.config["JWT_EXP_DELTA"]
        )

        return jsonify({
            "access_token": token,
            "token_type": "Bearer"
        })

    @app.route("/auth/register", methods=["POST"])
    def register():
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({
                "error": "Имя пользователя и пароль обязательны"
            }), 400

        if len(password) < 5:
            return jsonify({
                "error": "Пароль должен быть не менее 5 символов"
            }), 400

        if User.query.filter_by(username=username).first():
            return jsonify({
                "error": "Имя пользователя уже занято"
            }), 400

        password_hash = hash_password(password)
        new_user = User(username=username, password_hash=password_hash)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "Пользователь зарегистрирован",
            "user_id": new_user.id
        }), 201

    @app.route("/api/data", methods=["GET"])
    @require_auth(app)
    def get_data(auth_payload):
        users = User.query.all()
        users_data = []

        for user in users:
            user_info = {
                "id": user.id,
                "username": escape(user.username),
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
            users_data.append(user_info)

        return jsonify({
            "data": users_data,
            "total": len(users_data),
            "current_user": auth_payload.get("username")
        })


def require_auth(app_instance):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return jsonify({
                    "error": "Требуется авторизация",
                    "details": "Используйте заголовок: Authorization: Bearer <ваш_токен>"
                }), 401

            token = auth_header.split(" ", 1)[1].strip()

            if not token:
                return jsonify({
                    "error": "Токен не предоставлен"
                }), 401

            try:
                payload = decode_jwt(
                    token=token,
                    secret=app_instance.config["SECRET_KEY"],
                    algorithms=[app_instance.config["JWT_ALGORITHM"]]
                )

                if "sub" not in payload or "username" not in payload:
                    return jsonify({
                        "error": "Некорректный токен",
                        "details": "Отсутствуют обязательные поля"
                    }), 401

            except Exception as error:
                return jsonify({
                    "error": "Некорректный токен",
                    "details": str(error)
                }), 401

            return fn(auth_payload=payload, *args, **kwargs)

        return wrapper

    return decorator


def main():
    app = create_app()

    debug_mode = os.getenv("DEBUG_MODE", "false").lower() == "true"
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))

    app.run(
        debug=debug_mode,
        host=host,
        port=port
    )


if __name__ == "__main__":
    main()
