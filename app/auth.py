import bcrypt
from app.models import get_user_by_username, create_user


def hash_password(plain_password: str) -> str:
    salt   = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


def authenticate_user(db_path: str, username: str, password: str) -> bool:
    user = get_user_by_username(db_path, username)
    if not user:
        return False
    return verify_password(password, user["password"])


def register_user(db_path: str, username: str, password: str) -> None:
    password_hash = hash_password(password)
    create_user(db_path, username, password_hash)
