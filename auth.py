from passlib.context import CryptContext
from datetime import datetime, timezone
import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    if isinstance(password, bytes):
        password = password.decode('utf-8', errors='ignore')
    password = password[:72]
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_jwt(payload: dict, secret: str, algorithm: str, exp_delta) -> str:
    payload_copy = payload.copy()
    if "sub" in payload_copy and payload_copy["sub"] is not None:
        payload_copy["sub"] = str(payload_copy["sub"])
    payload_copy["exp"] = datetime.now(timezone.utc) + exp_delta
    return jwt.encode(payload_copy, secret, algorithm=algorithm)


def decode_jwt(token: str, secret: str, algorithms):
    return jwt.decode(token, secret, algorithms=algorithms)
