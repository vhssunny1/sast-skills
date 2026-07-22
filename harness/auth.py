from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

import config

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


# Store hashed password at startup — avoids rehashing on every request
_HASHED_PASSWORD = hash_password(config.HARNESS_PASSWORD)


def authenticate(username: str, password: str) -> bool:
    return (
        username == config.HARNESS_USERNAME
        and verify_password(password, _HASHED_PASSWORD)
    )


def create_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=config.JWT_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": username, "exp": expire},
        config.JWT_SECRET,
        algorithm=config.JWT_ALGORITHM,
    )


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_error
        return username
    except JWTError:
        raise credentials_error
