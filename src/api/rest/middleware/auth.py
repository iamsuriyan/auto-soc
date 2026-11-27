"""
src/api/rest/middleware/auth.py
================================
OAuth2 / JWT Bearer Authentication and Role-Based Access Control (RBAC).
Provides token issuance, validation, and route dependency injection.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Annotated, Dict, List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import BaseModel

from src.logger import get_logger
from src.config import settings

logger = get_logger(__name__)

# Reusable OAuth2 scheme pointing to login route
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

JWT_ALGORITHM = "HS256"
# Ensure key meets HMAC-SHA256 minimum length (32 bytes)
_raw_secret = settings.jwt_secret_key.encode()
JWT_SECRET = _raw_secret if len(_raw_secret) >= 32 else hashlib.sha256(_raw_secret).digest()


class TokenPayload(BaseModel):
    sub: str                    # Username / Subject
    roles: List[str]            # e.g. ["analyst"], ["admin"]
    exp: datetime               # Expiration timestamp


class User(BaseModel):
    username: str
    roles: List[str]
    is_active: bool = True


# Pre-configured demo accounts for SOC Analysts & Admins
DEMO_USERS: Dict[str, Dict] = {
    "analyst": {
        "password_hash": hashlib.sha256("analyst123".encode()).hexdigest(),
        "roles": ["analyst"],
    },
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "roles": ["admin", "analyst"],
    },
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored SHA256 hex digest."""
    candidate_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return hmac.compare_digest(candidate_hash, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Encodes claims into a signed JWT.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes))
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """
    FastAPI dependency that extracts and validates the Bearer JWT token from the Authorization header.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        roles: List[str] = payload.get("roles", [])
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError as e:
        logger.warning("jwt_validation_failed", error=str(e))
        raise credentials_exception

    return User(username=username, roles=roles)


def require_role(required_role: str):
    """
    Role-Based Access Control (RBAC) dependency factory.
    Example: Depends(require_role("admin"))
    """
    async def role_checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if required_role not in current_user.roles:
            logger.warning(
                "insufficient_permissions",
                user=current_user.username,
                required=required_role,
                actual=current_user.roles
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires '{required_role}' role"
            )
        return current_user

    return role_checker
