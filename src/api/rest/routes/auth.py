"""
src/api/rest/routes/auth.py
============================
Authentication routes for issuing OAuth2 JWT Bearer tokens to analysts and admins.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from src.logger import get_logger
from src.api.rest.middleware.auth import (
    DEMO_USERS,
    User,
    create_access_token,
    get_current_user,
    verify_password,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    roles: list[str]


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 standard login endpoint. Verifies username and password, returns signed JWT.
    """
    user_record = DEMO_USERS.get(form_data.username)
    if not user_record or not verify_password(form_data.password, user_record["password_hash"]):
        logger.warning("auth_login_failed", username=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    roles = user_record["roles"]
    access_token = create_access_token(data={"sub": form_data.username, "roles": roles})
    logger.info("auth_login_succeeded", username=form_data.username, roles=roles)

    return TokenResponse(
        access_token=access_token,
        username=form_data.username,
        roles=roles
    )


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Returns the profile and roles of the currently authenticated user.
    """
    return current_user
