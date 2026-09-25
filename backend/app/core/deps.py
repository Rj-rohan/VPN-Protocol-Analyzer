from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.models import Analysis, Role, User
from app.core.security import decode_access_token
from app.db.database import get_db

bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    if credentials is None:
        raise unauthorized
    claims = decode_access_token(credentials.credentials)
    if not claims:
        raise unauthorized
    try:
        user = db.get(User, UUID(claims["sub"]))
    except ValueError:
        raise unauthorized
    if not user or not user.is_active:
        raise unauthorized
    return user


def require_roles(*roles: Role):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action.")
        return user

    return checker


def can_view(user: User, analysis: Analysis) -> bool:
    return user.role in (Role.admin, Role.viewer) or analysis.capture.owner_id == user.id


def can_modify(user: User, analysis: Analysis) -> bool:
    return user.role == Role.admin or (user.role == Role.analyst and analysis.capture.owner_id == user.id)


def get_visible_analysis(analysis_id: UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    # Not-found and not-permitted look identical so analysis IDs cannot be probed.
    if not analysis or not can_view(user, analysis):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found.")
    return analysis
