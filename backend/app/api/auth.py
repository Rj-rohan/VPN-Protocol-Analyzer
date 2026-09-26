from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.deps import client_ip, get_current_user, require_roles
from app.core.models import Role, User
from app.core.schemas import LoginRequest, TokenResponse, UserCreate, UserOut, UserUpdate
from app.core.security import create_access_token, hash_password, login_throttle, validate_password_strength, verify_password
from app.db.database import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])
# Verifying against a real hash keeps response time the same for unknown accounts.
_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    throttle_key = f"{email}|{client_ip(request)}"
    if login_throttle.is_locked(throttle_key):
        audit(db, "login", resource_type="user", resource_id=email, ip_address=client_ip(request), outcome="locked")
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again later.")
    user = db.scalar(select(User).where(User.email == email))
    valid = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not valid or not user.is_active:
        login_throttle.record_failure(throttle_key)
        audit(db, "login", user, resource_type="user", resource_id=email, ip_address=client_ip(request), outcome="failure")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password.")
    login_throttle.reset(throttle_key)
    user.last_login_at = datetime.now(timezone.utc)
    token, expires = create_access_token(user.id, user.role.value)
    audit(db, "login", user, resource_type="user", resource_id=user.id, ip_address=client_ip(request))
    db.commit()
    return TokenResponse(access_token=token, expires_at=expires, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(_: User = Depends(require_roles(Role.admin)), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, request: Request, admin: User = Depends(require_roles(Role.admin)), db: Session = Depends(get_db)) -> User:
    if problem := validate_password_strength(body.password):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email already exists.")
    user = User(email=email, full_name=body.full_name, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    audit(db, "user.create", admin, resource_type="user", resource_id=user.id, ip_address=client_ip(request), detail={"role": body.role.value})
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: UUID, body: UserUpdate, request: Request, admin: User = Depends(require_roles(Role.admin)), db: Session = Depends(get_db)) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    if user.id == admin.id and (body.is_active is False or (body.role and body.role != Role.admin)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Administrators cannot demote or deactivate themselves.")
    changes = {}
    if body.role is not None:
        user.role = body.role
        changes["role"] = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.password is not None:
        if problem := validate_password_strength(body.password):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
        user.password_hash = hash_password(body.password)
        changes["password"] = "changed"
    audit(db, "user.update", admin, resource_type="user", resource_id=user.id, ip_address=client_ip(request), detail=changes)
    db.commit()
    return user
