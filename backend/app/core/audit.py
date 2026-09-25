import logging

from sqlalchemy.orm import Session

from app.core.models import AuditLog, User

logger = logging.getLogger("ipsec_analyzer.audit")


def audit(
    db: Session, action: str, user: User | None = None, *, resource_type: str | None = None, resource_id: object = None,
    ip_address: str | None = None, outcome: str = "success", detail: dict | None = None,
) -> None:
    """Record a security-relevant action. The caller commits the session."""
    db.add(AuditLog(
        user_id=user.id if user else None, action=action, resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None, ip_address=ip_address,
        outcome=outcome, detail=detail or {},
    ))
    logger.info("audit action=%s user=%s resource=%s:%s outcome=%s", action, user.email if user else "-", resource_type, resource_id, outcome)
