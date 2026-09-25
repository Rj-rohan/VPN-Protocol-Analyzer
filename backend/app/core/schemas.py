from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import AnalysisStatus, ReportKind, Role


class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: str
    role: Role
    is_active: bool
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserOut


class UserCreate(BaseModel):
    email: str = Field(max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = Field(default="", max_length=255)
    password: str = Field(min_length=12, max_length=256)
    role: Role = Role.analyst


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class UploadResponse(BaseModel):
    analysis_id: UUID
    capture_id: UUID
    filename: str
    sha256: str
    size_bytes: int
    status: AnalysisStatus


class AnalysisSummary(BaseModel):
    analysis_id: str
    filename: str
    status: str
    packet_count: int
    detected_protocols: list[str]
    ipsec_detected: bool | None
    security_score: int | None
    risk_level: str | None
    predicted_traffic: str | None
    ike_version: str | None
    error: str | None
    created_at: str | None
    completed_at: str | None
    owner: str | None


class AnalysisList(BaseModel):
    items: list[AnalysisSummary]
    total: int
    limit: int
    offset: int


class AnalysisDetail(AnalysisSummary):
    capture: dict
    warnings: list[str]
    result: dict
    reports: list[ReportOut]


class ReportRequest(BaseModel):
    kind: ReportKind


class ReportOut(BaseModel):
    id: UUID
    kind: ReportKind
    size_bytes: int
    narrative_source: str
    created_at: datetime | None = None


AnalysisDetail.model_rebuild()
