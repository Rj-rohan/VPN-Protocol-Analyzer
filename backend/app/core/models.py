from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, Enum as SqlEnum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Role(str, Enum):
    admin = "admin"        # manages users, sees every capture
    analyst = "analyst"    # uploads captures, sees own analyses, generates reports
    viewer = "viewer"      # read-only access to all analyses (auditors, managers)


class AnalysisStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ReportKind(str, Enum):
    executive = "executive"
    technical = "technical"


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[Role] = mapped_column(SqlEnum(Role), default=Role.analyst)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    owner_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    file_format: Mapped[str] = mapped_column(String(16), default="pcap")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped[User | None] = relationship()
    analyses: Mapped[list[Analysis]] = relationship(back_populates="capture", cascade="all, delete-orphan")


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    capture_id: Mapped[UUID] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    status: Mapped[AnalysisStatus] = mapped_column(SqlEnum(AnalysisStatus), default=AnalysisStatus.queued, index=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    detected_protocols: Mapped[list] = mapped_column(JSON, default=list)
    ipsec_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    predicted_traffic: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tshark_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    capture: Mapped[Capture] = relationship(back_populates="analyses")
    configuration: Mapped[IpsecConfiguration | None] = relationship(back_populates="analysis", cascade="all, delete-orphan", uselist=False)
    findings: Mapped[list[SecurityFindingRecord]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    predictions: Mapped[list[TrafficPrediction]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    reports: Mapped[list[Report]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class IpsecConfiguration(Base):
    """Flattened parser output for querying; `observations` keeps source and evidence per field."""

    __tablename__ = "ipsec_configurations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), unique=True)
    ipsec_protocol: Mapped[str] = mapped_column(String(64))
    ike_version: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(64))
    ip_version: Mapped[str] = mapped_column(String(64))
    encryption_algorithm: Mapped[str] = mapped_column(String(128))
    integrity_algorithm: Mapped[str] = mapped_column(String(128))
    prf_algorithm: Mapped[str] = mapped_column(String(128))
    authentication_method: Mapped[str] = mapped_column(String(128))
    dh_group: Mapped[str] = mapped_column(String(128))
    pfs: Mapped[str] = mapped_column(String(64))
    sa_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    nat_traversal: Mapped[str] = mapped_column(String(64))
    replay_protection: Mapped[str] = mapped_column(String(64))
    observations: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped[Analysis] = relationship(back_populates="configuration")


class TrafficPrediction(Base):
    __tablename__ = "traffic_predictions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    model_name: Mapped[str] = mapped_column(String(64))
    model_version: Mapped[str] = mapped_column(String(64))
    predicted_label: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    probabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped[Analysis] = relationship(back_populates="predictions")


class SecurityFindingRecord(Base):
    __tablename__ = "security_findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    condition: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32))

    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    kind: Mapped[ReportKind] = mapped_column(SqlEnum(ReportKind))
    stored_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    narrative_source: Mapped[str] = mapped_column(String(128))
    generated_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped[Analysis] = relationship(back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
