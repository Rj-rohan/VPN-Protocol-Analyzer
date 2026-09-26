from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.core.models import Base, Role, User
from app.core.security import hash_password, login_throttle
from app.db.database import get_db
from app.main import app
from app.worker import AnalysisQueue, set_queue

PASSWORD = "Correct-Horse-9-Battery"


class Api:
    """TestClient plus per-role bearer tokens."""

    def __init__(self, client: TestClient, session_factory):
        self.client = client
        self.Session = session_factory
        self.tokens: dict[str, str] = {}

    def login(self, email: str, password: str = PASSWORD):
        return self.client.post("/api/auth/login", json={"email": email, "password": password})

    def as_(self, role: str) -> dict:
        if role not in self.tokens:
            response = self.login(f"{role}@test.local")
            assert response.status_code == 200, response.text
            self.tokens[role] = response.json()["access_token"]
        return {"Authorization": f"Bearer {self.tokens[role]}"}

    def upload(self, role: str, content: bytes, filename: str = "capture.pcap"):
        return self.client.post("/api/captures/upload", files={"file": (filename, content)}, headers=self.as_(role))


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        for name, role in (("admin", Role.admin), ("analyst", Role.analyst), ("analyst2", Role.analyst), ("viewer", Role.viewer)):
            db.add(User(email=f"{name}@test.local", full_name=name, password_hash=hash_password(PASSWORD), role=role))
        db.commit()

    def session():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "storage_dir", tmp_path / "pcaps")
    monkeypatch.setattr(settings, "report_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    app.dependency_overrides[get_db] = session
    set_queue(AnalysisQueue(Session, mode="inline"))
    login_throttle._failures.clear()
    yield Api(TestClient(app), Session)
    app.dependency_overrides.clear()
    set_queue(None)
    login_throttle._failures.clear()
