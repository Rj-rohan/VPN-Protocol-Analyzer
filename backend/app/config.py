import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    app_name: str = "IPsec Analyzer"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://ipsec:ipsec@localhost:5432/ipsec_analyzer"

    # Capture storage and validation
    storage_dir: Path = Path("./storage/pcaps")
    report_dir: Path = Path("./storage/reports")
    max_upload_size_bytes: int = 100 * 1024 * 1024
    allowed_extensions: str = ".pcap,.pcapng,.cap"

    # TShark
    tshark_path: str = "tshark"
    tshark_timeout_seconds: int = 120

    # Live capture (dumpcap). DUMPCAP_PATH defaults to the dumpcap next to TShark.
    dumpcap_path: str = ""
    live_capture_roles: str = "admin"
    live_capture_max_seconds: int = 300
    live_capture_max_megabytes: int = 100
    live_snapshot_interval_seconds: int = 5

    # Extra folder of compliance profile JSON files (built-in profiles are always loaded)
    compliance_profile_dir: str = ""
    default_compliance_profile: str = "nist-sp-800-77r1"

    # Analysis worker: "background" runs analyses off the request thread; "inline" runs them synchronously (tests).
    analysis_execution: str = "background"
    analysis_workers: int = 2

    # Authentication. Set JWT_SECRET in production; a random per-process secret is used otherwise.
    jwt_secret: str = ""
    jwt_expiry_minutes: int = 480
    admin_email: str = ""
    admin_password: str = ""
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Directory holding traffic classifier artifacts produced by `python -m app.ml.train`
    model_dir: Path = REPO_DIR / "data" / "models"

    # Optional LLM explanation layer (structured JSON in, narrative out)
    anthropic_api_key: str = ""
    llm_model: str = "claude-opus-5"
    llm_enabled: bool = True

    cors_origins: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_extension_set(self) -> set[str]:
        return {ext.strip().lower() for ext in self.allowed_extensions.split(",") if ext.strip()}

    @property
    def effective_jwt_secret(self) -> str:
        return self.jwt_secret or _EPHEMERAL_SECRET


_EPHEMERAL_SECRET = secrets.token_urlsafe(48)
settings = Settings()
