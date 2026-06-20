from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "TruthLens API"
    database_url: str = Field("sqlite:///./truthlens.db", validation_alias="TRUTHLENS_DATABASE_URL")
    storage_dir: Path = Field(Path("./storage"), validation_alias="TRUTHLENS_STORAGE_DIR")
    allowed_origins: str = Field("http://localhost:3000", validation_alias="ALLOWED_ORIGINS")
    sightengine_api_user: str = Field("", validation_alias="SIGHTENGINE_API_USER")
    sightengine_api_secret: str = Field("", validation_alias="SIGHTENGINE_API_SECRET")
    reality_defender_api_key: str = Field("", validation_alias="REALITY_DEFENDER_API_KEY")
    auth_secret: str = Field("change-me-in-production", validation_alias="TRUTHLENS_AUTH_SECRET")
    google_client_id: str = Field("", validation_alias="GOOGLE_CLIENT_ID")
    admin_emails: str = Field("", validation_alias="TRUTHLENS_ADMIN_EMAILS")
    frontend_domain: str = Field("https://frontend-ruddy-chi-23.vercel.app/TruthLens", validation_alias="TRUTHLENS_FRONTEND_DOMAIN")
    vercel_project: str = Field("kalakonda-akshays-projects/frontend", validation_alias="TRUTHLENS_VERCEL_PROJECT")
    deployment_status: str = Field("Production", validation_alias="TRUTHLENS_DEPLOYMENT_STATUS")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def origins(self) -> list[str]:
        env_origins = self.allowed_origins or ""
        return [origin.strip() for origin in env_origins.split(",") if origin.strip()]

    @property
    def origin_regex(self) -> str:
        return r"https://.*\.vercel\.app|http://localhost:\d+"

    @property
    def administrators(self) -> set[str]:
        return {email.strip().lower() for email in self.admin_emails.split(",") if email.strip()}


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    (settings.storage_dir / "uploads").mkdir(parents=True, exist_ok=True)
    (settings.storage_dir / "frames").mkdir(parents=True, exist_ok=True)
    return settings
