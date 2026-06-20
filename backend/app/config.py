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


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    (settings.storage_dir / "uploads").mkdir(parents=True, exist_ok=True)
    (settings.storage_dir / "frames").mkdir(parents=True, exist_ok=True)
    return settings
