from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "VextHub API"
    environment: str = "development"
    database_url: str = Field(default="postgresql://vexthub:vexthub@localhost:5432/vexthub")
    redis_url: str = Field(default="redis://localhost:6379/0")
    app_base_url: str = "http://localhost:3000"
    jwt_audience: str = "vexthub"
    api_internal_token: str = ""
    webhook_signing_secret: str = ""
    cors_origins: List[str] = ["http://localhost:3000"]
    rate_limit_per_minute: int = 120
    plugin_container_network: str = "none"
    agent_shared_secret: str = Field(default="", validation_alias="AGENT_SHARED_SECRET")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
