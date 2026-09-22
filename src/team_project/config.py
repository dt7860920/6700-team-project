from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "ApartmentTest1"
    environment: str = "local"
    max_results_cap: int = 20
    log_level: str = "INFO"

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"local", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}, got {v!r}")
        return v


settings = Settings()
