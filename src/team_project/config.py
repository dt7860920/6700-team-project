from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "ApartmentTest1"
    environment: str = "local"
    max_results_cap: int = 20
    log_level: str = "INFO"
    model_backend: str = "local"
    model_path: str = "./artifacts/model"
    model_device: str = "cpu"
    model_service_url: str | None = None
    model_service_api_key: SecretStr | None = None

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"local", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}, got {v!r}")
        return v

    @field_validator("model_backend")
    @classmethod
    def validate_model_backend(cls, value: str) -> str:
        allowed = {"local", "service"}
        if value not in allowed:
            raise ValueError(f"model_backend must be one of {allowed}, got {value!r}")
        return value

    @model_validator(mode="after")
    def validate_model_service_settings(self) -> "Settings":
        if self.model_backend == "service" and not self.model_service_url:
            raise ValueError(
                "model_service_url is required when model_backend='service'"
            )
        return self


settings = Settings()
