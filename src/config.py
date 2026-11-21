"""
src/config.py — Centralised Application Configuration
======================================================
Built with pydantic-settings so ALL configuration comes from environment
variables (or a .env file). If a required value is missing or the wrong type,
the application raises a clear ValidationError at startup — not buried in a
runtime exception.

Pattern:
    from src.config import settings
    print(settings.redis_host)
"""

from functools import lru_cache

from pydantic import AnyUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """
    Master settings class that reads from environment variables.
    
    pydantic-settings automatically:
      1. Reads from a `.env` file (via model_config below).
      2. Overrides with actual environment variables if they exist.
      3. Validates types — e.g. if REDIS_PORT="abc", it raises immediately.
    """

    model_config = SettingsConfigDict(
        # Read from .env file at project root
        env_file=".env",
        env_file_encoding="utf-8",
        # Don't crash on extra env vars from the shell
        extra="ignore",
        # Field names are case-insensitive (REDIS_HOST == redis_host)
        case_sensitive=False,
    )

    # --- Application ---
    app_env: str = Field(default="development", description="Runtime environment")
    app_secret_key: str = Field(..., description="Application secret key")
    log_level: str = Field(default="INFO")

    # --- Redis ---
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_password: str = Field(default="")
    redis_db: int = Field(default=0)

    # --- RabbitMQ ---
    rabbitmq_host: str = Field(default="localhost")
    rabbitmq_port: int = Field(default=5672)
    rabbitmq_user: str = Field(default="guest")
    rabbitmq_password: str = Field(default="guest")
    rabbitmq_vhost: str = Field(default="/")

    # --- Qdrant ---
    qdrant_host: str = Field(default="localhost")
    qdrant_port: int = Field(default=6333)
    qdrant_collection_name: str = Field(default="autosoc_knowledge")

    # --- Phoenix (LLM Observability) ---
    phoenix_host: str = Field(default="localhost")
    phoenix_port: int = Field(default=6006)

    # --- FastAPI ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    jwt_secret_key: str = Field(default="change-me-jwt-secret")
    jwt_algorithm: str = Field(default="RS256")
    jwt_access_token_expire_minutes: int = Field(default=60)

    # --- gRPC ---
    grpc_host: str = Field(default="0.0.0.0")
    grpc_port: int = Field(default=50051)
    grpc_tls_cert_path: str = Field(default="certs/server.crt")
    grpc_tls_key_path: str = Field(default="certs/server.key")
    grpc_ca_cert_path: str = Field(default="certs/ca.crt")

    # --- LLM ---
    openai_api_key: str = Field(default="")
    openai_model: str = Field(default="gpt-4o")

    # --- Guardrail Thresholds ---
    injection_score_threshold: float = Field(default=0.85)
    nli_faithfulness_threshold: float = Field(default=0.95)
    crag_relevance_threshold: float = Field(default=0.80)
    semantic_cache_similarity_threshold: float = Field(default=0.94)

    # -------------------------------------------------------------------------
    # Computed Connection String Properties
    # These derive convenient DSN strings from individual fields above.
    # -------------------------------------------------------------------------

    @property
    def redis_url(self) -> str:
        """
        Redis URL for redis-py async client.
        Format: redis://:password@host:port/db
        If no password is set, omit the auth section.
        """
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def rabbitmq_url(self) -> str:
        """
        AMQP URL for aio-pika (async RabbitMQ client).
        Format: amqp://user:pass@host:port/vhost
        """
        vhost = self.rabbitmq_vhost.lstrip("/") or "%2F"
        return (
            f"amqp://{self.rabbitmq_user}:{self.rabbitmq_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/{vhost}"
        )

    @property
    def phoenix_otlp_endpoint(self) -> str:
        """
        OpenTelemetry OTLP endpoint pointing at the local Phoenix instance.
        Spans are sent here via gRPC.
        """
        return f"http://{self.phoenix_host}:4317"

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"app_env must be one of {allowed}, got '{v}'")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v

    @field_validator("injection_score_threshold", "nli_faithfulness_threshold",
                     "crag_relevance_threshold", "semantic_cache_similarity_threshold")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("All threshold values must be between 0.0 and 1.0")
        return v


# ============================================================================
# Module-level singleton — imported everywhere as `from src.config import settings`
#
# @lru_cache ensures we parse .env ONCE per process, not on every import.
# ============================================================================

@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()


settings: AppSettings = get_settings()
