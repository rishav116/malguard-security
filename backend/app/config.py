import os
from typing import List, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class Settings(BaseSettings):
    APP_NAME: str = "MALGUARD AI — Malware Detection Engine"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", validation_alias="ENVIRONMENT")
    DEBUG: bool = Field(default=True, validation_alias="DEBUG")
    
    API_V1_PREFIX: str = "/api/v1"
    
    # CORS Configuration: comma-separated URLs or list
    CORS_ORIGINS: Union[str, List[str]] = Field(
        default=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://malguard-ai-amber.vercel.app",
        ],
        validation_alias="CORS_ORIGINS"
    )

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        default_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://malguard-ai-amber.vercel.app",
        ]
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                return default_origins
            if v_str == "*":
                return ["*"]
            import json
            if v_str.startswith("[") and v_str.endswith("]"):
                try:
                    parsed = json.loads(v_str)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in v_str.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return default_origins
    
    # Upload limits
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    ALLOWED_EXTENSIONS: Union[str, List[str]] = Field(
        default=[".exe", ".dll"],
        validation_alias="ALLOWED_EXTENSIONS"
    )

    @field_validator("ALLOWED_EXTENSIONS", mode="after")
    @classmethod
    def parse_allowed_extensions(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",") if ext.strip()]
        return v
    
    # Supabase Configuration for JWT Validation
    SUPABASE_URL: str = Field(default="", validation_alias="SUPABASE_URL")
    SUPABASE_ANON_KEY: str = Field(default="", validation_alias="SUPABASE_ANON_KEY")
    SUPABASE_JWT_SECRET: str = Field(default="", validation_alias="SUPABASE_JWT_SECRET")
    ALLOW_DEMO_AUTH: bool = Field(default=False, validation_alias="ALLOW_DEMO_AUTH")
    
    # Database Persistence Configuration (Phase 4C)
    REQUIRE_DB_PERSISTENCE: bool = Field(default=True, validation_alias="REQUIRE_DB_PERSISTENCE")
    ALLOW_IN_MEMORY_FALLBACK: bool = Field(default=False, validation_alias="ALLOW_IN_MEMORY_FALLBACK")
    
    # ClamAV Configuration
    CLAMAV_HOST: str = Field(default="127.0.0.1", validation_alias="CLAMAV_HOST")
    CLAMAV_PORT: int = Field(default=3310, validation_alias="CLAMAV_PORT")
    CLAMAV_TIMEOUT_SEC: float = Field(default=10.0, validation_alias="CLAMAV_TIMEOUT_SEC")
    CLAMAV_CLI_PATH: str = Field(default="clamscan", validation_alias="CLAMAV_CLI_PATH")
    
    # ML Model Configuration (Phase 4B placeholder)
    ML_MODEL_PATH: str = Field(default="app/ml/models/random_forest_v1.pkl", validation_alias="ML_MODEL_PATH")
    
    # Gemini AI Security Assistant Configuration (Phase 5)
    GEMINI_API_KEY: str = Field(default="", validation_alias="GEMINI_API_KEY")
    GEMINI_MODEL: str = Field(default="gemini-3.5-flash", validation_alias="GEMINI_MODEL")
    GEMINI_MAX_INPUT_CHARS: int = Field(default=2000, validation_alias="GEMINI_MAX_INPUT_CHARS")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
