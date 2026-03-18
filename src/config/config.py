from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict
import os


class APIKeys(BaseModel):
    shodan: Optional[str] = Field(default="", alias="SHODAN_API_KEY")
    virustotal: Optional[str] = Field(default="", alias="VIRUSTOTAL_API_KEY")
    hunter: Optional[str] = Field(default="", alias="HUNTER_API_KEY")
    censys: Optional[str] = Field(default="", alias="CENSYS_API_KEY")
    securitytrails: Optional[str] = Field(default="", alias="SECURITYTRAILS_API_KEY")

    @field_validator("shodan", "virustotal", "hunter", "censys", "securitytrails", mode="before")
    @classmethod
    def get_from_env(cls, v: str, info) -> str:
        if v:
            return v
        env_key = info.alias or f"{info.field_name.upper()}_API_KEY"
        return os.getenv(env_key, "")

    def is_configured(self, service: str) -> bool:
        return bool(getattr(self, service, ""))

    def get_missing(self) -> List[str]:
        missing = []
        for field in ["shodan", "virustotal", "hunter", "censys", "securitytrails"]:
            if not getattr(self, field):
                missing.append(field.upper())
        return missing


class OllamaConfig(BaseModel):
    host: str = Field(default="http://localhost:11434")
    default_model: str = Field(default="llama3.2")
    timeout: int = Field(default=120)
    max_retries: int = Field(default=3)

    @property
    def base_url(self) -> str:
        return f"{self.host}/api"


class PathsConfig(BaseModel):
    reports_dir: str = "reports"
    scans_dir: str = "scans"
    output_dir: str = "output"
    audit_log: str = "audit.log"


class AppConfig(BaseModel):
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    api_keys: APIKeys = Field(default_factory=APIKeys)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    debug: bool = False


_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = AppConfig(
            ollama=OllamaConfig(
                host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
                default_model=os.getenv("DEFAULT_MODEL", "llama3.2"),
            ),
            api_keys=APIKeys(
                shodan=os.getenv("SHODAN_API_KEY", ""),
                virustotal=os.getenv("VIRUSTOTAL_API_KEY", ""),
                hunter=os.getenv("HUNTER_API_KEY", ""),
                censys=os.getenv("CENSYS_API_KEY", ""),
                securitytrails=os.getenv("SECURITYTRAILS_API_KEY", ""),
            ),
            paths=PathsConfig(),
            debug=os.getenv("DEBUG", "").lower() == "true",
        )
    return _config


def reload_config() -> AppConfig:
    global _config
    _config = None
    return get_config()
