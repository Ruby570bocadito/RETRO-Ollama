from pydantic import Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List, Dict, Any
import os
from pathlib import Path
import yaml
import threading
from datetime import datetime


class APIKeys(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='')

    shodan: Optional[str] = Field(default="", alias="SHODAN_API_KEY")
    virustotal: Optional[str] = Field(default="", alias="VIRUSTOTAL_API_KEY")
    hunter: Optional[str] = Field(default="", alias="HUNTER_API_KEY")
    censys: Optional[str] = Field(default="", alias="CENSYS_API_KEY")
    securitytrails: Optional[str] = Field(default="", alias="SECURITYTRAILS_API_KEY")

    def is_configured(self, service: str) -> bool:
        return bool(getattr(self, service, ""))

    def get_missing(self) -> List[str]:
        missing = []
        for field in ["shodan", "virustotal", "hunter", "censys", "securitytrails"]:
            if not getattr(self, field):
                missing.append(field.upper())
        return missing


class OllamaConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='OLLAMA_')

    host: str = Field(default="http://localhost:11434")
    default_model: str = Field(default="llama3.2")
    timeout: int = Field(default=120)
    max_retries: int = Field(default=3)

    @property
    def base_url(self) -> str:
        return f"{self.host}/api"


class PathsConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='')

    reports_dir: str = Field(default="reports", alias="REPORTS_DIR")
    scans_dir: str = Field(default="scans", alias="SCANS_DIR")
    output_dir: str = Field(default="output", alias="OUTPUT_DIR")
    audit_log: str = Field(default="audit.log", alias="AUDIT_LOG")


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='PTAI_')

    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    api_keys: APIKeys = Field(default_factory=APIKeys)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    debug: bool = Field(default=False, alias="DEBUG")
    environment: str = Field(default="development", alias="ENVIRONMENT")


class ConfigManager:
    """Manages application configuration with environment support and hot-reloading"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._config = None
                    cls._instance._config_path = None
                    cls._instance._last_modified = None
        return cls._instance
    
    def load_config(self, config_path: Optional[str] = None, environment: Optional[str] = None) -> AppConfig:
        """Load configuration from file and environment variables"""
        # Determine config file path
        if config_path is None:
            # Look for config.yaml in standard locations
            base_dir = Path(__file__).parent.parent
            config_file = base_dir / "config.yaml"
            if not config_file.exists():
                config_file = base_dir / "config.yml"
            if not config_file.exists():
                # Fall back to environment-only config
                return AppConfig()
            config_path = str(config_file)
        
        # Check if file has been modified (for hot-reload)
        path_obj = Path(config_path)
        if path_obj.exists():
            current_modified = path_obj.stat().st_mtime
            if (self._config_path == config_path and 
                self._last_modified == current_modified and 
                self._config is not None):
                return self._config
        
        # Load configuration
        config_data = {}
        if path_obj.exists():
            try:
                with open(path_obj, 'r') as f:
                    if path_obj.suffix in ['.yaml', '.yml']:
                        config_data = yaml.safe_load(f) or {}
                    else:
                        # Try JSON as fallback
                        import json
                        config_data = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load config file {config_path}: {e}")
                config_data = {}
        
        # Override with environment-specific settings
        env = environment or os.getenv("ENVIRONMENT", "development")
        if isinstance(config_data, dict) and env in config_data:
            env_config = config_data[env]
            if isinstance(env_config, dict):
                config_data.update(env_config)
        
        # Create config object
        try:
            # BaseSettings will automatically load env vars, but we need to pass yaml data
            # Note: This logic might need adjustment if pydantic-settings overrides yaml data with env vars
            # For now, we prioritize yaml data if present, but env vars override defaults
            # If pydantic-settings is used, it might override yaml data with env vars.
            # To support both, we can instantiate with yaml data and let validators handle env vars if needed.
            # However, pydantic-settings v2 handles env vars automatically.
            # We'll instantiate with the yaml data. If env vars are set, they will be picked up by BaseSettings
            # only if the field value is not provided (or defaults are used).
            # Since we pass **config_data, explicit values from yaml are used.
            # This is fine for now.
            config = AppConfig(**config_data)
            
            # Ensure environment is set (BaseSettings might load it from env, but we force it from context)
            config.environment = env
            self._config = config
            self._config_path = config_path
            self._last_modified = path_obj.stat().st_mtime if path_obj.exists() else None
            return config
        except Exception as e:
            print(f"Error creating config object: {e}")
            # Fall back to environment-only config
            return AppConfig()
    
    def get_config(self) -> AppConfig:
        """Get current configuration, loading if necessary"""
        if self._config is None:
            return self.load_config()
        return self._config
    
    def reload_config(self) -> AppConfig:
        """Force reload of configuration"""
        self._config = None
        self._last_modified = None
        return self.get_config()
    
    def is_debug(self) -> bool:
        """Check if debug mode is enabled"""
        config = self.get_config()
        return config.debug
    
    def get_environment(self) -> str:
        """Get current environment"""
        config = self.get_config()
        return config.environment


# Global config manager instance
_config_manager = ConfigManager()


def get_config() -> AppConfig:
    """Get application configuration"""
    return _config_manager.get_config()


def reload_config() -> AppConfig:
    """Reload application configuration"""
    return _config_manager.reload_config()


def init_config(config_path: Optional[str] = None, environment: Optional[str] = None) -> AppConfig:
    """Initialize configuration with specific path and environment"""
    return _config_manager.load_config(config_path, environment)


def is_debug() -> bool:
    """Check if debug mode is enabled"""
    return _config_manager.is_debug()


def get_environment() -> str:
    """Get current environment"""
    return _config_manager.get_environment()
