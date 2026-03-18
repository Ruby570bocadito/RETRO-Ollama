"""Logging configuration for RETRO-Ollama."""

import logging
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from src.config import get_config
from pathlib import Path


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


CUSTOM_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "critical": "red bold reverse",
    "debug": "dim",
    "success": "green",
})


class PTailogger:
    """Custom logger for RETRO-Ollama with structured logging."""

    def __init__(
        self,
        name: str = "ptai",
        level: str = "INFO",
        log_file: Optional[Path] = None,
        use_rich: bool = True,
    ):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers.clear()
        self.console = Console(theme=CUSTOM_THEME)
        self.use_rich = use_rich
        config = get_config()
        default_log_file = Path(config.paths.audit_log) if hasattr(config.paths, 'audit_log') else Path("ptai.log")
        self.log_file = log_file or default_log_file

        self._setup_handlers()
        self._setup_extra_context()

    def _setup_handlers(self) -> None:
        """Setup logging handlers."""
        self.logger.propagate = False

        if self.use_rich:
            rich_handler = RichHandler(
                console=self.console,
                show_time=True,
                show_path=False,
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
            )
            self.logger.addHandler(rich_handler)

        file_handler = logging.FileHandler(
            self.log_file,
            mode="a",
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(name)-15s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

    def _setup_extra_context(self) -> None:
        """Setup extra context for logging."""
        self.extra: Dict[str, Any] = {
            "app_name": "RETRO-Ollama",
            "version": "2.0.0",
        }

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(message, extra={**self.extra, **kwargs})

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self.logger.info(message, extra={**self.extra, **kwargs})

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self.logger.warning(message, extra={**self.extra, **kwargs})

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self.logger.error(message, extra={**self.extra, **kwargs})

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(message, extra={**self.extra, **kwargs})

    def success(self, message: str, **kwargs: Any) -> None:
        """Log success message (custom level)."""
        self.logger.info(f"[green]✓[/green] {message}", extra={**self.extra, **kwargs})

    def scan_start(self, target: str, scan_type: str) -> None:
        """Log scan start."""
        self.info(f"Starting {scan_type} scan on {target}")

    def scan_complete(self, target: str, duration: float, findings: int) -> None:
        """Log scan completion."""
        self.success(f"Scan complete on {target} - {findings} findings in {duration:.2f}s")

    def tool_execution(self, tool: str, status: str) -> None:
        """Log tool execution."""
        level = logging.INFO if status == "success" else logging.ERROR
        self.logger.log(level, f"Tool '{tool}' execution: {status}")

    def error_with_context(
        self,
        error: Exception,
        context: Dict[str, Any],
    ) -> None:
        """Log error with additional context."""
        self.error(
            f"{type(error).__name__}: {str(error)}",
            context=context,
        )

    def audit(self, action: str, user: str = "system", **kwargs: Any) -> None:
        """Log audit event."""
        self.logger.info(
            f"AUDIT: {action} by {user}",
            extra={**self.extra, "audit": True, **kwargs},
        )


def get_logger(name: str = "ptai", level: str = "INFO") -> PTailogger:
    """Get or create a logger instance."""
    return PTailogger(name=name, level=level)


default_logger = get_logger()
