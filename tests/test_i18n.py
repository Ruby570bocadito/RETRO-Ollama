"""Tests for i18n module."""

import pytest
from src.i18n import (
    get_message,
    get_available_locales,
    init_i18n,
    MESSAGES,
)


class TestI18n:
    """Test internationalization."""

    def test_get_message_english(self):
        """Test getting message in English."""
        msg = get_message("app_title", "en")
        assert msg == "RETRO-Ollama"

    def test_get_message_spanish(self):
        """Test getting message in Spanish."""
        msg = get_message("app_title", "es")
        assert msg == "RETRO-Ollama"

    def test_get_message_portuguese(self):
        """Test getting message in Portuguese."""
        msg = get_message("app_title", "pt")
        assert msg == "RETRO-Ollama"

    def test_get_message_with_params(self):
        """Test message with parameters."""
        msg = get_message("connecting", "en", backend="Ollama")
        assert "Ollama" in msg

    def test_get_message_fallback(self):
        """Test fallback to default locale."""
        msg = get_message("app_title", "invalid_locale")
        assert msg == "RETRO-Ollama"

    def test_get_available_locales(self):
        """Test getting available locales."""
        locales = get_available_locales()
        assert isinstance(locales, list)

    def test_messages_exist(self):
        """Test that all messages exist."""
        assert "en" in MESSAGES
        assert "es" in MESSAGES
        assert "pt" in MESSAGES

    def test_init_i18n(self):
        """Test i18n initialization."""
        locale = init_i18n()
        assert locale is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
