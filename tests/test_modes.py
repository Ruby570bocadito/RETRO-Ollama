import pytest
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.modes.mode_manager import (
    get_current_mode,
    set_mode,
    get_mode_info,
    list_modes,
    get_all_modes_list,
    MODES
)


class TestModeManager:
    """Tests para el gestor de modos"""

    def test_all_modes_defined(self):
        """Verifica que todos los modos estén definidos"""
        expected_modes = [
            "pentester", "blue", "osint", "forense", 
            "bugbounty", "redteam", "vulnassessment", 
            "network", "webapp", "social"
        ]
        for mode in expected_modes:
            assert mode in MODES, f"Modo {mode} no está definido"

    def test_mode_structure(self):
        """Verifica estructura de cada modo"""
        for mode, info in MODES.items():
            assert "name" in info
            assert "color" in info
            assert "description" in info
            assert "icon" in info

    def test_get_mode_info_existing(self):
        """Obtener info de modo existente"""
        info = get_mode_info("pentester")
        assert info is not None
        assert info["name"] == "Pentester"

    def test_get_mode_info_nonexistent(self):
        """Obtener info de modo inexistente"""
        info = get_mode_info("nonexistent")
        assert info is None

    def test_list_modes(self):
        """Listar todos los modos"""
        modes = list_modes()
        assert isinstance(modes, dict)
        assert len(modes) >= 5

    def test_get_all_modes_list(self):
        """Obtener lista de modos"""
        modes = get_all_modes_list()
        assert isinstance(modes, list)
        assert "pentester" in modes
        assert "redteam" in modes

    @patch("builtins.open", create=True)
    @patch("os.path.exists")
    def test_get_current_mode_default(self, mock_exists, mock_open):
        """Modo por defecto cuando no hay archivo"""
        mock_exists.return_value = False
        mode = get_current_mode()
        assert mode == "pentester"

    @patch("builtins.open", create=True)
    @patch("json.load")
    @patch("os.path.exists")
    def test_get_current_mode_from_file(self, mock_exists, mock_json, mock_open):
        """Leer modo desde archivo"""
        mock_exists.return_value = True
        mock_json.return_value = {"mode": "osint"}
        
        mode = get_current_mode()
        assert mode == "osint"

    @patch("builtins.open", create=True)
    @patch("json.load")
    @patch("os.path.exists")
    def test_get_current_mode_invalid(self, mock_exists, mock_json, mock_open):
        """Modo inválido desde archivo"""
        mock_exists.return_value = True
        mock_json.return_value = {"mode": "invalid_mode"}
        
        mode = get_current_mode()
        assert mode == "pentester"

    @patch("builtins.open", create=True)
    @patch("os.path.exists")
    def test_set_mode_valid(self, mock_exists, mock_open):
        """Establecer modo válido"""
        mock_exists.return_value = True
        result = set_mode("osint")
        assert result is True

    @patch("builtins.open", create=True)
    @patch("os.path.exists")
    def test_set_mode_invalid(self, mock_exists, mock_open):
        """Establecer modo inválido"""
        mock_exists.return_value = True
        result = set_mode("invalid_mode")
        assert result is False


class TestModePrompts:
    """Tests para los prompts de modos"""

    def test_all_modes_have_prompts(self):
        """Verifica que todos los modos tengan prompts"""
        from src.modes.prompts import get_mode_prompt
        
        for mode in MODES.keys():
            prompt = get_mode_prompt(mode)
            assert prompt is not None
            assert len(prompt) > 0

    def test_pentester_prompt_content(self):
        """Verifica contenido del prompt pentester"""
        from src.modes.prompts import get_mode_prompt
        
        prompt = get_mode_prompt("pentester")
        assert "PENTESTER" in prompt
        assert "nmap" in prompt.lower()

    def test_redteam_prompt_content(self):
        """Verifica contenido del prompt redteam"""
        from src.modes.prompts import get_mode_prompt
        
        prompt = get_mode_prompt("redteam")
        assert "RED TEAM" in prompt.upper()
        assert "ATAQUE" in prompt.upper()

    def test_webapp_prompt_content(self):
        """Verifica contenido del prompt webapp"""
        from src.modes.prompts import get_mode_prompt
        
        prompt = get_mode_prompt("webapp")
        assert "OWASP" in prompt
        assert "Injection" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
