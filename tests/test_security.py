import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.security import validate_command, sanitize_target


class TestValidateCommand:
    """Tests para la validación de comandos mejorada"""

    def test_valid_simple_commands(self):
        """Comandos simples válidos"""
        assert validate_command("nmap -sV 192.168.1.1")[0] is True
        assert validate_command("python script.py")[0] is True
        assert validate_command("ls -la")[0] is True
        assert validate_command("ping 8.8.8.8")[0] is True

    def test_command_chaining(self):
        """Detección de encadenamiento de comandos"""
        is_valid, error = validate_command("nmap && rm -rf")
        assert is_valid is False
        assert "Command chaining" in error

    def test_or_chaining(self):
        """Detección de OR chaining"""
        is_valid, error = validate_command("cat file || whoami")
        assert is_valid is False
        assert "OR chaining" in error

    def test_command_separator(self):
        """Detección de separador de comandos"""
        is_valid, error = validate_command("ls; rm -rf")
        assert is_valid is False
        assert "Command separator" in error

    def test_backtick_substitution(self):
        """Detección de sustitución con backticks"""
        is_valid, error = validate_command("echo `whoami`")
        assert is_valid is False
        assert "Command substitution" in error

    def test_dollar_substitution(self):
        """Detección de sustitución con $()"""
        is_valid, error = validate_command("echo $(whoami)")
        assert is_valid is False

    def test_variable_expansion(self):
        """Detección de expansión de variables"""
        is_valid, error = validate_command("echo ${HOME}")
        assert is_valid is False
        assert "Variable expansion" in error

    def test_pipe_to_shell(self):
        """Detección de pipe a shell"""
        is_valid, error = validate_command("cat file | sh")
        assert is_valid is False
        assert "pipe to shell" in error.lower()

    def test_pipe_to_bash(self):
        """Detección de pipe a bash"""
        is_valid, error = validate_command("cat file | bash")
        assert is_valid is False

    def test_sudo_rm(self):
        """Detección de sudo rm peligroso"""
        is_valid, error = validate_command("sudo rm -rf /")
        assert is_valid is False
        assert "sudo rm" in error.lower()

    def test_recursive_delete(self):
        """Detección de delete recursivo"""
        is_valid, error = validate_command("rm -rf /var/logs")
        assert is_valid is False

    def test_mkfs_dangerous(self):
        """Detección de formateo de filesystem"""
        is_valid, error = validate_command("mkfs /dev/sda1")
        assert is_valid is False
        assert "Filesystem" in error

    def test_dd_direct_disk(self):
        """Detección de acceso directo a disco"""
        is_valid, error = validate_command("dd if=/dev/zero of=/dev/sda")
        assert is_valid is False
        assert "Direct disk" in error

    def test_empty_command(self):
        """Comando vacío"""
        is_valid, error = validate_command("")
        assert is_valid is False
        assert "Empty" in error

    def test_whitespace_command(self):
        """Comando solo con espacios"""
        is_valid, error = validate_command("   ")
        assert is_valid is False


class TestSanitizeTarget:
    """Tests para sanitización de targets"""

    def test_valid_ipv4(self):
        """IPs válidas"""
        assert sanitize_target("192.168.1.1") == "192.168.1.1"
        assert sanitize_target("10.0.0.1") == "10.0.0.1"
        assert sanitize_target("172.16.0.1") == "172.16.0.1"

    def test_valid_domain(self):
        """Dominios válidos"""
        assert sanitize_target("example.com") == "example.com"
        assert sanitize_target("sub.example.com") == "sub.example.com"

    def test_invalid_ip_octets(self):
        """IPs con octetos inválidos"""
        assert sanitize_target("256.1.1.1") is None
        assert sanitize_target("1.1.1.999") is None

    def test_malicious_input(self):
        """Input malicioso"""
        assert sanitize_target("; rm -rf /") is None
        assert sanitize_target("$(whoami)") is None
        assert sanitize_target("`ls`") is None

    def test_empty_input(self):
        """Input vacío"""
        assert sanitize_target("") is None
        assert sanitize_target(None) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
