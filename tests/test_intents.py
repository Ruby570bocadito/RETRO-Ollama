import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli_app import detect_intent


class TestIntentDetection:
    """Tests para detección de intenciones mejorada"""

    def test_greeting_variations(self):
        """Diferentes saludos"""
        greetings = ["hola", "hello", "hey", "hi", "buenas", "que tal", "holiwis"]
        for g in greetings:
            intent = detect_intent(g)
            assert intent["action"] == "greeting"

    def test_scan_intents(self):
        """Intents de escaneo"""
        test_cases = [
            ("escanea 192.168.1.1", "scan", "quick"),
            ("escaneo completo de google.com", "scan", "full"),
            ("busca vulnerabilidades en example.com", "scan", "vuln"),
            ("escaneo web de miweb.com", "scan", "web"),
            ("busca directorios en target.com", "scan", "dir"),
            ("detecta el SO de 10.0.0.1", "scan", "os"),
            ("escaneo stealth de 192.168.1.1", "scan", "stealth"),
            ("busca inyeccion SQL en site.com", "scan", "sqlmap"),
            ("enumera subdominios de example.com", "scan", "dns"),
        ]
        for text, expected_action, expected_tool in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action, f"Failed for: {text}"
            assert intent["tool"] == expected_tool, f"Failed for: {text}"

    def test_search_intents(self):
        """Intents de búsqueda"""
        test_cases = [
            ("busca exploits de apache", "search"),
            ("search nginx vulnerabilities", "search"),
            ("busca CVE de mysql", "search"),
            ("searchsploit wordpress", "search"),
        ]
        for text, expected_action in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action

    def test_autopwn_intents(self):
        """Intents de autopwn"""
        test_cases = [
            ("haz un pentest completo a 192.168.1.1", "autopwn"),
            ("autopwn 10.0.0.5", "autopwn"),
            ("pentest completo de target.com", "autopwn"),
            ("fullpentest 192.168.1.0/24", "autopwn"),
        ]
        for text, expected_action in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action

    def test_generate_intents(self):
        """Intents de generación"""
        test_cases = [
            ("genera reverse shell python", "generate", "shell"),
            ("crea payload meterpreter", "generate", "payload"),
            ("necesito un script de enumeracion", "generate", "script"),
            ("hazme una tool de automation", "generate", "tool"),
        ]
        for text, expected_action, expected_type in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action
            assert intent["params"].get("type") == expected_type

    def test_osint_intents(self):
        """Intents OSINT"""
        test_cases = [
            ("whois de example.com", "whois"),
            ("busca subdominios de target.com", "subdomain"),
            ("shodan de 8.8.8.8", "shodan"),
            ("virustotal example.com", "virustotal"),
            ("busca emails de empresa.com", "hunter"),
            ("certificados SSL de domain.com", "crt"),
        ]
        for text, expected_action in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action

    def test_system_intents(self):
        """Intents de información del sistema"""
        test_cases = [
            ("que procesos hay", "processes"),
            ("informacion de red", "network"),
            ("info del sistema", "system"),
            ("lista servicios", "services"),
            ("espacio en disco", "disk"),
        ]
        for text, expected_action in test_cases:
            intent = detect_intent(text)
            assert intent["action"] == expected_action

    def test_target_extraction(self):
        """Extracción de targets"""
        test_cases = [
            ("escanea 192.168.1.1", "192.168.1.1"),
            ("analiza google.com", "google.com"),
            ("ping 10.0.0.5", "10.0.0.5"),
        ]
        for text, expected_target in test_cases:
            intent = detect_intent(text)
            assert intent["target"] == expected_target


class TestPentestTools:
    """Tests para herramientas de pentesting"""

    def test_tools_defined(self):
        """Verifica que las herramientas estén definidas"""
        from src.tools.pentest import TOOLS
        assert len(TOOLS) > 30

    def test_tool_categories(self):
        """Categorías de herramientas"""
        from src.tools.pentest import TOOLS
        categories = set(tool.category for tool in TOOLS.values())
        assert "recon" in categories
        assert "scanning" in categories
        assert "exploitation" in categories

    def test_scan_functions_exist(self):
        """Funciones de escaneo existen"""
        from src.tools import pentest
        assert hasattr(pentest, 'quick_scan')
        assert hasattr(pentest, 'full_scan')
        assert hasattr(pentest, 'vuln_scan')
        assert hasattr(pentest, 'web_scan')
        assert hasattr(pentest, 'sql_injection_scan')
        assert hasattr(pentest, 'ssl_scan')
        assert hasattr(pentest, 'smb_enum')
        assert hasattr(pentest, 'cms_scan')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
