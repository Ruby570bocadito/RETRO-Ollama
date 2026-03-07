import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai.backends.multi_backend import (
    OllamaBackend, LlamaCppBackend, LMStudioBackend,
    MultiBackendClient, create_client
)
from src.cli_commands.parsers import extract_ip_or_domain, extract_ports, detect_intent


class TestMultiBackend:
    def test_ollama_backend_creation(self):
        backend = OllamaBackend()
        assert backend.host == "http://localhost:11434"
    
    def test_ollama_backend_custom_host(self):
        backend = OllamaBackend(host="http://192.168.1.100:11434")
        assert backend.host == "http://192.168.1.100:11434"
    
    def test_llamacpp_backend_creation(self):
        backend = LlamaCppBackend()
        assert backend.host == "http://localhost:8080"
    
    def test_lmstudio_backend_creation(self):
        backend = LMStudioBackend()
        assert backend.host == "http://localhost:1234/v1"
    
    def test_multi_backend_client_creation(self):
        client = MultiBackendClient("ollama")
        assert client.backend_name == "ollama"
    
    def test_multi_backend_get_available_backends(self):
        backends = MultiBackendClient.get_available_backends()
        assert "ollama" in backends
        assert "llamacpp" in backends
        assert "lmstudio" in backends
    
    def test_create_client_ollama(self):
        client = create_client("ollama")
        assert isinstance(client.backend, OllamaBackend)
    
    def test_create_client_llamacpp(self):
        client = create_client("llamacpp")
        assert isinstance(client.backend, LlamaCppBackend)
    
    def test_create_client_lmstudio(self):
        client = create_client("lmstudio")
        assert isinstance(client.backend, LMStudioBackend)


class TestParsers:
    def test_extract_ip(self):
        assert extract_ip_or_domain("192.168.1.1") == "192.168.1.1"
        assert extract_ip_or_domain("10.0.0.1") == "10.0.0.1"
        assert extract_ip_or_domain("8.8.8.8") == "8.8.8.8"
    
    def test_extract_domain(self):
        assert extract_ip_or_domain("example.com") == "example.com"
        assert extract_ip_or_domain("google.com") == "google.com"
        assert extract_ip_or_domain("sub.domain.com") == "sub.domain.com"
    
    def test_extract_ip_from_text(self):
        assert extract_ip_or_domain("escanea 192.168.1.1") == "192.168.1.1"
        assert extract_ip_or_domain("target 10.0.0.5:8080") == "10.0.0.5"
    
    def test_extract_domain_from_text(self):
        assert extract_ip_or_domain("escanea google.com") == "google.com"
        assert extract_ip_or_domain("analiza sub.example.com") == "sub.example.com"
    
    def test_extract_ports(self):
        assert extract_ports("-p 80,443") == "80,443"
        assert extract_ports("puertos 22,80,443") == "22,80,443"
        assert extract_ports("port 8080") == "8080"
    
    def test_detect_intent_scan(self):
        intent = detect_intent("escanea 192.168.1.1")
        assert intent["action"] == "scan"
        assert intent["target"] == "192.168.1.1"
        assert intent["tool"] == "quick"
    
    def test_detect_intent_vuln_scan(self):
        intent = detect_intent("escanea vulnerabilidades en 192.168.1.1")
        assert intent["action"] == "scan"
        assert intent["tool"] == "vuln"
    
    def test_detect_intent_web_scan(self):
        intent = detect_intent("escaneo web de google.com")
        assert intent["action"] == "scan"
        assert intent["tool"] == "web"
    
    def test_detect_intent_autopwn(self):
        intent = detect_intent("pentest completo a 192.168.1.1")
        assert intent["action"] == "autopwn"
    
    def test_detect_intent_search(self):
        intent = detect_intent("busca exploits de apache")
        assert intent["action"] == "search"
        assert intent["params"]["keyword"] == "apache"
    
    def test_detect_intent_generate_shell(self):
        intent = detect_intent("genera reverse shell python")
        assert intent["action"] == "generate"
        assert intent["params"]["type"] == "shell"
    
    def test_detect_intent_generate_script(self):
        intent = detect_intent("crea script de enumeración")
        assert intent["action"] == "generate"
        assert intent["params"]["type"] == "script"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
