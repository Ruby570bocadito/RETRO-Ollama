import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.code_samples import (
    get_code_sample,
    list_categories,
    list_languages,
    search_samples,
    get_all_samples,
    CODE_SAMPLES
)


class TestCodeSamples:
    """Tests para ejemplos de código"""

    def test_get_code_sample(self):
        """Obtener ejemplo de código"""
        code = get_code_sample("network_info", "python")
        assert code is not None
        assert "socket" in code

    def test_get_code_sample_not_found(self):
        """Ejemplo no encontrado"""
        code = get_code_sample("nonexistent", "python")
        assert code is None

    def test_list_categories(self):
        """Lista categorías"""
        categories = list_categories()
        assert isinstance(categories, list)
        assert len(categories) > 0
        assert "network_info" in categories

    def test_list_languages(self):
        """Lista lenguajes"""
        languages = list_languages()
        assert isinstance(languages, list)
        assert "python" in languages

    def test_search_samples(self):
        """Buscar ejemplos"""
        results = search_samples("network")
        assert isinstance(results, list)

    def test_get_all_samples(self):
        """Obtener todos los ejemplos"""
        samples = get_all_samples()
        assert isinstance(samples, dict)
        assert len(samples) > 0


class TestCodeSamplesContent:
    """Tests para contenido de ejemplos"""

    def test_network_info(self):
        """Contenido de network_info"""
        code = get_code_sample("network_info", "python")
        assert "hostname" in code.lower()

    def test_port_scanner(self):
        """Contenido de port_scanner"""
        code = get_code_sample("port_scanner", "python")
        assert "socket" in code

    def test_http_requester(self):
        """Contenido de http_requester"""
        code = get_code_sample("http_requester", "python")
        assert "requests" in code

    def test_dns_lookup(self):
        """Contenido de dns_lookup"""
        code = get_code_sample("dns_lookup", "python")
        assert "socket" in code

    def test_hash_calculator(self):
        """Contenido de hash_calculator"""
        code = get_code_sample("hash_calculator", "python")
        assert "hashlib" in code


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
