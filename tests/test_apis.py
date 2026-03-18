import pytest
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAPIs:
    """Tests para las APIs OSINT"""

    @patch('src.tools.apis.requests.get')
    def test_shodan_scan_success(self, mock_get):
        """Test Shodan scan exitoso"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'isp': 'Test ISP',
            'os': 'Linux',
            'ports': [22, 80, 443],
            'hostnames': ['test.com'],
            'vulns': ['CVE-2021-44228']
        }
        mock_get.return_value = mock_response
        
        from src.tools import apis as apis_module
        with patch.object(apis_module, 'SHODAN_API_KEY', 'test_key'):
            result = apis_module.shodan_scan("8.8.8.8")
            assert result["success"] is True

    def test_shodan_no_api_key(self):
        """Test Shodan sin API key"""
        from src.tools import apis as apis_module
        with patch.object(apis_module, 'SHODAN_API_KEY', ''):
            result = apis_module.shodan_scan("8.8.8.8")
            assert result["success"] is False
            assert "no configurada" in result["error"]

    @patch('src.tools.apis.requests.get')
    def test_virustotal_scan_success(self, mock_get):
        """Test VirusTotal scan exitoso"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 100
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        from src.tools import apis as apis_module
        with patch.object(apis_module, 'VIRUSTOTAL_API_KEY', 'test_key'):
            result = apis_module.virustotal_scan("example.com")
            assert result["success"] is True

    def test_virustotal_no_api_key(self):
        """Test VirusTotal sin API key"""
        from src.tools import apis as apis_module
        with patch.object(apis_module, 'VIRUSTOTAL_API_KEY', ''):
            result = apis_module.virustotal_scan("example.com")
            assert result["success"] is False
            assert "no configurada" in result["error"]

    @patch('src.tools.apis.requests.get')
    def test_crt_sh_success(self, mock_get):
        """Test CRT.SH exitoso"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"common_name": "*.example.com", "not_after": "2025-12-31"},
            {"common_name": "example.com", "not_after": "2025-06-30"}
        ]
        mock_get.return_value = mock_response
        
        from src.tools.apis import crt_sh_lookup
        result = crt_sh_lookup("example.com")
        assert result["success"] is True

    @patch('src.tools.apis.requests.get')
    def test_whois_success(self, mock_get):
        """Test Whois exitoso"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Domain: example.com"
        mock_get.return_value = mock_response
        
        from src.tools.apis import whois_lookup
        result = whois_lookup("example.com")
        assert result["success"] is True

    @patch('src.tools.apis.requests.get')
    def test_api_error_handling(self, mock_get):
        """Test manejo de errores de API"""
        mock_get.side_effect = Exception("Connection error")
        
        from src.tools.apis import crt_sh_lookup
        result = crt_sh_lookup("example.com")
        assert result["success"] is False
        assert "error" in result


class TestRateLimiter:
    """Tests para el rate limiter"""

    def test_rate_limiter_allows_within_limit(self):
        """Test rate limiter permite dentro del límite"""
        from src.tools.rate_limit import RateLimiter
        limiter = RateLimiter(max_calls=5, period=60)
        
        for _ in range(5):
            assert limiter.is_allowed("test") is True

    def test_rate_limiter_blocks_after_limit(self):
        """Test rate limiter bloquea después del límite"""
        from src.tools.rate_limit import RateLimiter
        limiter = RateLimiter(max_calls=3, period=60)
        
        for _ in range(3):
            limiter.is_allowed("test")
        
        assert limiter.is_allowed("test") is False

    def test_rate_limiter_wait_time(self):
        """Test tiempo de espera"""
        from src.tools.rate_limit import RateLimiter
        limiter = RateLimiter(max_calls=1, period=60)
        
        limiter.is_allowed("test")
        wait = limiter.wait_time("test")
        
        assert wait >= 0

    def test_exponential_backoff(self):
        """Test exponential backoff decorator"""
        from src.tools.rate_limit import exponential_backoff
        
        call_count = 0
        
        @exponential_backoff(max_retries=2, base_delay=0.1)
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Test error")
            return "success"
        
        result = failing_function()
        assert result == "success"
        assert call_count == 2


class TestConfig:
    """Tests para configuración"""

    def test_check_api_keys_function(self):
        """Test función check_api_keys"""
        from src.config.settings import check_api_keys
        result = check_api_keys()
        assert isinstance(result, dict)
        assert "shodan" in result

    def test_get_missing_keys_function(self):
        """Test función get_missing_keys"""
        from src.config.settings import get_missing_keys
        result = get_missing_keys()
        assert isinstance(result, list)

    def test_pydantic_config(self):
        """Test configuración Pydantic"""
        from src.config.config import AppConfig, get_config
        config = get_config()
        assert isinstance(config, AppConfig)
        assert hasattr(config, 'ollama')
        assert hasattr(config, 'api_keys')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
