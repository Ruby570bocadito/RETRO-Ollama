import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.utils import (
    is_valid_ip,
    is_private_ip,
    is_valid_domain,
    extract_urls,
    extract_emails,
    extract_ips,
    calculate_hash,
    encode_base64,
    decode_base64,
    parse_nmap_output,
    severity_to_cvss,
    cvss_to_severity,
    sanitize_filename,
    truncate_string,
    get_severity_color,
    parse_json_safe,
    clean_html,
    count_findings_by_severity,
    chunk_list
)


class TestIPUtils:
    """Tests para utilidades de IP"""

    def test_is_valid_ip(self):
        """Test IPs válidas"""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("invalid") is False
        assert is_valid_ip("256.1.1.1") is False

    def test_is_private_ip(self):
        """Test IPs privadas"""
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False

    def test_is_valid_domain(self):
        """Test dominios válidos"""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("invalid..com") is False


class TestExtractors:
    """Tests para extractores"""

    def test_extract_urls(self):
        """Extrae URLs"""
        text = "Visit https://example.com or http://test.com"
        urls = extract_urls(text)
        assert "https://example.com" in urls
        assert "http://test.com" in urls

    def test_extract_emails(self):
        """Extrae emails"""
        text = "Contact test@example.com or admin@test.com"
        emails = extract_emails(text)
        assert "test@example.com" in emails
        assert "admin@test.com" in emails

    def test_extract_ips(self):
        """Extrae IPs"""
        text = "Server 192.168.1.1 responded to 10.0.0.1"
        ips = extract_ips(text)
        assert "192.168.1.1" in ips
        assert "10.0.0.1" in ips


class TestHashUtils:
    """Tests para hashing"""

    def test_calculate_hash(self):
        """Calcula hashes"""
        result = calculate_hash("test", "md5")
        assert result == "098f6bcd4621d373cade4e832627b4f6"
        
        result = calculate_hash("test", "sha256")
        assert result == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_base64(self):
        """Test encode/decode base64"""
        encoded = encode_base64("hello")
        assert encoded == "aGVsbG8="
        
        decoded = decode_base64(encoded)
        assert decoded == "hello"
        
        assert decode_base64("invalid!!!") == ""


class TestParsers:
    """Tests para parsers"""

    def test_parse_nmap_output(self):
        """Parsea salida nmap"""
        output = """
22/tcp   open  ssh     OpenSSH 7.4
80/tcp   open  http    Apache httpd 2.4.6
443/tcp  open  ssl/https Apache httpd
        """
        result = parse_nmap_output(output)
        assert len(result["open_ports"]) == 3
        assert "ssh" in result["services"]

    def test_parse_nmap_empty(self):
        """Parsea salida nmap vacía"""
        result = parse_nmap_output("")
        assert result["open_ports"] == []


class TestSeverityUtils:
    """Tests para severidad"""

    def test_severity_to_cvss(self):
        """Convierte severidad a CVSS"""
        assert severity_to_cvss("critical") == 9.5
        assert severity_to_cvss("high") == 7.5
        assert severity_to_cvss("medium") == 5.0
        assert severity_to_cvss("low") == 3.5
        assert severity_to_cvss("info") == 0.0

    def test_cvss_to_severity(self):
        """Convierte CVSS a severidad"""
        assert cvss_to_severity(9.5) == "Critical"
        assert cvss_to_severity(7.5) == "High"
        assert cvss_to_severity(5.0) == "Medium"
        assert cvss_to_severity(3.5) == "Low"
        assert cvss_to_severity(0.0) == "Info"

    def test_get_severity_color(self):
        """Colores de severidad"""
        assert get_severity_color("critical") == "#FF4757"
        assert get_severity_color("high") == "#FF6B35"
        assert get_severity_color("medium") == "#FFD93D"


class TestStringUtils:
    """Tests para utilidades de string"""

    def test_sanitize_filename(self):
        """Limpia nombres de archivo"""
        assert sanitize_filename("test<>file.txt") == "test__file.txt"
        assert sanitize_filename("normal.txt") == "normal.txt"

    def test_truncate_string(self):
        """Trunca strings"""
        assert truncate_string("hello world", 5) == "he..."
        assert truncate_string("hi", 10) == "hi"

    def test_clean_html(self):
        """Limpia HTML"""
        text = "<p>Hello <b>World</b></p>"
        assert clean_html(text) == "Hello World"


class TestDataUtils:
    """Tests para utilidades de datos"""

    def test_chunk_list(self):
        """Divide lista en chunks"""
        result = chunk_list([1,2,3,4,5,6,7,8,9], 3)
        assert result == [[1,2,3], [4,5,6], [7,8,9]]

    def test_parse_json_safe(self):
        """Parsea JSON seguro"""
        assert parse_json_safe('{"key": "value"}') == {"key": "value"}
        assert parse_json_safe("invalid") is None

    def test_count_findings_by_severity(self):
        """Cuenta hallazgos"""
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "critical"},
            {"severity": "low"}
        ]
        result = count_findings_by_severity(findings)
        assert result["critical"] == 2
        assert result["high"] == 1
        assert result["low"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
