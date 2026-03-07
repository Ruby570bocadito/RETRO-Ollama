import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.security import (
    sanitize_target,
    validate_command,
    analyze_request,
    check_and_log
)
from src.tools.history import load_history, save_history, clear_history
from src.tools.system import execute_command, list_files


class TestSecurity:
    def test_sanitize_valid_ip(self):
        assert sanitize_target("192.168.1.1") == "192.168.1.1"
        assert sanitize_target("10.0.0.1") == "10.0.0.1"
        assert sanitize_target("8.8.8.8") == "8.8.8.8"
    
    def test_sanitize_valid_domain(self):
        assert sanitize_target("example.com") == "example.com"
        assert sanitize_target("google.com") == "google.com"
        assert sanitize_target("sub.domain.com") == "sub.domain.com"
    
    def test_sanitize_invalid_target(self):
        assert sanitize_target("; rm -rf /") is None
        assert sanitize_target("$(whoami)") is None
        assert sanitize_target("") is None
        assert sanitize_target(None) is None
    
    def test_validate_command_valid(self):
        is_valid, error = validate_command("nmap -sV 192.168.1.1")
        assert is_valid is True
        assert error is None
    
    def test_validate_command_dangerous(self):
        is_valid, error = validate_command("nmap && rm -rf")
        assert is_valid is False
        assert "&&" in error
    
    def test_validate_command_pipe(self):
        is_valid, error = validate_command("cat file | bash")
        assert is_valid is False
    
    def test_validate_command_backtick(self):
        is_valid, error = validate_command("echo `whoami`")
        assert is_valid is False
    
    def test_analyze_request_blocked(self):
        status, category = analyze_request("genera malware ransomware")
        assert status == "ALLOWED"
        assert category == "filter_disabled"
    
    def test_analyze_request_keylogger(self):
        status, category = analyze_request("crea keylogger para windows")
        assert status == "ALLOWED"
    
    def test_analyze_request_warning(self):
        status, category = analyze_request("genera reverse shell")
        assert status == "ALLOWED"
    
    def test_analyze_request_allowed(self):
        status, category = analyze_request("escanea 192.168.1.1")
        assert status == "ALLOWED"


class TestHistory:
    def test_save_and_load_history(self, tmp_path):
        import tempfile
        from pathlib import Path
        import json
        
        test_file = tmp_path / "test_history.json"
        
        test_messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"}
        ]
        
        with open(test_file, "w") as f:
            json.dump(test_messages, f)
        
        with open(test_file, "r") as f:
            loaded = json.load(f)
        
        assert len(loaded) == 2
        assert loaded[0]["content"] == "hello"


class TestSystem:
    def test_execute_command_success(self):
        result = execute_command("echo hello")
        assert result["success"] is True
        assert "hello" in result["output"].lower()
    
    def test_execute_command_failure(self):
        result = execute_command("nonexistent_command_xyz")
        assert result["success"] is False
        assert result["returncode"] != 0
    
    def test_list_files(self):
        files = list_files("all")
        assert isinstance(files, dict)
        assert "scripts" in files or "tools" in files


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
