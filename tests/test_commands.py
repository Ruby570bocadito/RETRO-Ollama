import pytest
import sys
import os
from unittest.mock import Mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture
def console():
    return Mock()

from src.cli_commands.commands.scan import (
    handle_scan, handle_autopwn, handle_fullpentest,
    handle_enum, handle_exec, handle_run, handle_search, handle_tools
)
from src.cli_commands.commands.osint import (
    handle_shodan, handle_virustotal, handle_hunter,
    handle_crt, handle_whois
)
from unittest.mock import Mock, patch


class TestScanCommands:
    @patch('src.cli_commands.commands.scan.quick_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    @patch('src.cli_commands.commands.scan.Panel')
    def test_handle_scan_quick(self, mock_panel, mock_sanitize, mock_quick_scan, console):
        mock_sanitize.return_value = "192.168.1.1"
        mock_quick_scan.return_value = {"success": True, "output": "Open ports: 22,80"}
        mock_panel.return_value = "Panel"
        
        result = handle_scan("scan", "192.168.1.1", console)
        
        assert result == "Escaneo completado."
        mock_quick_scan.assert_called_once_with("192.168.1.1")
    
    @patch('src.cli_commands.commands.scan.quick_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_scan_invalid_target(self, mock_sanitize, mock_quick_scan):
        mock_sanitize.return_value = None
        
        console = Mock()
        result = handle_scan("scan", "invalid", console)
        
        assert result == "Target inválido"
        mock_quick_scan.assert_not_called()
    
    @patch('src.cli_commands.commands.scan.vuln_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_scan_vuln(self, mock_sanitize, mock_vuln_scan, console):
        mock_sanitize.return_value = "192.168.1.1"
        mock_vuln_scan.return_value = {"success": True, "output": "Vulns found"}
        
        result = handle_scan("vuln", "192.168.1.1", console)
        
        assert result == "Escaneo completado."
        mock_vuln_scan.assert_called_once()
    
    @patch('src.cli_commands.commands.scan.web_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_scan_web(self, mock_sanitize, mock_web_scan, console):
        mock_sanitize.return_value = "example.com"
        mock_web_scan.return_value = {"success": True, "output": "Web scan results"}
        
        result = handle_scan("web", "example.com", console)
        
        assert result == "Escaneo completado."
        mock_web_scan.assert_called_once()
    
    @patch('src.cli_commands.commands.scan.full_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_scan_full(self, mock_sanitize, mock_full_scan, console):
        mock_sanitize.return_value = "example.com"
        mock_full_scan.return_value = {"success": True, "output": "Full scan results"}
        
        result = handle_scan("full", "example.com", console)
        
        assert result == "Escaneo completado."
        mock_full_scan.assert_called_once()
    
    @patch('src.cli_commands.commands.scan.dir_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_scan_dir(self, mock_sanitize, mock_dir_scan, console):
        mock_sanitize.return_value = "example.com"
        mock_dir_scan.return_value = {"success": True, "output": "Dirs found"}
        
        result = handle_scan("dir", "example.com", console)
        
        assert result == "Escaneo completado."
        mock_dir_scan.assert_called_once()


class TestAutopwnCommand:
    @patch('src.cli_commands.commands.scan.create_quick_report')
    @patch('src.cli_commands.commands.scan.dir_scan')
    @patch('src.cli_commands.commands.scan.web_scan')
    @patch('src.cli_commands.commands.scan.vuln_scan')
    @patch('src.cli_commands.commands.scan.quick_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_autopwn(self, mock_sanitize, mock_quick, mock_vuln, mock_web, mock_dir, mock_report, console):
        mock_sanitize.return_value = "192.168.1.1"
        mock_quick.return_value = {"output": "Scan done"}
        mock_vuln.return_value = {"output": "Vulns done"}
        mock_web.return_value = {"output": "Web done"}
        mock_dir.return_value = {"output": "Dirs done"}
        mock_report.return_value = "/reports/report.txt"
        
        result = handle_autopwn("192.168.1.1", console)
        
        assert "Reporte en:" in result
        mock_quick.assert_called()
        mock_vuln.assert_called()


class TestEnumCommand:
    @patch('src.cli_commands.commands.scan.create_quick_report')
    @patch('src.cli_commands.commands.scan.subdomain_enum')
    @patch('src.cli_commands.commands.scan.dns_enum')
    @patch('src.cli_commands.commands.scan.os_detect')
    @patch('src.cli_commands.commands.scan.port_scan')
    @patch('src.cli_commands.commands.scan.sanitize_target')
    def test_handle_enum(self, mock_sanitize, mock_port, mock_os, mock_dns, mock_sub, mock_report, console):
        mock_sanitize.return_value = "example.com"
        mock_port.return_value = {"success": True, "output": "Ports"}
        mock_os.return_value = {"success": True, "output": "OS"}
        mock_dns.return_value = {"success": True, "output": "DNS"}
        mock_sub.return_value = {"success": True, "output": "Subs"}
        mock_report.return_value = "/reports/enum.txt"
        
        result = handle_enum("example.com", console)
        
        assert "Reporte:" in result
        mock_port.assert_called()


class TestRunCommand:
    @patch('src.cli_commands.commands.scan.execute_command')
    @patch('src.cli_commands.commands.scan.validate_command')
    def test_handle_run_valid(self, mock_validate, mock_execute, console):
        mock_validate.return_value = (True, None)
        mock_execute.return_value = {"success": True, "output": "Command output", "returncode": 0}
        
        result = handle_run("echo hello", console)
        
        assert "Código: 0" == result
        mock_execute.assert_called_once_with("echo hello")
    
    @patch('src.cli_commands.commands.scan.validate_command')
    def test_handle_run_blocked(self, mock_validate, console):
        mock_validate.return_value = (False, "Comando peligroso")
        
        result = handle_run("rm -rf /", console)
        
        assert result == "Comando no permitido."


class TestSearchCommand:
    @patch('src.cli_commands.commands.scan.search_exploits')
    def test_handle_search(self, mock_search, console):
        mock_search.return_value = {"success": True, "output": "Exploit found"}
        
        result = handle_search("apache", console)
        
        assert result is None
        mock_search.assert_called_once_with("apache")


class TestToolsCommand:
    @patch('src.cli_commands.commands.scan.get_available_tools')
    def test_handle_tools(self, mock_tools, console):
        mock_tools.return_value = {"Scanning": ["nmap", "nikto"]}
        
        result = handle_tools(console)
        
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
