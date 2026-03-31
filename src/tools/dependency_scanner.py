#!/usr/bin/env python3
"""
Dependency vulnerability scanner for RETRO-Ollama.
Uses safety-db to check for known vulnerable dependencies.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from src.config import get_config


class DependencyScanner:
    """Scans project dependencies for known vulnerabilities."""

    def __init__(self):
        self.config = get_config()
        self.project_root = Path(__file__).parent.parent.parent
        self.requirements_file = self.project_root / "requirements.txt"

    def scan_with_safety(self) -> Dict:
        """
        Run safety check on requirements.txt.
        Returns a dictionary with scan results.
        """
        if not self.requirements_file.exists():
            return {
                "success": False,
                "error": f"Requirements file not found: {self.requirements_file}",
                "vulnerabilities": [],
            }

        try:
            # Run safety check
            result = subprocess.run(
                [sys.executable, "-m", "safety", "check", "-r", str(self.requirements_file), "--json"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                # No vulnerabilities found
                return {
                    "success": True,
                    "output": "No known vulnerable dependencies found.",
                    "vulnerabilities": [],
                    "returncode": 0,
                }
            else:
                # Safety found vulnerabilities or error
                try:
                    vulns = json.loads(result.stdout) if result.stdout else []
                except json.JSONDecodeError:
                    vulns = []

                return {
                    "success": False,
                    "error": result.stderr if result.stderr else "Safety check failed",
                    "vulnerabilities": vulns,
                    "returncode": result.returncode,
                    "raw_output": result.stdout,
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Safety check timed out",
                "vulnerabilities": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "vulnerabilities": [],
            }

    def scan_with_pip_audit(self) -> Dict:
        """
        Run pip-audit check on requirements.txt.
        Returns a dictionary with scan results.
        """
        if not self.requirements_file.exists():
            return {
                "success": False,
                "error": f"Requirements file not found: {self.requirements_file}",
                "vulnerabilities": [],
            }

        try:
            # Run pip-audit check
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "-r", str(self.requirements_file), "--format=json"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                # No vulnerabilities found
                return {
                    "success": True,
                    "output": "No known vulnerable dependencies found.",
                    "vulnerabilities": [],
                    "returncode": 0,
                }
            else:
                # Pip-audit found vulnerabilities or error
                try:
                    data = json.loads(result.stdout) if result.stdout else {}
                    vulns = data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    vulns = []

                return {
                    "success": False,
                    "error": result.stderr if result.stderr else "Pip-audit check failed",
                    "vulnerabilities": vulns,
                    "returncode": result.returncode,
                    "raw_output": result.stdout,
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Pip-audit check timed out",
                "vulnerabilities": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "vulnerabilities": [],
            }

    def scan(self, use_safety: bool = True) -> Dict:
        """
        Perform dependency vulnerability scan.
        Prefers safety if available, falls back to pip-audit.
        """
        if use_safety:
            result = self.scan_with_safety()
            if result["success"] or "No known vulnerable dependencies" in result.get("output", ""):
                return result
            # If safety fails, try pip-audit as fallback
            return self.scan_with_pip_audit()
        else:
            return self.scan_with_pip_audit()


def scan_dependencies() -> Dict:
    """Convenience function to scan dependencies."""
    scanner = DependencyScanner()
    return scanner.scan()


if __name__ == "__main__":
    # When run directly, perform scan and print results
    result = scan_dependencies()
    if result["success"]:
        print("OK Dependency scan completed successfully")
        if result.get("vulnerabilities"):
            print(f"Found {len(result['vulnerabilities'])} vulnerabilities:")
            for vuln in result["vulnerabilities"]:
                print(f"  - {vuln.get('package', 'Unknown')}: {vuln.get('advisory', 'No details')}")
        else:
            print("No vulnerabilities found.")
    else:
        print("X Dependency scan failed:")
        print(result.get("error", "Unknown error"))
        if result.get("raw_output"):
            print("Output:", result["raw_output"])
        sys.exit(1)