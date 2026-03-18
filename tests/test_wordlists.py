import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.wordlists import (
    get_wordlist,
    get_all_wordlists,
    get_wordlist_names,
    search_wordlist,
    generate_username_wordlist,
    generate_password_wordlist,
    WORDLISTS
)


class TestWordlists:
    """Tests para wordlists"""

    def test_get_wordlist(self):
        """Obtener wordlist por nombre"""
        users = get_wordlist("common_usernames")
        assert isinstance(users, list)
        assert "admin" in users
        assert "root" in users

    def test_get_wordlist_not_found(self):
        """Wordlist no encontrada"""
        result = get_wordlist("nonexistent")
        assert result == []

    def test_get_all_wordlists(self):
        """Obtener todas las wordlists"""
        all_lists = get_all_wordlists()
        assert isinstance(all_lists, dict)
        assert len(all_lists) > 0
        assert "common_usernames" in all_lists
        assert "common_passwords" in all_lists

    def test_get_wordlist_names(self):
        """Nombres de wordlists"""
        names = get_wordlist_names()
        assert isinstance(names, list)
        assert len(names) > 5

    def test_search_wordlist(self):
        """Buscar en wordlists"""
        results = search_wordlist("admin")
        assert isinstance(results, list)

    def test_generate_username_wordlist(self):
        """Generar usernames"""
        usernames = generate_username_wordlist("John", "Doe")
        assert isinstance(usernames, list)
        assert len(usernames) > 0

    def test_generate_password_wordlist(self):
        """Generar passwords"""
        passwords = generate_password_wordlist("password")
        assert isinstance(passwords, list)
        assert len(passwords) > 0


class TestWordlistContent:
    """Tests para contenido de wordlists"""

    def test_common_usernames(self):
        """Verifica contenido de usernames"""
        users = WORDLISTS["common_usernames"]
        assert "admin" in users
        assert "root" in users

    def test_common_passwords(self):
        """Verifica contenido de passwords"""
        passwords = WORDLISTS["common_passwords"]
        assert "password" in passwords
        assert "123456" in passwords

    def test_web_paths(self):
        """Verifica paths web"""
        paths = WORDLISTS["web_paths"]
        assert "admin" in paths
        assert "wp-admin" in paths
        assert ".git" in paths

    def test_subdomains(self):
        """Verifica subdominios"""
        subs = WORDLISTS["subdomains"]
        assert "www" in subs
        assert "mail" in subs
        assert "ftp" in subs

    def test_sensitive_files(self):
        """Verifica archivos sensibles"""
        files = WORDLISTS["sensitive_files"]
        assert ".env" in files
        assert ".git/config" in files
        assert "wp-config.php" in files


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
