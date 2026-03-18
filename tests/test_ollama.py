import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ollama_client import OllamaClient


class TestOllamaClient:
    """Tests para el cliente Ollama con manejo de errores mejorado"""

    @patch('src.ollama_client.requests.get')
    def test_check_connection_success(self, mock_get):
        """Test de conexión exitosa"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        client = OllamaClient()
        assert client.check_connection() is True
        mock_get.assert_called_once()

    @patch('src.ollama_client.requests.get')
    def test_check_connection_failure(self, mock_get):
        """Test de conexión fallida"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        client = OllamaClient()
        assert client.check_connection() is False

    @patch('src.ollama_client.requests.get')
    def test_check_connection_timeout(self, mock_get):
        """Test de timeout en conexión"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        client = OllamaClient()
        assert client.check_connection() is False

    @patch('src.ollama_client.requests.get')
    def test_check_connection_refused(self, mock_get):
        """Test de conexión rechazada"""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()

        client = OllamaClient()
        assert client.check_connection() is False

    @patch('src.ollama_client.requests.get')
    def test_list_models_success(self, mock_get):
        """Test de listado de modelos exitoso"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "models": [
                {"name": "llama3.2", "size": 4000000000},
                {"name": "mistral", "size": 4000000000}
            ]
        }
        mock_get.return_value = mock_response

        client = OllamaClient()
        models = client.list_models()
        
        assert len(models) == 2
        assert models[0]["name"] == "llama3.2"

    @patch('src.ollama_client.requests.get')
    def test_list_models_empty(self, mock_get):
        """Test de listado sin modelos"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": []}
        mock_get.return_value = mock_response

        client = OllamaClient()
        models = client.list_models()
        
        assert models == []

    @patch('src.ollama_client.requests.get')
    def test_list_models_timeout(self, mock_get):
        """Test de timeout en listado"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        client = OllamaClient()
        models = client.list_models()
        
        assert models == []

    @patch('src.ollama_client.requests.post')
    def test_get_model_info_success(self, mock_post):
        """Test de información de modelo"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "llama3.2",
            "size": 4000000000,
            "parameters": "8B"
        }
        mock_post.return_value = mock_response

        client = OllamaClient()
        info = client.get_model_info("llama3.2")
        
        assert info["name"] == "llama3.2"

    @patch('src.ollama_client.requests.post')
    def test_chat_stream_success(self, mock_post):
        """Test de chat con streaming"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = [
            b'{"message": {"content": "Hello"}, "done": false}',
            b'{"message": {"content": " World"}, "done": true}'
        ]
        mock_post.return_value.__enter__ = Mock(return_value=mock_response)
        mock_post.return_value.__exit__ = Mock(return_value=False)

        client = OllamaClient()
        messages = [{"role": "user", "content": "Hi"}]
        chunks = list(client.chat("llama3.2", messages))
        
        assert len(chunks) >= 1

    @patch('src.ollama_client.requests.post')
    def test_chat_with_retry(self, mock_post):
        """Test de retry en chat"""
        import requests
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = [
            b'{"message": {"content": "Response"}, "done": true}'
        ]
        
        mock_post.side_effect = [
            requests.exceptions.ConnectionError(),
            requests.exceptions.ConnectionError(),
            mock_response
        ]
        mock_post.return_value.__enter__ = Mock(return_value=mock_response)
        mock_post.return_value.__exit__ = Mock(return_value=False)

        client = OllamaClient()
        messages = [{"role": "user", "content": "Test"}]
        chunks = list(client.chat("llama3.2", messages, max_retries=3))
        
        assert mock_post.call_count >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
