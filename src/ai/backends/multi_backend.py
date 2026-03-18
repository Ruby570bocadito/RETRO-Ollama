from typing import Generator, Optional, List, Dict
from abc import ABC, abstractmethod
import requests
import json


class LLMBackend(ABC):
    @abstractmethod
    def check_connection(self) -> bool:
        pass
    
    @abstractmethod
    def list_models(self) -> List[Dict]:
        pass
    
    @abstractmethod
    def chat(self, model: str, messages: List[Dict]) -> Generator[str, None, None]:
        pass
    
    @abstractmethod
    def generate(self, model: str, prompt: str) -> Generator[str, None, None]:
        pass


class OllamaBackend(LLMBackend):
    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host
        self.base_url = f"{host}/api"
    
    def check_connection(self) -> bool:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> List[Dict]:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=10)
            if response.status_code == 200:
                return response.json().get("models", [])
            return []
        except:
            return []
    
    def chat(self, model: str, messages: List[Dict]) -> Generator[str, None, None]:
        payload = {"model": model, "messages": messages, "stream": True}
        try:
            with requests.post(f"{self.base_url}/chat", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        data = json.loads(line)
                        if "message" in data:
                            content = data["message"].get("content", "")
                            if content:
                                yield content
                        if data.get("done", False):
                            break
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def generate(self, model: str, prompt: str) -> Generator[str, None, None]:
        payload = {"model": model, "prompt": prompt, "stream": True}
        try:
            with requests.post(f"{self.base_url}/generate", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        data = json.loads(line)
                        if "response" in data:
                            yield data["response"]
                        if data.get("done", False):
                            break
        except Exception as e:
            yield f"Error: {str(e)}"


class LlamaCppBackend(LLMBackend):
    def __init__(self, host: str = "http://localhost:8080"):
        self.host = host
    
    def check_connection(self) -> bool:
        try:
            response = requests.get(f"{self.host}/v1/models", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> List[Dict]:
        try:
            response = requests.get(f"{self.host}/v1/models", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [{"name": m["id"], "size": m.get("size", 0)} for m in data.get("data", [])]
            return []
        except:
            return []
    
    def chat(self, model: str, messages: List[Dict]) -> Generator[str, None, None]:
        payload = {
            "model": model,
            "messages": messages,
            "stream": True
        }
        try:
            with requests.post(f"{self.host}/v1/chat/completions", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        line = line.decode('utf-8')
                        if line.startswith('data: '):
                            data = json.loads(line[6:])
                            if "choices" in data:
                                delta = data["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def generate(self, model: str, prompt: str) -> Generator[str, None, None]:
        payload = {"model": model, "prompt": prompt, "stream": True}
        try:
            with requests.post(f"{self.host}/v1/completions", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        line = line.decode('utf-8')
                        if line.startswith('data: '):
                            data = json.loads(line[6:])
                            if "choices" in data:
                                yield data["choices"][0].get("text", "")
        except Exception as e:
            yield f"Error: {str(e)}"


class LMStudioBackend(LLMBackend):
    def __init__(self, host: str = "http://localhost:1234/v1"):
        self.host = host
    
    def check_connection(self) -> bool:
        try:
            response = requests.get(f"{self.host}/models", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> List[Dict]:
        try:
            response = requests.get(f"{self.host}/models", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [{"name": m["id"], "size": m.get("size", 0)} for m in data.get("data", [])]
            return []
        except:
            return []
    
    def chat(self, model: str, messages: List[Dict]) -> Generator[str, None, None]:
        payload = {"model": model, "messages": messages, "stream": True}
        try:
            with requests.post(f"{self.host}/chat/completions", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        try:
                            line = line.decode('utf-8')
                        except:
                            line = line.decode('latin-1', errors='replace')
                        if line.startswith('data: '):
                            try:
                                data = json.loads(line[6:])
                                if "choices" in data:
                                    delta = data["choices"][0].get("delta", {})
                                    if "content" in delta and delta["content"]:
                                        yield delta["content"]
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def generate(self, model: str, prompt: str) -> Generator[str, None, None]:
        payload = {"model": model, "prompt": prompt, "stream": True}
        try:
            with requests.post(f"{self.host}/completions", json=payload, stream=True, timeout=120) as r:
                for line in r.iter_lines():
                    if line:
                        line = line.decode('utf-8')
                        if line.startswith('data: '):
                            data = json.loads(line[6:])
                            if "choices" in data:
                                yield data["choices"][0].get("text", "")
        except Exception as e:
            yield f"Error: {str(e)}"


class MultiBackendClient:
    BACKENDS = {
        "ollama": OllamaBackend,
        "llamacpp": LlamaCppBackend,
        "lmstudio": LMStudioBackend
    }
    
    def __init__(self, backend: str = "ollama", **kwargs):
        self.backend_name = backend
        backend_class = self.BACKENDS.get(backend, OllamaBackend)
        self.backend = backend_class(**kwargs)
        self.current_model = None
    
    def check_connection(self) -> bool:
        return self.backend.check_connection()
    
    def list_models(self) -> List[Dict]:
        return self.backend.list_models()
    
    def chat(self, model: str, messages: List[Dict]) -> Generator[str, None, None]:
        self.current_model = model
        return self.backend.chat(model, messages)
    
    def generate(self, model: str, prompt: str) -> Generator[str, None, None]:
        return self.backend.generate(model, prompt)
    
    @classmethod
    def get_available_backends(cls) -> List[str]:
        return list(cls.BACKENDS.keys())


def create_client(backend: str = "ollama", **kwargs) -> MultiBackendClient:
    return MultiBackendClient(backend, **kwargs)
