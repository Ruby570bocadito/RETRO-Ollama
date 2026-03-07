import requests
import json
from typing import Generator, Optional, List, Dict
from src.config.settings import OLLAMA_HOST

class OllamaClient:
    def __init__(self, host: str = OLLAMA_HOST):
        self.host = host
        self.base_url = f"{host}/api"
        self.current_model = None
        
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
        except Exception as e:
            return []
    
    def get_model_info(self, model_name: str) -> Optional[Dict]:
        try:
            response = requests.post(
                f"{self.host}/api/show",
                json={"name": model_name},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None
    
    def pull_model(self, model_name: str) -> Generator[str, None, None]:
        try:
            with requests.post(
                f"{self.host}/api/pull",
                json={"name": model_name},
                stream=True,
                timeout=300
            ) as r:
                for line in r.iter_lines():
                    if line:
                        data = json.loads(line)
                        yield data.get("status", "")
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def chat(self, model: str, messages: List[Dict], 
             system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        self.current_model = model
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": True
        }
        
        try:
            with requests.post(
                f"{self.base_url}/chat",
                json=payload,
                stream=True,
                timeout=120
            ) as r:
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
    
    def generate(self, model: str, prompt: str, 
                 system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True
        }
        if system_prompt:
            payload["system"] = system_prompt
            
        try:
            with requests.post(
                f"{self.base_url}/generate",
                json=payload,
                stream=True,
                timeout=120
            ) as r:
                for line in r.iter_lines():
                    if line:
                        data = json.loads(line)
                        if "response" in data:
                            yield data["response"]
                        if data.get("done", False):
                            break
        except Exception as e:
            yield f"Error: {str(e)}"
