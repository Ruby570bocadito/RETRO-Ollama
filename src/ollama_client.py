import requests
import json
import time
import logging
from typing import Generator, Optional, List, Dict
from src.config.settings import OLLAMA_HOST

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self, host: str = OLLAMA_HOST):
        self.host = host
        self.base_url = f"{host}/api"
        self.current_model = None
        self.backend_name = "ollama"
        
    def check_connection(self) -> bool:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info(f"Connected to Ollama at {self.host}")
                return True
            logger.warning(f"Ollama returned status {response.status_code}")
            return False
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Ollama at {self.host}")
            return False
        except requests.exceptions.Timeout:
            logger.error(f"Connection to Ollama timed out")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking connection: {str(e)}")
            return False
    
    def list_models(self) -> List[Dict]:
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                logger.info(f"Found {len(models)} models")
                return models
            logger.warning(f"Failed to list models, status: {response.status_code}")
            return []
        except requests.exceptions.Timeout:
            logger.error("Timeout listing models")
            return []
        except requests.exceptions.ConnectionError:
            logger.error("Connection error listing models")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing models: {str(e)}")
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
            logger.warning(f"Failed to get model info for {model_name}, status: {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error getting model info: {str(e)}")
            return None
    
    def pull_model(self, model_name: str, max_retries: int = 3) -> Generator[str, None, None]:
        for attempt in range(max_retries):
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
                return
            except requests.exceptions.Timeout:
                logger.warning(f"Pull timeout, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(5)
            except Exception as e:
                logger.error(f"Error pulling model: {str(e)}")
                yield f"Error: {str(e)}"
                return
    
    def chat(self, model: str, messages: List[Dict], 
             system_prompt: Optional[str] = None, max_retries: int = 3) -> Generator[str, None, None]:
        self.current_model = model
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": True
        }
        
        for attempt in range(max_retries):
            try:
                with requests.post(
                    f"{self.base_url}/chat",
                    json=payload,
                    stream=True,
                    timeout=120
                ) as r:
                    for line in r.iter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                if "message" in data:
                                    content = data["message"].get("content", "")
                                    if content:
                                        yield content
                                if data.get("done", False):
                                    break
                            except json.JSONDecodeError:
                                logger.warning("Invalid JSON chunk received")
                                continue
                    return
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                continue
            except requests.exceptions.Timeout:
                logger.warning(f"Chat timeout, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                continue
            except Exception as e:
                logger.error(f"Unexpected error in chat: {str(e)}")
                yield f"Error: {str(e)}"
                return
        
        yield f"Error: Failed after {max_retries} attempts. Check if Ollama is running."
    
    def generate(self, model: str, prompt: str, 
                 system_prompt: Optional[str] = None, max_retries: int = 3) -> Generator[str, None, None]:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True
        }
        if system_prompt:
            payload["system"] = system_prompt
            
        for attempt in range(max_retries):
            try:
                with requests.post(
                    f"{self.base_url}/generate",
                    json=payload,
                    stream=True,
                    timeout=120
                ) as r:
                    for line in r.iter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                if "response" in data:
                                    yield data["response"]
                                if data.get("done", False):
                                    break
                            except json.JSONDecodeError:
                                continue
                    return
            except Exception as e:
                logger.error(f"Error in generate: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                yield f"Error: {str(e)}"
                return
