import time
import logging
from functools import wraps
from typing import Callable, Any, Optional, Dict

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, max_calls: int = 15, period: float = 60.0):
        self.max_calls = max_calls
        self.period = period
        self.calls: Dict[str, list] = {}

    def is_allowed(self, key: str = "default") -> bool:
        now = time.time()
        if key not in self.calls:
            self.calls[key] = []
        
        self.calls[key] = [t for t in self.calls[key] if now - t < self.period]
        
        if len(self.calls[key]) < self.max_calls:
            self.calls[key].append(now)
            return True
        return False

    def wait_time(self, key: str = "default") -> float:
        if key not in self.calls or not self.calls[key]:
            return 0.0
        oldest = min(self.calls[key])
        return max(0.0, self.period - (time.time() - oldest))


def exponential_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential_base: float = 2.0
) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries} failed: {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(f"All {max_retries} attempts failed: {e}")
            raise last_exception
        return wrapper
    return decorator


def with_rate_limit(max_calls: int = 15, period: float = 60.0) -> Callable:
    limiter = RateLimiter(max_calls, period)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            key = func.__name__
            if not limiter.is_allowed(key):
                wait = limiter.wait_time(key)
                logger.warning(f"Rate limit reached for {key}. Wait {wait:.1f}s")
                raise Exception(f"Rate limit exceeded. Wait {wait:.1f}s")
            return func(*args, **kwargs)
        return wrapper
    return decorator


shodan_limiter = RateLimiter(max_calls=15, period=60)
virustotal_limiter = RateLimiter(max_calls=4, period=60)
hunter_limiter = RateLimiter(max_calls=50, period=3600)
censys_limiter = RateLimiter(max_calls=5, period=60)
securitytrails_limiter = RateLimiter(max_calls=100, period=3600)
