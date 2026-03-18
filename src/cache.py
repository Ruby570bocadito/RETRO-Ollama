"""Cache system for external APIs."""

import hashlib
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Union

from src.config.settings import BASE_DIR
from src.logging_config import get_logger

logger = get_logger("ptai.cache")


class CacheEntry:
    """Cache entry with expiration."""

    def __init__(
        self,
        data: Any,
        timestamp: float,
        ttl: int = 3600,
    ):
        self.data = data
        self.timestamp = timestamp
        self.ttl = ttl

    def is_expired(self) -> bool:
        """Check if entry is expired."""
        return time.time() > (self.timestamp + self.ttl)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "data": self.data,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary."""
        return cls(
            data=data["data"],
            timestamp=data["timestamp"],
            ttl=data["ttl"],
        )


class APICache:
    """Cache for external API responses."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        default_ttl: int = 3600,
    ):
        self.cache_dir = cache_dir or (BASE_DIR / ".cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self._memory_cache: Dict[str, CacheEntry] = {}

    def _get_key(self, namespace: str, identifier: str) -> str:
        """Generate cache key."""
        key_string = f"{namespace}:{identifier}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path."""
        return self.cache_dir / f"{key}.json"

    def get(
        self,
        namespace: str,
        identifier: str,
    ) -> Optional[Any]:
        """Get cached data."""
        key = self._get_key(namespace, identifier)

        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if not entry.is_expired():
                logger.debug(f"Cache hit (memory): {namespace}:{identifier}")
                return entry.data
            else:
                del self._memory_cache[key]

        cache_file = self._get_cache_file(key)
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                entry = CacheEntry.from_dict(cached_data)
                if not entry.is_expired():
                    self._memory_cache[key] = entry
                    logger.debug(f"Cache hit (disk): {namespace}:{identifier}")
                    return entry.data
                else:
                    cache_file.unlink()
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Cache read error: {e}")

        logger.debug(f"Cache miss: {namespace}:{identifier}")
        return None

    def set(
        self,
        namespace: str,
        identifier: str,
        data: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """Set cached data."""
        key = self._get_key(namespace, identifier)
        ttl = ttl or self.default_ttl
        entry = CacheEntry(data=data, timestamp=time.time(), ttl=ttl)

        self._memory_cache[key] = entry

        cache_file = self._get_cache_file(key)
        with open(cache_file, "w") as f:
            json.dump(entry.to_dict(), f)

        logger.debug(f"Cache set: {namespace}:{identifier} (ttl={ttl}s)")

    def delete(
        self,
        namespace: str,
        identifier: str,
    ) -> bool:
        """Delete cached data."""
        key = self._get_key(namespace, identifier)

        if key in self._memory_cache:
            del self._memory_cache[key]

        cache_file = self._get_cache_file(key)
        if cache_file.exists():
            cache_file.unlink()
            return True

        return False

    def clear_namespace(self, namespace: str) -> int:
        """Clear all cached data in a namespace."""
        count = 0
        
        keys_to_delete = []
        for key in self._memory_cache:
            keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self._memory_cache[key]
            count += 1

        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        logger.info(f"Cleared {count} entries from namespace: {namespace}")
        return count

    def clear_all(self) -> int:
        """Clear all cached data."""
        count = len(self._memory_cache)
        self._memory_cache.clear()

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except OSError:
                pass

        logger.info(f"Cleared all cache: {count} entries")
        return count

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        count = 0

        for key in list(self._memory_cache.keys()):
            if self._memory_cache[key].is_expired():
                del self._memory_cache[key]
                count += 1

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                entry = CacheEntry.from_dict(cached_data)
                if entry.is_expired():
                    cache_file.unlink()
                    count += 1
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        logger.info(f"Cleaned up {count} expired cache entries")
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_files = len(list(self.cache_dir.glob("*.json")))
        memory_entries = len(self._memory_cache)

        total_size = sum(
            f.stat().st_size
            for f in self.cache_dir.glob("*.json")
            if f.exists()
        )

        return {
            "disk_entries": total_files,
            "memory_entries": memory_entries,
            "total_size_bytes": total_size,
            "cache_dir": str(self.cache_dir),
        }


api_cache = APICache()


def cached_api_call(
    namespace: str,
    ttl: int = 3600,
):
    """Decorator for caching API calls."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            identifier = "_".join(str(a) for a in args)
            cached = api_cache.get(namespace, identifier)
            if cached is not None:
                return cached
            result = func(*args, **kwargs)
            api_cache.set(namespace, identifier, result, ttl)
            return result

        return wrapper

    return decorator
