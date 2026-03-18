"""Tests for cache module."""

import pytest
import time
from pathlib import Path
import tempfile
import shutil

from src.cache import APICache, CacheEntry, cached_api_call


class TestCacheEntry:
    """Test CacheEntry class."""

    def test_cache_entry_creation(self):
        """Create a cache entry."""
        entry = CacheEntry(data={"key": "value"}, timestamp=time.time(), ttl=60)
        assert entry.data == {"key": "value"}
        assert entry.ttl == 60

    def test_cache_entry_not_expired(self):
        """Test entry is not expired."""
        entry = CacheEntry(data="test", timestamp=time.time(), ttl=60)
        assert entry.is_expired() is False

    def test_cache_entry_expired(self):
        """Test entry is expired."""
        entry = CacheEntry(data="test", timestamp=time.time() - 100, ttl=60)
        assert entry.is_expired() is True

    def test_cache_entry_to_dict(self):
        """Convert entry to dict."""
        entry = CacheEntry(data="test", timestamp=1000.0, ttl=60)
        data = entry.to_dict()
        assert data["data"] == "test"
        assert data["timestamp"] == 1000.0
        assert data["ttl"] == 60

    def test_cache_entry_from_dict(self):
        """Create entry from dict."""
        data = {"data": "test", "timestamp": 1000.0, "ttl": 60}
        entry = CacheEntry.from_dict(data)
        assert entry.data == "test"
        assert entry.timestamp == 1000.0
        assert entry.ttl == 60


class TestAPICache:
    """Test APICache class."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def cache(self, temp_cache_dir):
        """Create cache instance."""
        return APICache(cache_dir=temp_cache_dir, default_ttl=60)

    def test_cache_set_and_get(self, cache):
        """Set and get cache."""
        cache.set("test", "key1", {"value": 123})
        result = cache.get("test", "key1")
        assert result == {"value": 123}

    def test_cache_miss(self, cache):
        """Test cache miss."""
        result = cache.get("test", "nonexistent")
        assert result is None

    def test_cache_expiration(self, cache):
        """Test cache expiration."""
        cache.set("test", "key1", "value", ttl=1)
        time.sleep(2)
        result = cache.get("test", "key1")
        assert result is None

    def test_cache_clear_all(self, cache):
        """Clear all cache."""
        cache.set("test", "key1", "value1")
        
        count = cache.clear_all()
        assert cache.get("test", "key1") is None

    def test_cache_stats(self, cache):
        """Get cache statistics."""
        cache.set("test", "key1", "value1")
        cache.set("test", "key2", "value2")
        
        stats = cache.get_stats()
        assert stats["disk_entries"] >= 2
        assert stats["memory_entries"] >= 2

    def test_cache_cleanup_expired(self, cache):
        """Cleanup expired entries."""
        cache.set("test", "key1", "value1", ttl=1)
        cache.set("test", "key2", "value2", ttl=60)
        
        time.sleep(2)
        
        count = cache.cleanup_expired()
        assert count >= 1
        assert cache.get("test", "key2") == "value2"


class TestCachedDecorator:
    """Test cached_api_call decorator."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def cache(self, temp_cache_dir):
        """Create cache instance with short TTL."""
        return APICache(cache_dir=temp_cache_dir, default_ttl=1)

    def test_cached_decorator(self, cache, monkeypatch):
        """Test cached decorator."""
        monkeypatch.setattr("src.cache.api_cache", cache)
        
        call_count = 0
        
        @cached_api_call("test", ttl=60)
        def get_data(param):
            nonlocal call_count
            call_count += 1
            return {"param": param, "value": 123}
        
        result1 = get_data("key1")
        assert result1 == {"param": "key1", "value": 123}
        assert call_count == 1
        
        result2 = get_data("key1")
        assert result2 == {"param": "key1", "value": 123}
        assert call_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
