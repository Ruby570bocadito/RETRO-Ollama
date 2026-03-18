"""Tests for rate_limit module."""

import pytest
import time
from src.tools.rate_limit import (
    RateLimiter,
    RateLimitExceeded,
    exponential_backoff,
    with_rate_limit,
)


class TestRateLimiter:
    """Test RateLimiter."""

    def test_creation(self):
        """Test creating a rate limiter."""
        limiter = RateLimiter(max_calls=10, period=60.0)
        assert limiter.max_calls == 10
        assert limiter.period == 60.0

    def test_is_allowed(self):
        """Test allowed request."""
        limiter = RateLimiter(max_calls=5, period=60.0)
        assert limiter.is_allowed("test") is True

    def test_is_allowed_limit(self):
        """Test rate limit."""
        limiter = RateLimiter(max_calls=2, period=60.0)
        assert limiter.is_allowed("test") is True
        assert limiter.is_allowed("test") is True
        assert limiter.is_allowed("test") is False

    def test_wait_time(self):
        """Test wait time calculation."""
        limiter = RateLimiter(max_calls=1, period=60.0)
        limiter.is_allowed("test")
        wait = limiter.wait_time("test")
        assert wait >= 0

    def test_reset(self):
        """Test reset."""
        limiter = RateLimiter(max_calls=1, period=60.0)
        limiter.is_allowed("test")
        limiter.reset("test")
        assert limiter.is_allowed("test") is True

    def test_get_remaining(self):
        """Test get remaining calls."""
        limiter = RateLimiter(max_calls=5, period=60.0)
        assert limiter.get_remaining("test") == 5
        limiter.is_allowed("test")
        assert limiter.get_remaining("test") == 4


class TestExponentialBackoff:
    """Test exponential backoff."""

    def test_success(self):
        """Test successful call."""
        @exponential_backoff(max_retries=3, base_delay=0.1)
        def success_func():
            return "success"
        
        result = success_func()
        assert result == "success"

    def test_retry(self):
        """Test retry on failure."""
        call_count = 0
        
        @exponential_backoff(max_retries=3, base_delay=0.1)
        def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"
        
        result = fail_twice()
        assert result == "success"
        assert call_count == 3

    def test_max_retries(self):
        """Test max retries exceeded."""
        call_count = 0
        
        @exponential_backoff(max_retries=2, base_delay=0.1)
        def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("Permanent error")
        
        with pytest.raises(ValueError):
            always_fail()
        assert call_count == 2


class TestWithRateLimit:
    """Test with_rate_limit decorator."""

    def test_rate_limit_exceeded(self):
        """Test rate limit exceeded."""
        limiter = RateLimiter(max_calls=1, period=60.0)
        
        @with_rate_limit(max_calls=1, period=60.0)
        def test_func():
            return "success"
        
        result = test_func()
        assert result == "success"
        
        with pytest.raises(RateLimitExceeded):
            test_func()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
