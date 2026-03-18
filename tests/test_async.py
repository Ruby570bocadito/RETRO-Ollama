"""Tests for async utilities."""

import pytest
import asyncio
from src.async_utils import (
    AsyncRunner,
    RateLimiterAsync,
    AsyncTimeout,
    gather_with_concurrency,
    retry_async,
    AsyncBatch,
)


@pytest.mark.asyncio
class TestAsyncRunner:
    """Test AsyncRunner."""

    async def test_run_single(self):
        """Test running single coroutine."""
        runner = AsyncRunner(max_concurrent=5)
        
        async def dummy():
            return "result"
        
        result = await runner.run(dummy())
        assert result == "result"

    async def test_run_many(self):
        """Test running multiple coroutines."""
        runner = AsyncRunner(max_concurrent=5)
        
        async def dummy(x):
            return x * 2
        
        coros = [dummy(i) for i in range(5)]
        results = await runner.run_many(coros)
        
        assert results == [0, 2, 4, 6, 8]


@pytest.mark.asyncio
class TestRateLimiterAsync:
    """Test RateLimiterAsync."""

    async def test_acquire(self):
        """Test acquiring permission."""
        limiter = RateLimiterAsync(max_calls=5, period=1.0)
        await limiter.acquire()
        assert len(limiter.calls) == 1

    async def test_context_manager(self):
        """Test using as context manager."""
        async with RateLimiterAsync(max_calls=5, period=1.0):
            pass


@pytest.mark.asyncio
class TestGatherWithConcurrency:
    """Test gather_with_concurrency."""

    async def test_concurrent(self):
        """Test gathering with concurrency."""
        counter = 0
        
        async def increment():
            nonlocal counter
            await asyncio.sleep(0.01)
            counter += 1
            return counter
        
        results = await gather_with_concurrency(3, *[
            increment() for _ in range(5)
        ])
        
        assert counter == 5


@pytest.mark.asyncio
class TestRetryAsync:
    """Test retry_async."""

    async def test_success(self):
        """Test successful retry."""
        call_count = 0
        
        async def success():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = await retry_async(success, max_retries=3)
        
        assert result == "success"
        assert call_count == 1

    async def test_retry(self):
        """Test retry on failure."""
        call_count = 0
        
        async def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("fail")
            return "success"
        
        result = await retry_async(fail_twice, max_retries=3, delay=0.01)
        
        assert result == "success"
        assert call_count == 3


@pytest.mark.asyncio
class TestAsyncBatch:
    """Test AsyncBatch."""

    async def test_process(self):
        """Test batch processing."""
        batch = AsyncBatch(batch_size=2)
        
        async def processor(x):
            return x * 2
        
        items = [1, 2, 3, 4, 5]
        results = await batch.process(items, processor)
        
        assert results == [2, 4, 6, 8, 10]


@pytest.mark.asyncio
class TestAsyncTimeout:
    """Test async timeout."""

    async def test_timeout(self):
        """Test timeout."""
        async def slow():
            await asyncio.sleep(10)
        
        with pytest.raises((AsyncTimeout, TimeoutError)):
            result = await asyncio.wait_for(slow(), timeout=0.01)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
