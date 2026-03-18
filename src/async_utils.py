"""Async utilities for RETRO-Ollama."""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from typing import Any, Callable, Coroutine, List, Optional, TypeVar

T = TypeVar("T")


def run_in_executor(func: Callable[..., T]) -> Callable[..., Coroutine[Any, Any, T]]:
    """Decorator to run blocking function in executor."""
    
    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, partial(func, *args, **kwargs)
        )
    return wrapper


class AsyncRunner:
    """Run multiple async tasks with concurrency control."""

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore: Optional[asyncio.Semaphore] = None

    async def run(self, coro: Coroutine) -> Any:
        """Run a single coroutine."""
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async with self.semaphore:
            return await coro

    async def run_many(self, coros: List[Coroutine]) -> List[Any]:
        """Run multiple coroutines concurrently."""
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def limited_coro(coro: Coroutine) -> Any:
            async with self.semaphore:
                return await coro
        
        tasks = [limited_coro(coro) for coro in coros]
        return await asyncio.gather(*tasks)

    async def run_with_timeout(
        self,
        coro: Coroutine,
        timeout: float,
    ) -> Any:
        """Run coroutine with timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            raise AsyncTimeout(f"Operation timed out after {timeout}s")


class AsyncTimeout(Exception):
    """Async operation timeout."""
    pass


class RateLimiterAsync:
    """Async rate limiter."""

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls: List[float] = []
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self.lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.period]
            
            if len(self.calls) >= self.max_calls:
                wait_time = self.period - (now - self.calls[0])
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    now = time.time()
                    self.calls = [t for t in self.calls if now - t < self.period]
            
            self.calls.append(now)

    async def __aenter__(self) -> "RateLimiterAsync":
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


async def gather_with_concurrency(
    n: int,
    *coros: Coroutine,
) -> List[Any]:
    """Gather coroutines with limited concurrency."""
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro: Coroutine) -> Any:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(coro) for coro in coros))


async def retry_async(
    func: Callable[..., Coroutine[Any, Any, T]],
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Retry async function with exponential backoff."""
    last_exception: Optional[Exception] = None
    
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                await asyncio.sleep(delay * (backoff ** attempt))
    
    raise last_exception


class AsyncBatch:
    """Process items in async batches."""

    def __init__(self, batch_size: int = 10):
        self.batch_size = batch_size

    async def process(
        self,
        items: List[Any],
        processor: Callable[[Any], Coroutine[Any, Any, Any]],
    ) -> List[Any]:
        """Process items in batches."""
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_results = await asyncio.gather(
                *[processor(item) for item in batch],
                return_exceptions=True,
            )
            results.extend(batch_results)
        
        return results


def create_task_group(tasks: List[Callable[..., Coroutine]]) -> List[asyncio.Task]:
    """Create a group of async tasks."""
    return [asyncio.create_task(task()) for task in tasks]


async def wait_for_all(
    tasks: List[asyncio.Task],
    timeout: Optional[float] = None,
) -> List[Any]:
    """Wait for all tasks to complete."""
    if timeout:
        done, pending = await asyncio.wait(
            tasks,
            timeout=timeout,
            return_when=asyncio.ALL_COMPLETED,
        )
        for task in pending:
            task.cancel()
        return [task.result() for task in done]
    else:
        return await asyncio.gather(*tasks, return_exceptions=True)
