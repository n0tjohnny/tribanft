"""
TribanFT File Locking Utility

Provides advisory file locking for concurrent operation safety.

Uses fcntl.flock() for advisory locks to prevent race conditions in:
- Cache file updates (ipinfo_cache)
- Statistics file updates
- Blacklist read-modify-write operations

Author: TribanFT Project
License: GNU GPL v3
"""

import fcntl
import os
import time
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class FileLockError(Exception):
    """Raised when file lock cannot be acquired within timeout."""
    pass


@contextmanager
def file_lock(lock_path: Path, timeout: int = 30, description: str = "operation"):
    """
    Advisory file lock with timeout and exponential backoff.
    
    Acquires an exclusive lock on the specified lock file. If the lock
    cannot be acquired immediately, retries with exponential backoff
    until timeout is reached.
    
    Args:
        lock_path: Path to lock file (will be created if doesn't exist)
        timeout: Maximum seconds to wait for lock (default: 30)
        description: Human-readable description for logging
        
    Yields:
        None (lock is held during context manager scope)
        
    Raises:
        FileLockError: If lock cannot be acquired within timeout
        
    Example:
        >>> lock_file = Path("/var/lib/tribanft/.ipinfo.lock")
        >>> with file_lock(lock_file, timeout=30, description="cache update"):
        ...     # Critical section - modify cache files
        ...     update_cache()
    """
    logger = logging.getLogger(__name__)
    lock_file = None
    lock_acquired = False
    
    try:
        # Ensure lock file exists and parent directories are created
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(lock_path, 'a+')
        
        # Try to acquire lock with exponential backoff
        start_time = time.time()
        retry_delay = 0.1  # Start with 100ms
        attempts = 0
        
        while True:
            try:
                # Try non-blocking exclusive lock
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_acquired = True
                logger.debug(f"Lock acquired for {description} (attempt {attempts + 1})")
                break
                
            except BlockingIOError:
                attempts += 1
                elapsed = time.time() - start_time
                
                if elapsed >= timeout:
                    raise FileLockError(
                        f"Failed to acquire lock for {description} after {timeout}s "
                        f"({attempts} attempts)"
                    )
                
                # Log retry attempts (but not too frequently)
                if attempts in [1, 5, 10, 20] or attempts % 50 == 0:
                    logger.warning(
                        f"Waiting for lock: {description} "
                        f"(attempt {attempts}, {elapsed:.1f}s elapsed)"
                    )
                
                # Sleep with exponential backoff (cap at 2 seconds)
                time.sleep(min(retry_delay, 2.0))
                retry_delay *= 1.5
        
        # Lock acquired, write PID and timestamp for debugging
        # Note: This is safe from race conditions because we hold an exclusive lock
        try:
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(f"{os.getpid()}:{time.time()}\n")
            lock_file.flush()
        except Exception as e:
            logger.warning(f"Non-critical: failed to write lock metadata: {e}")
        
        # Yield control to context manager body
        yield
        
    finally:
        # Always release lock and close file
        if lock_file:
            if lock_acquired:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    logger.debug(f"Lock released for {description}")
                except Exception as e:
                    logger.warning(f"Error releasing lock: {e}")
            
            try:
                lock_file.close()
            except Exception as e:
                logger.warning(f"Error closing lock file: {e}")


def cleanup_stale_lock(lock_path: Path, max_age_seconds: int = 300) -> bool:
    """
    Detect and clean up stale lock files.
    
    A lock is considered stale if:
    - Lock file is older than max_age_seconds (default: 5 minutes)
    - PID in lock file is not running (if available)
    
    Args:
        lock_path: Path to lock file
        max_age_seconds: Maximum age before lock is considered stale (default: 300 = 5 minutes)
        
    Returns:
        True if lock was cleaned up, False otherwise
        
    Example:
        >>> lock_file = Path("/var/lib/tribanft/.ipinfo.lock")
        >>> if cleanup_stale_lock(lock_file):
        ...     logger.info("Cleaned up stale lock file")
    """
    logger = logging.getLogger(__name__)
    
    if not lock_path.exists():
        return False
    
    try:
        # Check file age
        file_stat = lock_path.stat()
        file_age = time.time() - file_stat.st_mtime
        
        if file_age < max_age_seconds:
            logger.debug(f"Lock file age ({file_age:.1f}s) is within threshold ({max_age_seconds}s)")
            return False
        
        # Try to extract PID from lock file
        try:
            with open(lock_path, 'r') as f:
                content = f.read().strip()
                if ':' in content:
                    pid_str = content.split(':')[0]
                    pid = int(pid_str)
                    
                    # Check if process is still running
                    try:
                        os.kill(pid, 0)  # Signal 0 doesn't kill, just checks existence
                        logger.debug(f"Process {pid} from lock file is still running")
                        return False
                    except OSError:
                        # Process doesn't exist
                        logger.info(f"Lock file references dead process {pid}")
        except (ValueError, IndexError, FileNotFoundError):
            # Can't extract PID or file disappeared
            pass
        
        # Lock is stale - remove it
        logger.warning(
            f"🧹 Removing stale lock file (age: {file_age:.1f}s, "
            f"threshold: {max_age_seconds}s): {lock_path}"
        )
        lock_path.unlink()
        return True
        
    except Exception as e:
        logger.error(f"Error checking/cleaning stale lock: {e}")
        return False


class FileLockContext:
    """
    Reusable file lock context for multiple operations.
    
    Use when you need to acquire the same lock multiple times
    with consistent configuration.
    
    Example:
        >>> cache_lock = FileLockContext("/var/lib/tribanft/.cache.lock", timeout=30)
        >>> with cache_lock("update results"):
        ...     save_results()
        >>> with cache_lock("update stats"):
        ...     save_stats()
    """
    
    def __init__(self, lock_path: Path, timeout: int = 30):
        """
        Initialize reusable lock context.
        
        Args:
            lock_path: Path to lock file
            timeout: Default timeout in seconds
        """
        self.lock_path = Path(lock_path)
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def __call__(self, description: str = "operation", timeout: Optional[int] = None):
        """
        Create lock context manager for specific operation.
        
        Args:
            description: Human-readable operation description
            timeout: Override default timeout (optional)
            
        Returns:
            Context manager for file lock
        """
        return file_lock(
            self.lock_path,
            timeout=timeout or self.timeout,
            description=description
        )
