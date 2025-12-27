"""
TribanFT Real-Time Log Watcher

Monitors log files for changes using inotify (Linux) via watchdog library.
Provides immediate detection instead of periodic polling.

Features:
- File system event monitoring (inotify/kqueue)
- Incremental log reading (tracks byte offset)
- File rotation detection
- Rate limiting for DoS protection
- Thread-safe file access
- Automatic fallback to periodic mode if watchdog unavailable

Author: TribanFT Project
License: GNU GPL v3
"""

import os
import time
import threading
import logging
import json
import tempfile
from pathlib import Path
from typing import Dict, Callable, Optional, List, Set
from datetime import datetime, timedelta

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileModifiedEvent = None
    # Create dummy base class when watchdog unavailable
    class FileSystemEventHandler:
        pass


class LogFileHandler(FileSystemEventHandler):
    """
    Event handler for log file modifications.

    Handles:
    - File modifications (new log entries)
    - File rotation (truncation/recreation)
    - Debouncing rapid writes
    """

    def __init__(self, callback: Callable[[str], None], debounce_interval: float = 1.0):
        """
        Initialize log file event handler.

        Args:
            callback: Function to call when file is modified (receives file path)
            debounce_interval: Minimum seconds between processing same file
        """
        super().__init__()
        self.callback = callback
        self.debounce_interval = debounce_interval
        self.last_processed: Dict[str, float] = {}
        self.logger = logging.getLogger(__name__)

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        file_path = event.src_path

        # Debouncing: ignore rapid successive modifications
        now = time.time()
        last_time = self.last_processed.get(file_path, 0)

        if now - last_time < self.debounce_interval:
            return

        self.last_processed[file_path] = now

        # Trigger callback
        try:
            self.callback(file_path)
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")


class LogWatcher:
    """
    Real-time log file watcher using filesystem events.

    Monitors specified log files for changes and triggers callbacks
    when new content is written. Tracks file positions to enable
    incremental reading.

    Thread-safe implementation with per-file locking.
    """

    def __init__(self, config, callback: Callable[[str, int, int], None]):
        """
        Initialize log watcher.

        Args:
            config: Configuration object with realtime settings
            callback: Function(file_path, from_offset, to_offset) called on file change
        """
        self.config = config
        self.callback = callback
        self.logger = logging.getLogger(__name__)

        # File position tracking (file_path -> byte offset)
        self.positions: Dict[str, int] = {}

        # File locks for thread safety
        self.file_locks: Dict[str, threading.Lock] = {}

        # Rate limiting
        self.event_count = 0
        self.event_window_start = time.time()
        self.max_events_per_second = getattr(config, 'max_events_per_second', 1000)
        self.paused_until: Optional[float] = None

        # Rate limit state persistence (Fix #20)
        self.state_file = Path(config.state_dir) / 'log_watcher_rate_limit.json'
        self._load_rate_limit_state()

        # Watchdog observer
        self.observer: Optional[Observer] = None
        self.watched_paths: Set[str] = set()

        # Debounce interval
        self.debounce_interval = getattr(config, 'debounce_interval', 1.0)

    def is_available(self) -> bool:
        """Check if watchdog is available on this system."""
        return WATCHDOG_AVAILABLE

    def add_file(self, file_path: str, initial_offset: int = None):
        """
        Add a file to watch.

        Args:
            file_path: Path to log file
            initial_offset: Starting byte offset (None = end of file)
        """
        file_path = os.path.abspath(file_path)

        if not os.path.exists(file_path):
            self.logger.warning(f"File does not exist, will watch when created: {file_path}")
            # Still add to watch list - file might be created later

        # Initialize position
        if initial_offset is None:
            # Start from end of file (only process new entries)
            try:
                initial_offset = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            except OSError:
                initial_offset = 0

        self.positions[file_path] = initial_offset
        self.file_locks[file_path] = threading.Lock()
        self.watched_paths.add(file_path)

        self.logger.info(f"Watching file: {file_path} (offset: {initial_offset})")

    def start(self):
        """Start watching files."""
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("watchdog library not available")

        if self.observer is not None:
            self.logger.warning("Observer already running")
            return

        # Create observer
        self.observer = Observer()

        # Group files by directory for efficient watching
        directories: Dict[str, List[str]] = {}
        for file_path in self.watched_paths:
            dir_path = os.path.dirname(file_path)
            if dir_path not in directories:
                directories[dir_path] = []
            directories[dir_path].append(file_path)

        # Schedule handlers for each directory
        for dir_path, files in directories.items():
            handler = LogFileHandler(
                callback=self._on_file_modified,
                debounce_interval=self.debounce_interval
            )

            try:
                self.observer.schedule(handler, dir_path, recursive=False)
                self.logger.info(f"Monitoring directory: {dir_path}")
            except Exception as e:
                self.logger.error(f"Failed to watch directory {dir_path}: {e}")

        # Start observer thread
        self.observer.start()
        self.logger.info("Real-time log monitoring started")

    def stop(self):
        """Stop watching files."""
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
            self.logger.info("Real-time log monitoring stopped")

    def _on_file_modified(self, file_path: str):
        """
        Internal callback when file is modified.

        Handles file rotation, rate limiting, and position tracking.
        """
        # Only process files we're watching
        if file_path not in self.watched_paths:
            return

        # Check if paused (rate limit backoff)
        if self.paused_until is not None:
            if time.time() < self.paused_until:
                return
            else:
                self.logger.info("Rate limit backoff ended, resuming real-time monitoring")
                self.paused_until = None

        # Rate limiting check
        if not self._check_rate_limit():
            return

        # Thread-safe file processing
        lock = self.file_locks.get(file_path)
        if lock is None:
            self.logger.warning(f"No lock for file: {file_path}")
            return

        with lock:
            try:
                # Get current file size
                if not os.path.exists(file_path):
                    self.logger.warning(f"File disappeared: {file_path}")
                    return

                current_size = os.path.getsize(file_path)
                last_position = self.positions.get(file_path, 0)

                # Detect file rotation (file size decreased)
                if current_size < last_position:
                    self.logger.info(f"Log rotation detected: {file_path}")
                    self.logger.info(f"  Previous size: {last_position}, Current size: {current_size}")
                    last_position = 0
                    self.positions[file_path] = 0

                # Check if there's new content
                if current_size == last_position:
                    return

                # Update position BEFORE callback to prevent race condition (H2 fix)
                # This ensures concurrent modifications see the updated position
                # even if the callback takes time to execute
                self.positions[file_path] = current_size

                # Trigger callback with offset range
                # If callback fails, position is already updated (at-most-once delivery)
                self.callback(file_path, last_position, current_size)

            except Exception as e:
                self.logger.error(f"Error processing file modification {file_path}: {e}")

    def _load_rate_limit_state(self):
        """
        Load rate limit state from disk (survives restarts).

        FIX #20: Persists rate limit backoff across daemon restarts
        to prevent DoS bypass via restart cycling.
        """
        if not self.state_file.exists():
            return

        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)

            # Restore paused_until if still valid
            paused_until = state.get('paused_until')
            if paused_until and paused_until > time.time():
                self.paused_until = paused_until
                remaining = int(paused_until - time.time())
                self.logger.warning(
                    f"Rate limit backoff restored: {remaining}s remaining "
                    f"(from previous session - DoS protection active)"
                )
            else:
                self.paused_until = None

        except Exception as e:
            self.logger.warning(f"Could not load rate limit state: {e}")

    def _save_rate_limit_state(self):
        """
        Save rate limit state to disk for persistence across restarts.

        FIX #20: Uses atomic write pattern (tempfile + rename).
        """
        try:
            state = {
                'paused_until': self.paused_until,
                'last_saved': time.time()
            }

            # Atomic write
            fd, temp_path = tempfile.mkstemp(
                dir=self.state_file.parent,
                prefix=".rate_limit.",
                suffix=".tmp"
            )

            with os.fdopen(fd, 'w') as f:
                json.dump(state, f)

            os.replace(temp_path, self.state_file)

        except Exception as e:
            self.logger.warning(f"Could not save rate limit state: {e}")

    def _check_rate_limit(self) -> bool:
        """
        Check if rate limit is exceeded.

        FIX #20: Now persists backoff state to survive restarts.

        Returns:
            True if processing should continue, False if rate limited
        """
        now = time.time()

        # Check if paused (Fix #20: restored from state file)
        if self.paused_until and now < self.paused_until:
            return False

        # Reset window every second
        if now - self.event_window_start >= 1.0:
            self.event_count = 0
            self.event_window_start = now

        self.event_count += 1

        # Check if limit exceeded
        if self.event_count > self.max_events_per_second:
            backoff_seconds = getattr(self.config, 'rate_limit_backoff', 30)
            self.paused_until = now + backoff_seconds

            # PERSIST STATE (Fix #20)
            self._save_rate_limit_state()

            self.logger.warning(
                f"Rate limit exceeded ({self.event_count} events/sec > {self.max_events_per_second})"
            )
            self.logger.warning(f"Pausing real-time monitoring for {backoff_seconds}s (DoS protection)")

            return False

        return True

    def get_position(self, file_path: str) -> int:
        """Get current byte offset for a file (thread-safe)."""
        file_path = os.path.abspath(file_path)
        lock = self.file_locks.get(file_path)
        if lock:
            with lock:
                return self.positions.get(file_path, 0)
        else:
            # File not watched yet, return 0
            return self.positions.get(file_path, 0)

    def set_position(self, file_path: str, offset: int):
        """Manually set byte offset for a file (thread-safe)."""
        file_path = os.path.abspath(file_path)
        lock = self.file_locks.get(file_path)
        if lock:
            with lock:
                self.positions[file_path] = offset
                self.logger.debug(f"Position updated: {file_path} -> {offset}")
        else:
            # File not watched yet, set position anyway
            self.positions[file_path] = offset
            self.logger.debug(f"Position updated (no lock): {file_path} -> {offset}")

    def get_all_positions(self) -> Dict[str, int]:
        """Get all file positions (for state persistence)."""
        return self.positions.copy()

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
