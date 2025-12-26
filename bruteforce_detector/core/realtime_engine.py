"""
TribanFT Real-Time Detection Engine

Extends BruteForceDetectorEngine with real-time log monitoring capabilities.
Provides automatic fallback to periodic mode if real-time unavailable.

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import time
import threading
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from ..models import SecurityEvent, DetectionResult
from .log_watcher import LogWatcher, WATCHDOG_AVAILABLE


class RealtimeDetectionMixin:
    """
    Mixin to add real-time monitoring to BruteForceDetectorEngine.

    Provides:
    - Real-time log monitoring with inotify/kqueue
    - Automatic fallback to periodic mode
    - File position tracking for incremental parsing
    - Graceful degradation on errors
    """

    def _init_realtime(self):
        """
        Initialize real-time monitoring components.

        Called during engine __init__. Sets up LogWatcher if available,
        otherwise prepares for periodic fallback.
        """
        self.realtime_available = False
        self.log_watcher: Optional[LogWatcher] = None
        self.parser_map = {}  # Maps file paths to parser instances
        self._stop_event = threading.Event()  # RACE CONDITION FIX (C9): Coordinated shutdown

        # Check if watchdog is available
        if not WATCHDOG_AVAILABLE:
            self.logger.warning("Watchdog library not available")
            self.logger.warning(f"Install with: pip install watchdog>=3.0.0")
            self.logger.info(f"Falling back to periodic mode ({self.config.fallback_interval}s interval)")
            return

        # Try to initialize LogWatcher
        try:
            self.log_watcher = LogWatcher(
                config=self.config,
                callback=self._on_log_file_modified
            )

            # Build parser map and add files to watch
            monitored_files = self._get_monitored_files()

            if not monitored_files:
                self.logger.warning("No log files configured for monitoring")
                self.logger.info(f"Falling back to periodic mode ({self.config.fallback_interval}s interval)")
                return

            # Load file positions from state
            state = self.state_manager.get_state()
            positions = state.last_processed_positions if state else {}

            for file_path, parser in monitored_files:
                # Add to watcher
                initial_offset = positions.get(str(file_path))
                self.log_watcher.add_file(str(file_path), initial_offset=initial_offset)

                # Store parser mapping
                self.parser_map[str(file_path)] = parser

            self.realtime_available = True
            self.logger.info("Real-time monitoring initialized successfully")
            self.logger.info(f"Monitoring {len(monitored_files)} log file(s)")

        except Exception as e:
            self.logger.error(f"Failed to initialize real-time monitoring: {e}")
            self.logger.info(f"Falling back to periodic mode ({self.config.fallback_interval}s interval)")
            self.realtime_available = False

    def _get_monitored_files(self) -> List[tuple]:
        """
        Get list of (file_path, parser) tuples for real-time monitoring.

        Uses configuration to determine which files to monitor.

        Returns:
            List of (Path, BaseLogParser) tuples
        """
        files = []

        # Custom file list (override)
        if self.config.monitor_files:
            custom_paths = [p.strip() for p in self.config.monitor_files.split(',')]

            for file_path in custom_paths:
                path_obj = Path(file_path)

                if not path_obj.exists():
                    self.logger.warning(f"Custom monitor file not found: {file_path}")
                    continue

                # Find matching parser
                parser = self._find_parser_for_file(file_path)
                if parser:
                    files.append((path_obj, parser))
                else:
                    self.logger.warning(f"No parser found for custom file: {file_path}")

            return files

        # Auto-detect from configured log paths and enabled monitors
        if self.config.monitor_syslog and self.config.syslog_path:
            path = Path(self.config.syslog_path)
            if path.exists():
                parser = self._find_parser_for_file(str(path))
                if parser:
                    files.append((path, parser))

        if self.config.monitor_mssql and self.config.mssql_error_log_path:
            path = Path(self.config.mssql_error_log_path)
            if path.exists():
                parser = self._find_parser_for_file(str(path))
                if parser:
                    files.append((path, parser))

        if self.config.monitor_apache and self.config.apache_access_log_path:
            path = Path(self.config.apache_access_log_path)
            if path.exists():
                parser = self._find_parser_for_file(str(path))
                if parser:
                    files.append((path, parser))

        if self.config.monitor_nginx and self.config.nginx_access_log_path:
            path = Path(self.config.nginx_access_log_path)
            if path.exists():
                parser = self._find_parser_for_file(str(path))
                if parser:
                    files.append((path, parser))

        return files

    def _find_parser_for_file(self, file_path: str) -> Optional[object]:
        """
        Find parser instance that handles this log file.

        Args:
            file_path: Path to log file

        Returns:
            Parser instance or None
        """
        for parser in self.parsers:
            if str(parser.log_path) == str(file_path):
                return parser
        return None

    def _on_log_file_modified(self, file_path: str, from_offset: int, to_offset: int):
        """
        Callback when log file is modified.

        Parses new content incrementally and triggers detection.

        Args:
            file_path: Path to modified file
            from_offset: Starting byte offset
            to_offset: Ending byte offset
        """
        parser = self.parser_map.get(file_path)

        if not parser:
            self.logger.warning(f"No parser for modified file: {file_path}")
            return

        try:
            # Parse incrementally
            events, final_offset = parser.parse_incremental(from_offset, to_offset)

            if events:
                self.logger.info(f"Real-time: {len(events)} new events from {Path(file_path).name}")

                # Run detectors on new events
                detections = self._run_detectors_on_events(events)

                # Process detections
                if detections:
                    self._process_detections(detections)

        except Exception as e:
            self.logger.error(f"Error processing file modification {file_path}: {e}")

    def _run_detectors_on_events(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Run all enabled detectors on events.

        Args:
            events: List of SecurityEvent objects

        Returns:
            List of DetectionResult objects
        """
        all_detections = []

        # Run plugin detectors
        for detector in self.detectors:
            if not detector.enabled:
                continue

            try:
                detections = detector.detect(events)
                all_detections.extend(detections)
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed: {e}")

        # Run YAML rule engine
        if self.rule_engine:
            try:
                rule_detections = self.rule_engine.apply_rules(events)
                all_detections.extend(rule_detections)
            except Exception as e:
                self.logger.error(f"YAML Rule Engine failed: {e}")

        return all_detections

    def run_realtime(self):
        """
        Run real-time detection daemon with coordinated shutdown.

        RACE CONDITION FIX (C9): Uses threading.Event() for graceful shutdown.
        - Threads check _stop_event before processing
        - No race condition between stop signal and event processing
        - All threads terminate cleanly

        Monitors log files continuously using filesystem events.
        Updates state periodically to persist file positions.
        """
        if not self.realtime_available or not self.log_watcher:
            raise RuntimeError("Real-time monitoring not available")

        self.logger.info("=" * 60)
        self.logger.info("Starting Real-Time Detection Daemon")
        self.logger.info("=" * 60)

        try:
            # Start watching
            self.log_watcher.start()

            # Get initial state
            state = self.state_manager.get_state()

            # Run until stop event is set
            last_state_update = time.time()
            state_update_interval = 60  # Save state every minute
            last_nftables_discovery = time.time()
            nftables_discovery_interval = self.config.nftables_discovery_interval

            # RACE CONDITION FIX: Use Event.wait() instead of while True + sleep
            # This allows immediate response to stop signal
            while not self._stop_event.wait(timeout=5):
                # Periodically save file positions
                now = time.time()
                if now - last_state_update >= state_update_interval:
                    # Update state with current positions
                    if state:
                        state.last_processed_positions = self.log_watcher.get_all_positions()
                        self.state_manager.update_state(state)

                    last_state_update = now

                # Periodically run NFTables auto-discovery
                if (self.config.enable_nftables_update and
                    self.config.nftables_auto_discovery and
                    nftables_discovery_interval > 0):
                    if now - last_nftables_discovery >= nftables_discovery_interval:
                        try:
                            self.logger.info("Running periodic NFTables auto-discovery...")
                            self._enrich_metadata_from_sources()
                            last_nftables_discovery = now
                        except Exception as e:
                            self.logger.error(f"NFTables auto-discovery failed: {e}")
                            # Don't crash real-time monitoring on discovery errors

        except KeyboardInterrupt:
            self.logger.info("Stopping real-time monitoring (Ctrl+C)...")
        finally:
            self.log_watcher.stop()

        self.logger.info("Real-time detection daemon stopped")

    def run_periodic_fallback(self):
        """
        Fallback to periodic mode if real-time unavailable.

        RACE CONDITION FIX (C9): Uses threading.Event() for graceful shutdown.

        Runs detection cycles at regular intervals using traditional
        timestamp-based filtering.
        """
        interval = self.config.fallback_interval

        self.logger.info("=" * 60)
        self.logger.info(f"Running in Periodic Fallback Mode ({interval}s interval)")
        self.logger.info("=" * 60)

        try:
            cycle_count = 0

            # RACE CONDITION FIX: Use Event.wait() instead of while True + sleep
            while not self._stop_event.is_set():
                cycle_count += 1
                self.logger.info(f"Detection cycle #{cycle_count} starting...")

                try:
                    # Run normal detection cycle
                    self.run_detection()
                    self.logger.info(f"Cycle #{cycle_count} completed")

                except Exception as e:
                    self.logger.error(f"Cycle #{cycle_count} failed: {e}")

                # Sleep with stop event check for responsive shutdown
                self.logger.info(f"Sleeping for {interval}s until next cycle...")
                if self._stop_event.wait(timeout=interval):
                    break  # Stop event was set during sleep

        except KeyboardInterrupt:
            self.logger.info("Stopping periodic detection (Ctrl+C)...")

        self.logger.info("Periodic detection stopped")

    def stop(self):
        """
        Stop the real-time detection daemon gracefully.

        RACE CONDITION FIX (C9): Sets stop event to signal all threads to terminate.
        Provides thread-safe coordinated shutdown.

        Can be called from signal handlers or other threads to trigger shutdown.
        """
        self.logger.info("Stop signal received - shutting down...")
        self._stop_event.set()
