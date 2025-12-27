"""
TribanFT State Manager

Manages processing state between detection runs for incremental parsing.

Persists run history to enable incremental log processing - only parse
logs since last successful run. Stores timestamps and file positions
to avoid reprocessing the same events.

Uses atomic writes (write-to-temp-then-rename) to prevent corruption.
Includes automatic backup and recovery for state file corruption.

State file location: Configured via config.state_file (default: XDG state dir)

Author: TribanFT Project
License: GNU GPL v3
"""

import json
import os
import tempfile
import shutil
from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

from ..models import ProcessingState
from ..config import get_config


class StateManager:
    """Manages processing state between runs"""

    def __init__(self):
        """Initialize state manager with configuration."""
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        self.state_file = Path(self.config.state_file)
        self.backup_file = self.state_file.with_suffix('.bak')

    def get_state(self) -> Optional[ProcessingState]:
        """
        Load processing state from file with automatic recovery.

        Tries to load from main state file. If corrupted, attempts to
        restore from backup file. If both fail, returns fresh state.

        Returns:
            ProcessingState object with last run data, or new state if unavailable
        """
        if not self.state_file.exists():
            self.logger.info("No state file found, starting fresh")
            return ProcessingState()

        # Try main state file
        try:
            return self._load_from_file(self.state_file)
        except Exception as e:
            self.logger.warning(f"State file corrupted: {e}")

            # Try backup file
            if self.backup_file.exists():
                self.logger.info("Attempting to restore from backup state")
                try:
                    state = self._load_from_file(self.backup_file)

                    # Restore backup to main file
                    shutil.copy(self.backup_file, self.state_file)
                    self.logger.info("Successfully restored state from backup")

                    return state
                except Exception as backup_error:
                    self.logger.error(f"Backup state also corrupted: {backup_error}")

            # Both failed - start fresh
            self.logger.warning("Both state files corrupted, starting with fresh state")
            return ProcessingState()

    def _load_from_file(self, file_path: Path) -> ProcessingState:
        """
        Load state from specific file.

        Args:
            file_path: Path to state file

        Returns:
            ProcessingState object

        Raises:
            Exception if file cannot be loaded or parsed
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        return ProcessingState.from_dict(data)
    
    def update_state(self, state: ProcessingState = None):
        """
        Update processing state with current timestamp and backup.

        Called after successful detection cycle to mark this run's completion.
        Next run will only process events newer than this timestamp.

        Args:
            state: Optional ProcessingState to save. If None, creates new state.

        Uses atomic write (temp file + rename) to prevent corruption.
        Creates automatic backup before overwriting existing state.
        """
        if state is None:
            state = ProcessingState()

        state.last_processed_timestamp = datetime.now()

        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Backup existing state file before overwriting
            if self.state_file.exists():
                try:
                    shutil.copy(self.state_file, self.backup_file)
                    self.logger.debug(f"Created backup: {self.backup_file}")
                except Exception as backup_error:
                    self.logger.warning(f"Failed to create backup: {backup_error}")
                    # Continue anyway - backup failure shouldn't stop state update

            # ATOMIC WRITE: Write to temp file first, then rename
            fd, temp_path = tempfile.mkstemp(
                dir=self.state_file.parent,
                prefix=f".{self.state_file.name}.",
                suffix='.tmp'
            )

            try:
                # Write state to temp file
                with os.fdopen(fd, 'w') as f:
                    json.dump(state.to_dict(), f, indent=2, default=str)

                # Atomic rename
                try:
                    os.replace(temp_path, self.state_file)
                    self.logger.debug(f"State saved: {self.state_file}")
                except OSError as e:
                    self.logger.error(f"Failed to rename temp file to {self.state_file}: {e}")
                    raise

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")