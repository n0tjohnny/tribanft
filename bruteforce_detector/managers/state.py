"""
TribanFT State Manager

Manages processing state between detection runs for incremental parsing.

Persists run history to enable incremental log processing - only parse
logs since last successful run. Stores timestamps and file positions
to avoid reprocessing the same events.

Uses atomic writes (write-to-temp-then-rename) to prevent corruption.

State file location: Configured via config.state_file (default: XDG state dir)

Author: TribanFT Project
License: GNU GPL v3
"""

import json
import os
import tempfile
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
    
    def get_state(self) -> Optional[ProcessingState]:
        """
        Load processing state from file.
        
        Returns:
            ProcessingState object with last run timestamp, or None if no state exists
        """
        if not self.state_file.exists():
            return None
        
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
            return ProcessingState.from_dict(data)
        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
            return None
    
    def update_state(self, state: ProcessingState = None):
        """
        Update processing state with current timestamp.

        Called after successful detection cycle to mark this run's completion.
        Next run will only process events newer than this timestamp.

        Args:
            state: Optional ProcessingState to save. If None, creates new state.

        Uses atomic write (temp file + rename) to prevent corruption.
        """
        if state is None:
            state = ProcessingState()

        state.last_processed_timestamp = datetime.now()
        
        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # ATOMIC WRITE: Write to temp file first, then rename
            fd, temp_path = tempfile.mkstemp(
                dir=self.state_file.parent,
                prefix=f".{self.state_file.name}.",
                suffix='.tmp'
            )
            
            try:
                # Write state to temp file
                with os.fdopen(fd, 'w') as f:
                    json.dump(state.to_dict(), f, indent=2)
                
                # Atomic rename
                try:
                    os.replace(temp_path, self.state_file)
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