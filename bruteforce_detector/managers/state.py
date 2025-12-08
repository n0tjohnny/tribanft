import json
from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

from ..models import ProcessingState
from ..config import get_config

class StateManager:
    """Manages processing state between runs"""
    
    def __init__(self):
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        self.state_file = Path(self.config.state_file)
    
    def get_state(self) -> Optional[ProcessingState]:
        """Load processing state from file"""
        if not self.state_file.exists():
            return None
        
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
            return ProcessingState.from_dict(data)
        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
            return None
    
    def update_state(self):
        """Update processing state with current timestamp"""
        state = ProcessingState()
        state.last_processed_timestamp = datetime.now()
        
        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")