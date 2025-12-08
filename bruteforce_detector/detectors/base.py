from abc import ABC, abstractmethod
from typing import List, Set
from datetime import datetime, timedelta
import ipaddress

from ..models import SecurityEvent, DetectionResult, DetectionConfidence
from ..managers.whitelist import WhitelistManager
from ..config import get_config

class BaseDetector(ABC):
    """Base class for all detectors"""
    
    def __init__(self, name: str, whitelist_manager: WhitelistManager):
        self.name = name
        self.whitelist_manager = whitelist_manager
        self.config = get_config()
        self.enabled = True
    
    @abstractmethod
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """Analyze events and return detection results"""
        pass
    
    def filter_whitelisted(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Filter out whitelisted IPs from events"""
        return [
            event for event in events 
            if not self.whitelist_manager.is_whitelisted(event.source_ip)
        ]
    
    def group_events_by_ip(self, events: List[SecurityEvent]) -> dict:
        """Group events by source IP"""
        grouped = {}
        for event in events:
            ip_str = str(event.source_ip)
            if ip_str not in grouped:
                grouped[ip_str] = []
            grouped[ip_str].append(event)
        return grouped
    
    def calculate_time_window_events(self, events: List[SecurityEvent], 
                                   time_window_minutes: int,
                                   reference_time: datetime = None) -> List[SecurityEvent]:
        """Filter events to only those within the time window"""
        # FIX: Allow configurable reference time for testing/historical analysis
        if reference_time is None:
            reference_time = datetime.now()
            
        cutoff_time = reference_time - timedelta(minutes=time_window_minutes)
        return [event for event in events if event.timestamp >= cutoff_time]