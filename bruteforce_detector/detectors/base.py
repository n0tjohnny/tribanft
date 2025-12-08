"""
TribanFT Base Detector

Abstract base class for all threat detection modules.

Provides common functionality for all detectors:
- Whitelist filtering to exclude trusted IPs
- Event grouping by source IP
- Time window calculations for rate-based detection
- Standardized detection interface

All detector implementations must inherit from this class and implement
the detect() method with their specific detection logic.

Author: TribanFT Project
License: GNU GPL v3
"""

from abc import ABC, abstractmethod
from typing import List, Set
from datetime import datetime, timedelta
import ipaddress

from ..models import SecurityEvent, DetectionResult, DetectionConfidence
from ..managers.whitelist import WhitelistManager
from ..config import get_config


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.
    
    Provides shared functionality for filtering, grouping, and analyzing
    security events. All concrete detectors inherit from this class.
    """
    
    def __init__(self, name: str, whitelist_manager: WhitelistManager):
        """
        Initialize detector with name and whitelist manager.
        
        Args:
            name: Detector name for logging (e.g., "prelogin_detector")
            whitelist_manager: WhitelistManager instance for filtering trusted IPs
        """
        self.name = name
        self.whitelist_manager = whitelist_manager
        self.config = get_config()
        self.enabled = True
    
    @abstractmethod
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze events and return detection results.
        
        Must be implemented by subclasses with their specific detection logic.
        
        Args:
            events: List of SecurityEvent objects to analyze
            
        Returns:
            List of DetectionResult objects for detected threats
        """
        pass
    
    def filter_whitelisted(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """
        Remove events from whitelisted IPs.
        
        Args:
            events: List of SecurityEvent objects
            
        Returns:
            Filtered list excluding whitelisted IPs
        """
        return [
            event for event in events 
            if not self.whitelist_manager.is_whitelisted(event.source_ip)
        ]
    
    def group_events_by_ip(self, events: List[SecurityEvent]) -> dict:
        """
        Group events by source IP address.
        
        Args:
            events: List of SecurityEvent objects
            
        Returns:
            Dictionary mapping IP strings to lists of events from that IP
        """
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
        """
        Filter events to only those within the time window.
        
        Args:
            events: List of SecurityEvent objects
            time_window_minutes: Time window in minutes (e.g., 10080 = 7 days)
            reference_time: Reference time (default: now) for calculating window
            
        Returns:
            Filtered list of events within the time window
        """
        # Allow configurable reference time for testing/historical analysis
        if reference_time is None:
            reference_time = datetime.now()
            
        cutoff_time = reference_time - timedelta(minutes=time_window_minutes)
        return [event for event in events if event.timestamp >= cutoff_time]