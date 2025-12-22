"""
TribanFT Base Detector

Base class for all detectors providing common detection functionality.

Provides:
- Abstract interface for detectors
- Timestamp extraction from SecurityEvent lists
- DetectionResult creation with guaranteed timestamps
- IP validation and confidence mapping

All detectors inherit from BaseDetector and implement detect() method.

Author: TribanFT Project
License: GNU GPL v3
"""

import ipaddress
import logging
from typing import List, Optional
from datetime import datetime
from abc import ABC, abstractmethod

from ..models import DetectionResult, SecurityEvent, EventType, DetectionConfidence


class BaseDetector(ABC):
    """
    Base class for all threat detectors.
    
    Provides common functionality for creating DetectionResult objects
    with proper timestamp extraction from SecurityEvent lists.
    """
    
    def __init__(self, config, event_type: EventType):
        """
        Initialize base detector.
        
        Args:
            config: Configuration object
            event_type: EventType enum for this detector
        """
        self.config = config
        self.event_type = event_type
        self.logger = logging.getLogger(__name__)
        
        # Map event types to their config enable flags
        enable_map = {
            EventType.PRELOGIN_INVALID: config.enable_prelogin_detection,
            EventType.FAILED_LOGIN: config.enable_failed_login_detection,
            EventType.PORT_SCAN: config.enable_port_scan_detection,
            EventType.CROWDSEC_BLOCK: config.enable_crowdsec_integration,
        }
        
        # Set enabled flag based on event type
        self.enabled = enable_map.get(event_type, True)
        self.name = self.__class__.__name__
    
    @abstractmethod
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Analyze events and return detections.
        
        Must be implemented by subclasses to provide detection logic.
        
        Args:
            events: List of SecurityEvent objects to analyze
            
        Returns:
            List of DetectionResult objects for malicious IPs
        """
        pass
    
    def _create_detection_result(
        self,
        ip_str: str,
        reason: str,
        confidence: str,
        event_count: int,
        source_events: List[SecurityEvent],
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None
    ) -> Optional[DetectionResult]:
        """
        Create DetectionResult with guaranteed timestamps.
        
        This helper ensures all DetectionResults have valid timestamps by:
        1. Using provided first_seen/last_seen if available
        2. Extracting from source_events if not provided
        3. Falling back to datetime.now() as last resort
        
        Args:
            ip_str: IP address string
            reason: Human-readable detection reason
            confidence: 'high', 'medium', or 'low'
            event_count: Number of events detected
            source_events: List of SecurityEvent objects that triggered detection
            first_seen: Optional override for first detection time
            last_seen: Optional override for last detection time
            
        Returns:
            DetectionResult object or None if IP is invalid
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Determine timestamps with fallback chain
            final_first_seen = first_seen
            final_last_seen = last_seen
            
            # Extract from source_events if not explicitly provided
            if (not final_first_seen or not final_last_seen) and source_events:
                timestamps = [
                    e.timestamp for e in source_events 
                    if e.timestamp is not None
                ]
                
                if timestamps:
                    if not final_first_seen:
                        final_first_seen = min(timestamps)
                    if not final_last_seen:
                        final_last_seen = max(timestamps)
            
            # Final fallback to current time
            now = datetime.now()
            if not final_first_seen:
                final_first_seen = now
            if not final_last_seen:
                final_last_seen = now
            
            # Map confidence string to enum
            confidence_map = {
                'high': DetectionConfidence.HIGH,
                'medium': DetectionConfidence.MEDIUM,
                'low': DetectionConfidence.LOW
            }
            confidence_level = confidence_map.get(confidence.lower(), DetectionConfidence.MEDIUM)
            
            return DetectionResult(
                ip=ip,
                reason=reason,
                confidence=confidence_level,
                event_count=event_count,
                event_type=self.event_type,
                source_events=source_events,
                geolocation=None,  # Enriched later by BlacklistManager
                first_seen=final_first_seen,
                last_seen=final_last_seen
            )
            
        except ValueError as e:
            self.logger.warning(f"Invalid IP address {ip_str}: {e}")
            return None
