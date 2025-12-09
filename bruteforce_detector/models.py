"""
TribanFT Data Models

Core data structures used throughout the application.

This module defines:
- SecurityEvent: Raw security events from log parsers
- DetectionResult: Output from detection algorithms
- ProcessingState: Tracks run history between executions
- Enums: EventType, DetectionConfidence

Type safety: All models use dataclasses for automatic __init__, __repr__, etc.
Serialization: to_dict() and from_dict() methods for JSON persistence

Author: TribanFT Project
License: GNU GPL v3
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import ipaddress
from typing import Dict, Optional, Set, List, Any, Union
import json


class EventType(Enum):
    """
    Types of security events detected in logs.
    
    Values:
        PRELOGIN_INVALID: MSSQL reconnaissance attempts (invalid prelogin packets)
        FAILED_LOGIN: Authentication failures (MSSQL, SSH, etc)
        PORT_SCAN: Port scanning activity detected
        CROWDSEC_BLOCK: IPs blocked by CrowdSec
    """
    PRELOGIN_INVALID = "prelogin_invalid"
    FAILED_LOGIN = "failed_login"
    PORT_SCAN = "port_scan"
    CROWDSEC_BLOCK = "crowdsec_block"


class DetectionConfidence(Enum):
    """
    Confidence level of threat detection.
    
    Values:
        HIGH: Strong evidence (e.g., >20 failed logins in window)
        MEDIUM: Moderate evidence (e.g., port scan patterns)
        LOW: Weak evidence (single suspicious event)
    """
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"


# Type alias for IP addresses (IPv4 or IPv6)
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class SecurityEvent:
    """
    Single security event extracted from logs.
    
    Represents one occurrence of suspicious activity (failed login,
    port scan, etc) parsed from system logs.
    
    Attributes:
        source_ip: IP address of attacker
        event_type: Type of security event (EventType enum)
        timestamp: When the event occurred
        source: Log source (e.g., 'syslog', 'mssql')
        raw_message: Original log line for reference
        metadata: Additional event-specific data
    """
    source_ip: IPAddress
    event_type: EventType
    timestamp: datetime
    source: str
    raw_message: str = ""
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON storage."""
        return {
            'source_ip': str(self.source_ip),
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'raw_message': self.raw_message,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SecurityEvent':
        """Deserialize from dictionary."""
        ip_obj = ipaddress.ip_address(data['source_ip'])
        return cls(
            source_ip=ip_obj,
            event_type=EventType(data['event_type']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            source=data['source'],
            raw_message=data.get('raw_message', ''),
            metadata=data.get('metadata', {})
        )


@dataclass
class DetectionResult:
    """
    Output from a detection algorithm indicating a threat.
    
    When a detector identifies malicious activity (e.g., 20+ failed logins
    from same IP), it creates a DetectionResult with evidence and metadata.
    
    Attributes:
        ip: IP address to block
        reason: Human-readable explanation (e.g., "Failed login brute force: 25 attempts")
        confidence: Detection confidence level
        event_count: Number of events that triggered detection
        source_events: List of SecurityEvents that caused detection
        first_seen: Timestamp of first event in attack
        last_seen: Timestamp of last event in attack
        geolocation: Optional geo data (country, city, ISP)
    """
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    reason: str
    confidence: DetectionConfidence
    event_count: int
    source_events: List[SecurityEvent] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    geolocation: Optional[Dict] = None
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON storage."""
        return {
            'ip': str(self.ip),
            'reason': self.reason,
            'confidence': self.confidence.value,
            'event_count': self.event_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'geolocation': self.geolocation,
            'source_events': [event.to_dict() for event in self.source_events]
        }


@dataclass 
class ProcessingState:
    """
    Tracks processing state between detection runs.
    
    Persisted to disk (/var/lib/tribanft/state.json) to enable
    incremental processing - only parse logs since last run.
    
    Attributes:
        last_processed_positions: File offsets for incremental parsing
        last_processed_timestamp: Timestamp of last successful run
        recent_detections: Recent IPs blocked (for deduplication)
    """
    last_processed_positions: dict = field(default_factory=dict)
    last_processed_timestamp: Optional[datetime] = None
    recent_detections: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON storage."""
        return {
            'last_processed_positions': self.last_processed_positions,
            'last_processed_timestamp': self.last_processed_timestamp.isoformat() if self.last_processed_timestamp else None,
            'recent_detections': {ip: ts.isoformat() for ip, ts in self.recent_detections.items()}
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ProcessingState':
        """Deserialize from dictionary."""
        return cls(
            last_processed_positions=data.get('last_processed_positions', {}),
            last_processed_timestamp=datetime.fromisoformat(data['last_processed_timestamp']) if data.get('last_processed_timestamp') else None,
            recent_detections={ip: datetime.fromisoformat(ts) for ip, ts in data.get('recent_detections', {}).items()}
        )
