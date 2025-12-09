"""
TribanFT CrowdSec Detector

Queries CrowdSec LAPI for active ban decisions and converts to detections.

Integrates with CrowdSec via cscli command to fetch:
- Currently active bans
- Decision timestamps (created_at)
- Scenario information (ssh-bf, http-scan, etc.)
- Event counts

Extracts real decision timestamps instead of using datetime.now().

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
import json
import logging
from typing import List, Dict
from datetime import datetime

from .base import BaseDetector
from ..models import DetectionResult, EventType


class CrowdSecDetector(BaseDetector):
    """
    Detector for IPs banned by CrowdSec.
    
    Queries CrowdSec's Local API via cscli to fetch active decisions
    and converts them to DetectionResult objects.
    """
    
    def __init__(self, config):
        """Initialize CrowdSec detector."""
        super().__init__(config, EventType.CROWDSEC_BAN)
        self.logger = logging.getLogger(__name__)
    
    def detect(self, events) -> List[DetectionResult]:
        """
        Query CrowdSec for active bans and convert to detections.
        
        Args:
            events: Not used (CrowdSec maintains its own event store)
            
        Returns:
            List of DetectionResult for each banned IP
        """
        try:
            # Query CrowdSec for decisions with metadata
            blocked_ips = self._get_crowdsec_blocked_ips()
            
            if not blocked_ips:
                self.logger.debug("No CrowdSec decisions found")
                return []
            
            self.logger.info(f"Found {len(blocked_ips)} IPs from CrowdSec")
            
            # Convert to DetectionResult objects
            detections = []
            for ip_str, metadata in blocked_ips.items():
                try:
                    result = self._create_detection_result(
                        ip_str=ip_str,
                        reason=self._format_crowdsec_reason(metadata),
                        confidence='high',
                        event_count=metadata.get('events', 1),
                        source_events=[],  # CrowdSec decisions don't have SecurityEvent objects
                        first_seen=metadata.get('timestamp'),
                        last_seen=metadata.get('timestamp')
                    )
                    
                    if result:
                        detections.append(result)
                        
                except Exception as e:
                    self.logger.warning(f"Error processing CrowdSec IP {ip_str}: {e}")
                    continue
            
            return detections
            
        except Exception as e:
            self.logger.error(f"CrowdSec detection error: {e}")
            return []
    
    def _get_crowdsec_blocked_ips(self) -> Dict[str, Dict]:
        """
        Query CrowdSec LAPI for active ban decisions with metadata.
        
        Executes: cscli decisions list -o json
        Parses JSON response to extract IP, timestamps, scenario, events.
        
        Returns:
            Dict mapping IP address -> {timestamp, reason, events, scenario}
        """
        try:
            # Execute cscli with JSON output
            result = subprocess.run(
                ['cscli', 'decisions', 'list', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error(f"cscli command failed: {result.stderr}")
                return {}
            
            # Parse JSON response
            try:
                decisions = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse cscli JSON output: {e}")
                return {}
            
            if not decisions:
                return {}
            
            # Extract IPs with metadata
            blocked_ips = {}
            
            for decision in decisions:
                try:
                    # Extract IP from scope:value format
                    # CrowdSec returns "Ip:192.168.1.1" or just "192.168.1.1"
                    scope_value = decision.get('scope_value') or decision.get('value', '')
                    if not scope_value:
                        continue
                    
                    # Remove "Ip:" prefix if present
                    ip_str = scope_value.replace('Ip:', '').strip()
                    
                    # Parse creation timestamp
                    created_at = decision.get('created_at')
                    timestamp = None
                    
                    if created_at:
                        try:
                            # CrowdSec uses ISO 8601 format: "2024-12-08T14:30:00Z"
                            # Handle both with and without 'Z' suffix
                            if created_at.endswith('Z'):
                                timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            else:
                                timestamp = datetime.fromisoformat(created_at)
                        except (ValueError, AttributeError) as e:
                            self.logger.debug(f"Timestamp parse error for {ip_str}: {e}")
                            timestamp = datetime.now()
                    else:
                        timestamp = datetime.now()
                    
                    # Store complete metadata
                    blocked_ips[ip_str] = {
                        'timestamp': timestamp,
                        'reason': decision.get('reason', 'Unknown'),
                        'events': int(decision.get('events_count', 1)),
                        'scenario': decision.get('scenario', 'Unknown'),
                        'type': decision.get('type', 'ban'),
                        'duration': decision.get('duration', 'Unknown')
                    }
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing CrowdSec decision: {e}")
                    continue
            
            return blocked_ips
            
        except subprocess.TimeoutExpired:
            self.logger.error("cscli command timed out after 10 seconds")
            return {}
        except FileNotFoundError:
            self.logger.error("cscli command not found - is CrowdSec installed?")
            return {}
        except Exception as e:
            self.logger.error(f"Error querying CrowdSec: {e}")
            return {}
    
    def _format_crowdsec_reason(self, metadata: Dict) -> str:
        """
        Format human-readable blocking reason from CrowdSec metadata.
        
        Converts scenario names like "crowdsecurity/ssh-slow-bf" to
        readable format: "SSH Slow Bf (11 events)"
        
        Args:
            metadata: Dict with scenario, events, etc.
            
        Returns:
            Formatted reason string
        """
        scenario = metadata.get('scenario', 'Unknown')
        events = metadata.get('events', 1)
        
        # Make scenario more readable
        # "crowdsecurity/ssh-slow-bf" -> "SSH Slow Bf"
        scenario_name = scenario.replace('crowdsecurity/', '').replace('-', ' ').title()
        
        return f"IP blocked by CrowdSec - {scenario_name} ({events} events)"