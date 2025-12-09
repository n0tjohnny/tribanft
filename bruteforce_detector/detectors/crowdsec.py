"""
TribanFT CrowdSec Detector - Fixed JSON Parsing

Queries CrowdSec LAPI for active ban decisions and converts to detections.
"""

import subprocess
import json
import logging
from typing import List, Dict
from datetime import datetime

from .base import BaseDetector
from ..models import DetectionResult, EventType


class CrowdSecDetector(BaseDetector):
    """Detector for IPs banned by CrowdSec."""
    
    def __init__(self, config):
        """Initialize CrowdSec detector."""
        super().__init__(config, EventType.CROWDSEC_BLOCK)
        self.logger = logging.getLogger(__name__)
    
    def detect(self, events) -> List[DetectionResult]:
        """Query CrowdSec for active bans and convert to detections."""
        try:
            blocked_ips = self._get_crowdsec_blocked_ips()
            
            if not blocked_ips:
                self.logger.debug("No CrowdSec decisions found")
                return []
            
            self.logger.info(f"Found {len(blocked_ips)} IPs from CrowdSec")
            
            detections = []
            for ip_str, metadata in blocked_ips.items():
                try:
                    result = self._create_detection_result(
                        ip_str=ip_str,
                        reason=self._format_crowdsec_reason(metadata),
                        confidence='high',
                        event_count=metadata.get('events', 1),
                        source_events=[],
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
        
        FIXED: Properly parse the JSON structure from cscli decisions list -o json
        """
        try:
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
                decisions_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse cscli JSON output: {e}")
                return {}
            
            if not decisions_data:
                return {}
            
            # Debug: Log structure
            self.logger.debug(f"CrowdSec returned {len(decisions_data)} decision entries")
            
            blocked_ips = {}
            
            # The JSON is an array of decision objects
            for decision_entry in decisions_data:
                try:
                    # Each entry has a 'decisions' array and a 'source' object
                    decisions_list = decision_entry.get('decisions', [])
                    source = decision_entry.get('source', {})
                    
                    # Get IP from source object
                    ip_str = source.get('ip') or source.get('value', '')
                    
                    if not ip_str:
                        self.logger.debug(f"No IP found in entry: {decision_entry.keys()}")
                        continue
                    
                    # Parse creation timestamp from decision entry
                    created_at = decision_entry.get('created_at') or decision_entry.get('start_at')
                    timestamp = datetime.now()
                    
                    if created_at:
                        try:
                            if created_at.endswith('Z'):
                                timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            else:
                                timestamp = datetime.fromisoformat(created_at)
                        except (ValueError, AttributeError) as e:
                            self.logger.debug(f"Timestamp parse error for {ip_str}: {e}")
                    
                    # Get decision metadata
                    scenario = decision_entry.get('scenario', 'Unknown')
                    events_count = decision_entry.get('events_count', 1)
                    
                    # Get decision type and duration from decisions array
                    decision_type = 'ban'
                    duration = 'Unknown'
                    if decisions_list:
                        first_decision = decisions_list[0]
                        decision_type = first_decision.get('type', 'ban')
                        duration = first_decision.get('duration', 'Unknown')
                    
                    blocked_ips[ip_str] = {
                        'timestamp': timestamp,
                        'reason': scenario,
                        'events': events_count,
                        'scenario': scenario,
                        'type': decision_type,
                        'duration': duration
                    }
                    
                    self.logger.debug(f"Parsed CrowdSec IP: {ip_str} ({scenario}, {events_count} events)")
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing CrowdSec decision entry: {e}")
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
        """Format human-readable blocking reason from CrowdSec metadata."""
        scenario = metadata.get('scenario', 'Unknown')
        events = metadata.get('events', 1)
        
        # Make scenario more readable
        scenario_name = scenario.replace('crowdsecurity/', '').replace('-', ' ').title()
        
        return f"CrowdSec: {scenario_name} ({events} events)"
