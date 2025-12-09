"""
TribanFT CrowdSec Integration

Integrates with CrowdSec for collaborative threat intelligence.

CrowdSec is a collaborative security engine that shares threat intelligence
across a community. This detector imports IP decisions from CrowdSec's local
agent to complement local detection.

Detection logic:
- Queries CrowdSec for currently blocked IPs with decision timestamps
- Extracts real creation time from CrowdSec decisions
- Medium confidence - relies on community intelligence
- No threshold needed - direct import from CrowdSec decisions

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
import json
from typing import List, Dict
from datetime import datetime
import ipaddress
import logging

from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import get_config


class CrowdSecDetector(BaseDetector):
    """Integrates with CrowdSec for additional detections with real timestamps"""
    
    def __init__(self, whitelist_manager):
        """
        Initialize CrowdSec detector.
        
        Args:
            whitelist_manager: WhitelistManager for filtering trusted IPs
        """
        super().__init__("crowdsec_detector", whitelist_manager)
        self.config = get_config()
        self.enabled = self.config.enable_crowdsec_integration
        self.logger = logging.getLogger(__name__)
    
    def detect(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Query CrowdSec and import blocked IPs as detections with real timestamps.
        
        Args:
            events: List of SecurityEvent objects (not used for CrowdSec)
            
        Returns:
            List of DetectionResult objects from CrowdSec decisions
        """
        if not self.enabled:
            return []
        
        blocked_ips_with_time = self._get_crowdsec_blocked_ips()
        results = []
        
        self.logger.info(f"Found {len(blocked_ips_with_time)} IPs from CrowdSec")
        
        for ip_str, decision_info in blocked_ips_with_time.items():
            try:
                ip = ipaddress.ip_address(ip_str)
                
                # Create event with REAL timestamp from CrowdSec
                synthetic_event = SecurityEvent(
                    source_ip=ip,
                    event_type=EventType.CROWDSEC_BLOCK,
                    timestamp=decision_info['timestamp'],  # ← Real timestamp from CrowdSec
                    source="crowdsec",
                    raw_message=f"Blocked by CrowdSec: {decision_info['reason']}",
                    metadata={
                        'scenario': decision_info.get('scenario'),
                        'duration': decision_info.get('duration'),
                        'scope': decision_info.get('scope')
                    }
                )
                
                results.append(DetectionResult(
                    ip=ip,
                    reason=decision_info['reason'],
                    confidence=DetectionConfidence.MEDIUM,
                    event_count=1,
                    source_events=[synthetic_event],
                    first_seen=decision_info['timestamp'],  # ← Real timestamps
                    last_seen=decision_info['timestamp']
                ))
                
                self.logger.debug(
                    f"Added CrowdSec decision: {ip_str} at {decision_info['timestamp']}"
                )
                
            except ValueError as e:
                self.logger.warning(f"Invalid IP from CrowdSec: {ip_str}, {e}")
        
        return results
    
    def _get_crowdsec_blocked_ips(self) -> Dict[str, Dict]:
        """
        Query CrowdSec and return IPs with their actual decision timestamps and metadata.
        
        Returns:
            Dict mapping IP strings to decision info dicts containing:
                - timestamp: datetime when decision was created
                - reason: scenario/reason for blocking
                - duration: decision duration
                - scenario: CrowdSec scenario name
                - scope: decision scope (ip, range, etc)
        """
        blocked_ips_with_info = {}
        
        try:
            result = subprocess.run(
                ['cscli', 'decisions', 'list', '-o', 'json'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                decisions = json.loads(result.stdout)
                
                for decision in decisions:
                    # Extract IP address
                    ip_str = decision.get('value', '').strip()
                    if not ip_str:
                        continue
                    
                    # Extract timestamp
                    created_at_str = decision.get('created_at', '')
                    if not created_at_str:
                        self.logger.debug(f"No timestamp for {ip_str}, using current time")
                        timestamp = datetime.now()
                    else:
                        try:
                            # Parse CrowdSec ISO timestamp
                            # Format: "2024-12-08T14:30:00Z" or "2024-12-08T14:30:00+00:00"
                            created_at_str = created_at_str.replace('Z', '+00:00')
                            timestamp = datetime.fromisoformat(created_at_str)
                        except (ValueError, AttributeError) as e:
                            self.logger.warning(
                                f"Failed to parse timestamp '{created_at_str}' for {ip_str}: {e}"
                            )
                            timestamp = datetime.now()
                    
                    # Extract scenario/reason
                    scenario = decision.get('scenario', 'unknown')
                    reason = decision.get('reason', scenario)
                    duration = decision.get('duration', 'unknown')
                    scope = decision.get('scope', 'ip')
                    
                    # Validate IP and check whitelist
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if self.whitelist_manager.is_whitelisted(ip):
                            self.logger.debug(f"Skipping whitelisted IP from CrowdSec: {ip_str}")
                            continue
                    except ValueError:
                        self.logger.warning(f"Invalid IP from CrowdSec: {ip_str}")
                        continue
                    
                    # Build reason string
                    friendly_reason = self._format_crowdsec_reason(scenario, reason, duration)
                    
                    blocked_ips_with_info[ip_str] = {
                        'timestamp': timestamp,
                        'reason': friendly_reason,
                        'scenario': scenario,
                        'duration': duration,
                        'scope': scope
                    }
                    
            else:
                self.logger.error(f"CrowdSec command failed: {result.stderr}")
                
        except FileNotFoundError:
            self.logger.warning("CrowdSec (cscli) not found, skipping")
        except subprocess.TimeoutExpired:
            self.logger.error("CrowdSec command timed out")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse CrowdSec JSON output: {e}")
        except Exception as e:
            self.logger.error(f"Error getting CrowdSec blocked IPs: {e}")
        
        return blocked_ips_with_info
    
    def _format_crowdsec_reason(self, scenario: str, reason: str, duration: str) -> str:
        """
        Format CrowdSec scenario into human-readable reason.
        
        Args:
            scenario: CrowdSec scenario name
            reason: Raw reason from CrowdSec
            duration: Decision duration
            
        Returns:
            Human-readable reason string
        """
        # Map common scenarios to friendly names
        scenario_map = {
            'ssh-bf': 'SSH brute force',
            'ssh-slow-bf': 'SSH slow brute force',
            'http-bf': 'HTTP brute force',
            'http-probing': 'HTTP probing/scanning',
            'port-scan': 'Port scanning activity',
            'mssql-bf': 'MSSQL brute force',
            'http-crawl-non_statics': 'HTTP crawler/bot activity',
            'http-bad-user-agent': 'Malicious user agent'
        }
        
        # Extract scenario basename (remove crowdsecurity/ prefix if present)
        scenario_base = scenario.split('/')[-1] if '/' in scenario else scenario
        
        # Get friendly name
        friendly = scenario_map.get(scenario_base, f"CrowdSec: {scenario_base}")
        
        # Add duration if available
        if duration and duration != 'unknown':
            return f"{friendly} (duration: {duration})"
        
        return friendly