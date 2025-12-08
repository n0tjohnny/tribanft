"""
TribanFT CrowdSec Integration

Integrates with CrowdSec for collaborative threat intelligence.

CrowdSec is a collaborative security engine that shares threat intelligence
across a community. This detector imports IP decisions from CrowdSec's local
agent to complement local detection.

Detection logic:
- Queries CrowdSec for currently blocked IPs
- Medium confidence - relies on community intelligence
- No threshold needed - direct import from CrowdSec decisions

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
from typing import List
from datetime import datetime
import ipaddress
import logging

from .base import BaseDetector
from ..models import SecurityEvent, DetectionResult, DetectionConfidence, EventType
from ..config import get_config


class CrowdSecDetector(BaseDetector):
    """Integrates with CrowdSec for additional detections"""
    
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
        Query CrowdSec and import blocked IPs as detections.
        
        Args:
            events: List of SecurityEvent objects (not used for CrowdSec)
            
        Returns:
            List of DetectionResult objects from CrowdSec decisions
        """
        if not self.enabled:
            return []
        
        blocked_ips = self._get_crowdsec_blocked_ips()
        results = []
        
        for ip in blocked_ips:
            # Create synthetic SecurityEvent for CrowdSec block
            synthetic_event = SecurityEvent(
                source_ip=ip,
                event_type=EventType.CROWDSEC_BLOCK,
                timestamp=datetime.now(),
                source="crowdsec",
                raw_message="Blocked by CrowdSec"
            )
            
            results.append(DetectionResult(
                ip=ip,
                reason="IP blocked by CrowdSec",
                confidence=DetectionConfidence.MEDIUM,
                event_count=1,
                source_events=[synthetic_event],
                first_seen=datetime.now(),
                last_seen=datetime.now()
            ))
        
        return results
    
    def _get_crowdsec_blocked_ips(self):
        """
        Query CrowdSec CLI for currently blocked IPs.
        
        Returns:
            Set of IP addresses blocked by CrowdSec
        """
        blocked_ips = set()
        
        try:
            result = subprocess.run(['cscli', 'decisions', 'list', '-o', 'raw'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.split(',')
                    if len(parts) > 2:
                        ip_part = parts[2].strip()
                        if ip_part.startswith('Ip:'):
                            ip_str = ip_part[3:].strip()
                            try:
                                ip = ipaddress.ip_address(ip_str)
                                if not self.whitelist_manager.is_whitelisted(ip):
                                    blocked_ips.add(ip)
                            except ValueError:
                                self.logger.warning(f"Invalid IP from CrowdSec: {ip_str}")
            else:
                self.logger.error(f"CrowdSec command failed: {result.stderr}")
                
        except FileNotFoundError:
            self.logger.warning("CrowdSec (cscli) not found, skipping")
        except subprocess.TimeoutExpired:
            self.logger.error("CrowdSec command timed out")
        except Exception as e:
            self.logger.error(f"Error getting CrowdSec blocked IPs: {e}")
        
        return blocked_ips