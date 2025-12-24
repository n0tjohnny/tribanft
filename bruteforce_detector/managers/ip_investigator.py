"""
TribanFT IP Investigator

Investigates IPs combining geolocation and log analysis.

Provides comprehensive IP investigation by:
- Fetching geolocation data (country, city, ISP)
- Analyzing historical log activity
- Determining threat severity and reason for blocking
- Generating investigation reports

Used when manually adding IPs to blacklist to provide context
and evidence for the blocking decision.

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Dict
from datetime import datetime
import logging
import ipaddress


class IPInvestigator:
    """Investigates IPs combining geolocation and log analysis"""
    
    def __init__(self, geolocation_manager, log_searcher):
        """
        Initialize IP investigator.
        
        Args:
            geolocation_manager: IPGeolocationManager for location data
            log_searcher: LogSearcher for historical analysis
        """
        self.geolocation_manager = geolocation_manager
        self.log_searcher = log_searcher
        self.logger = logging.getLogger(__name__)
    
    def investigate_ip(self, ip_str: str, search_logs: bool = True) -> Dict:
        """
        Perform comprehensive IP investigation.
        
        Combines geolocation lookup with log analysis to build
        complete threat profile.
        
        Args:
            ip_str: IP address to investigate
            search_logs: Whether to search logs (default: True)
            
        Returns:
            Dict with geolocation, log analysis, reason, and metadata
        """
        investigation = {
            'ip': ip_str,
            'geolocation': None,
            'log_analysis': None,
            'reason': 'Manually added',
            'confidence': 'manual',
            'event_count': 0,
            'first_seen': datetime.now(),
            'source': 'manual'
        }
        
        # Fetch geolocation
        if self.geolocation_manager:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                investigation['geolocation'] = self.geolocation_manager.get_ip_info(ip_obj)
            except Exception as e:
                self.logger.warning(f"Geolocation failed for {ip_str}: {e}")
        
        # Search logs
        if search_logs and self.log_searcher:
            investigation['log_analysis'] = self.log_searcher.search_ip_activity(ip_str)
            
            # Determine reason from logs
            if investigation['log_analysis']['events_found'] > 0:
                investigation['event_count'] = investigation['log_analysis']['events_found']
                investigation['confidence'] = 'high'
                investigation['reason'] = self._determine_reason(investigation['log_analysis'])
        
        return investigation
    
    def _determine_reason(self, log_analysis: Dict) -> str:
        """
        Determine blocking reason based on log analysis.
        
        Args:
            log_analysis: Dict from LogSearcher with event details
            
        Returns:
            Human-readable reason string
        """
        events_found = log_analysis['events_found']
        files_searched = log_analysis['files_searched']
        event_types = log_analysis['event_types']
        
        if 'port_scan' in event_types:
            return f"Port scan detected ({events_found} events across {files_searched} files)"
        elif 'prelogin_bruteforce' in event_types:
            return f"Prelogin brute force ({events_found} events)"
        elif 'failed_login' in event_types or 'mssql_failed_login' in event_types:
            return f"Failed login attempts ({events_found} events)"
        else:
            return f"Suspicious activity in logs ({events_found} events)"
    
    def format_investigation_log(self, ip_str: str, investigation: Dict):
        """
        Format and log investigation results.
        
        Args:
            ip_str: IP address investigated
            investigation: Investigation results dict
        """
        geo = investigation.get('geolocation', {})
        country = geo.get('country', 'Unknown') if geo else 'Unknown'
        isp = geo.get('isp', 'Unknown ISP') if geo else 'Unknown ISP'
        
        log_analysis = investigation.get('log_analysis')
        
        if log_analysis and log_analysis['events_found'] > 0:
            self.logger.warning(f"Added {ip_str}: {investigation['reason']}")
            self.logger.info(f"   Location: {country} | ISP: {isp}")
            self.logger.info(f"   {log_analysis['events_found']} events in {log_analysis['files_searched']} files")
            self.logger.info(f"   Types: {', '.join(log_analysis['event_types'])}")
            
            # Show top 3 recent events
            for i, event in enumerate(log_analysis['recent_events'][:3]):
                self.logger.info(f"   {i+1}. [{event['source']}] {event['type']} - {event['timestamp']}")
        else:
            self.logger.warning(f"Manually added {ip_str}: {investigation['reason']}")
            self.logger.info(f"   Location: {country} | ISP: {isp}")
            self.logger.info("   No recent activity (manual addition)")