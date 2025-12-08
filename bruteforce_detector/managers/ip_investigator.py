"""
bruteforce_detector/managers/ip_investigator.py

Módulo responsável por investigar IPs (geolocalização + análise de logs)
"""

from typing import Dict
from datetime import datetime
import logging
import ipaddress


class IPInvestigator:
    """Investiga IPs combinando geolocalização e análise de logs"""
    
    def __init__(self, geolocation_manager, log_searcher):
        self.geolocation_manager = geolocation_manager
        self.log_searcher = log_searcher
        self.logger = logging.getLogger(__name__)
    
    def investigate_ip(self, ip_str: str, search_logs: bool = True) -> Dict:
        """
        Investiga um IP completamente: geolocalização + logs
        
        Args:
            ip_str: IP a ser investigado
            search_logs: Se deve buscar nos logs
            
        Returns:
            Dict com todas as informações do IP
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
        
        # Obtém geolocalização
        if self.geolocation_manager:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                investigation['geolocation'] = self.geolocation_manager.get_ip_info(ip_obj)
            except Exception as e:
                self.logger.warning(f"Could not get geolocation for {ip_str}: {e}")
        
        # Busca nos logs
        if search_logs and self.log_searcher:
            investigation['log_analysis'] = self.log_searcher.search_ip_activity(ip_str)
            
            # Determina melhor reason baseado nos logs
            if investigation['log_analysis']['events_found'] > 0:
                investigation['event_count'] = investigation['log_analysis']['events_found']
                investigation['confidence'] = 'high'
                investigation['reason'] = self._determine_reason(investigation['log_analysis'])
        
        return investigation
    
    def _determine_reason(self, log_analysis: Dict) -> str:
        """Determina a melhor razão baseado na análise de logs"""
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
        """Formata log de investigação de forma clara"""
        geo = investigation.get('geolocation', {})
        country = geo.get('country', 'Unknown') if geo else 'Unknown'
        isp = geo.get('isp', 'Unknown ISP') if geo else 'Unknown ISP'
        
        log_analysis = investigation.get('log_analysis')
        
        if log_analysis and log_analysis['events_found'] > 0:
            self.logger.warning(f"🔒 Added {ip_str} to blacklists: {investigation['reason']}")
            self.logger.info(f"   🌍 Location: {country} | ISP: {isp}")
            self.logger.info(f"   📊 Found {log_analysis['events_found']} events in {log_analysis['files_searched']} files")
            self.logger.info(f"   🎯 Event types: {', '.join(log_analysis['event_types'])}")
            
            # Mostra top 3 eventos mais recentes
            for i, event in enumerate(log_analysis['recent_events'][:3]):
                self.logger.info(f"   {i+1}. [{event['source']}] {event['type']} - {event['timestamp']}")
        else:
            self.logger.warning(f"🔒 Manually added {ip_str} to blacklists: {investigation['reason']}")
            self.logger.info(f"   🌍 Location: {country} | ISP: {isp}")
            self.logger.info("   📝 No recent malicious activity found in logs (manual addition)")
