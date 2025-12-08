#!/usr/bin/env python3
"""
recover_blacklist_metadata.py

Script para recuperar metadados perdidos do blacklist_ipv4.txt

PROBLEMAS QUE ESTE SCRIPT RESOLVE:
1. IPs marcados como "legacy" sem geolocalização
2. IPs sem informação de reason/eventos do CrowdSec
3. IPs sem informação de source (nftables, crowdsec, etc)

FUNCIONAMENTO:
1. Lê blacklist atual e identifica IPs sem metadados
2. Consulta CrowdSec para obter histórico de decisões
3. Consulta NFTables para obter sets ativos
4. Adiciona geolocalização via IP-API (respeitando rate limits)
5. Reescreve blacklist com metadados completos
"""

import sys
import os
import argparse
import logging
import subprocess
import json
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, Optional

# Add project to path
sys.path.insert(0, '/root/bruteforce_detector')

from bruteforce_detector.config import get_config
from bruteforce_detector.managers.geolocation import IPGeolocationManager
from bruteforce_detector.managers.blacklist_writer import BlacklistWriter


class BlacklistMetadataRecovery:
    """Recupera metadados perdidos do blacklist"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.geo_manager = IPGeolocationManager()
        self.writer = BlacklistWriter(config)
        
        # Estatísticas
        self.stats = {
            'total_ips': 0,
            'without_geo': 0,
            'without_reason': 0,
            'legacy_source': 0,
            'geo_recovered': 0,
            'crowdsec_recovered': 0,
            'nftables_recovered': 0
        }
    
    def analyze_blacklist(self, blacklist_file: str) -> Dict:
        """Analisa blacklist e identifica IPs sem metadados"""
        self.logger.info(f"🔍 Analyzing blacklist: {blacklist_file}")
        
        ips_info = self.writer.read_blacklist(blacklist_file)
        
        self.stats['total_ips'] = len(ips_info)
        
        # Identifica IPs problemáticos
        ips_without_geo = {}
        ips_without_reason = {}
        ips_legacy = {}
        
        for ip_str, info in ips_info.items():
            # Sem geolocalização
            geo = info.get('geolocation')
            if not geo or not geo.get('country') or geo.get('country') == 'Unknown':
                ips_without_geo[ip_str] = info
                self.stats['without_geo'] += 1
            
            # Sem motivo válido
            reason = info.get('reason', '')
            if reason in ['Unknown', 'Previously blocked']:
                ips_without_reason[ip_str] = info
                self.stats['without_reason'] += 1
            
            # Source legacy
            if info.get('source') == 'legacy':
                ips_legacy[ip_str] = info
                self.stats['legacy_source'] += 1
        
        self.logger.info(f"\n📊 ANÁLISE:")
        self.logger.info(f"   Total IPs: {self.stats['total_ips']}")
        self.logger.info(f"   Sem geolocalização: {self.stats['without_geo']} ({self.stats['without_geo']/self.stats['total_ips']*100:.1f}%)")
        self.logger.info(f"   Sem reason válido: {self.stats['without_reason']} ({self.stats['without_reason']/self.stats['total_ips']*100:.1f}%)")
        self.logger.info(f"   Source legacy: {self.stats['legacy_source']} ({self.stats['legacy_source']/self.stats['total_ips']*100:.1f}%)")
        
        return {
            'all': ips_info,
            'without_geo': ips_without_geo,
            'without_reason': ips_without_reason,
            'legacy': ips_legacy
        }
    
    def recover_from_crowdsec(self, ips_info: Dict) -> Dict:
        """Recupera metadados do CrowdSec usando alerts (histórico completo)"""
        self.logger.info("\n🔍 Querying CrowdSec for metadata...")
        
        enriched = {}
        
        try:
            # Query CrowdSec alerts (histórico completo com -a)
            result = subprocess.run(
                ['cscli', 'alerts', 'list', '-a', '-o', 'json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                self.logger.warning(f"CrowdSec query failed: {result.stderr}")
                return enriched
            
            alerts = json.loads(result.stdout)
            self.logger.info(f"   Found {len(alerts)} CrowdSec alerts (historical)")
            
            for alert in alerts:
                try:
                    # Extrai IP do source
                    source = alert.get('source', {})
                    ip_str = source.get('ip', '')
                    
                    if not ip_str or ip_str not in ips_info:
                        continue
                    
                    scenario = alert.get('scenario', 'Unknown')
                    events_count = alert.get('events_count', 0)
                    capacity = alert.get('capacity', 0)
                    created_at = alert.get('created_at', '')
                    
                    # Extrai geolocalização dos eventos
                    geo_data = {}
                    events = alert.get('events', [])
                    if events:
                        for event in events[:1]:  # Primeiro evento
                            meta = event.get('meta', [])
                            for item in meta:
                                key = item.get('key', '')
                                value = item.get('value', '')
                                if key == 'IsoCode':
                                    geo_data['country'] = value
                                    geo_data['countryCode'] = value
                                elif key == 'ASNOrg':
                                    geo_data['isp'] = value
                                    geo_data['org'] = value
                                elif key == 'ASNNumber':
                                    geo_data['as'] = f"AS{value}"
                    
                    # Mapeia scenario para reason legível
                    reason_map = {
                        'ssh-bf': 'SSH brute force',
                        'ssh-slow-bf': 'SSH slow brute force',
                        'http-bf': 'HTTP brute force',
                        'http-probing': 'HTTP probing/scanning',
                        'port-scan': 'Port scanning activity',
                        'mssql-bf': 'MSSQL brute force'
                    }
                    
                    reason = reason_map.get(scenario.split('/')[-1], f"CrowdSec: {scenario}")
                    
                    enriched[ip_str] = {
                        **ips_info[ip_str],
                        'reason': f"{reason} ({events_count} events, capacity {capacity})",
                        'confidence': 'high',
                        'event_count': events_count,
                        'source': 'crowdsec',
                        'event_types': [scenario.split('/')[-1]]
                    }
                    
                    # Adiciona geolocalização se extraída
                    if geo_data:
                        enriched[ip_str]['geolocation'] = geo_data
                    
                    self.stats['crowdsec_recovered'] += 1
                    
                    if self.stats['crowdsec_recovered'] % 100 == 0:
                        self.logger.info(f"   Processed {self.stats['crowdsec_recovered']} CrowdSec IPs...")
                
                except Exception as e:
                    self.logger.debug(f"Error processing CrowdSec alert: {e}")
            
            self.logger.info(f"   ✅ Recovered {self.stats['crowdsec_recovered']} IPs from CrowdSec")
        
        except FileNotFoundError:
            self.logger.warning("   ⚠️  CrowdSec (cscli) not found")
        except subprocess.TimeoutExpired:
            self.logger.error("   ⚠️  CrowdSec query timeout")
        except Exception as e:
            self.logger.error(f"   ⚠️  CrowdSec error: {e}")
        
        return enriched
    
    def recover_from_nftables(self, ips_info: Dict) -> Dict:
        """Recupera metadados do NFTables"""
        self.logger.info("\n🔍 Querying NFTables for metadata...")
        
        enriched = {}
        
        nft_sets = {
            'port_scanners': 'Port scan detected (NFTables)',
            'blacklist_ipv4': 'Blacklisted (NFTables)',
            'addr-set-mssqld': 'MSSQL brute force (Fail2Ban)'
        }
        
        for set_name, reason in nft_sets.items():
            try:
                result = subprocess.run(
                    ['nft', 'list', 'set', 'inet', 'filter', set_name],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    # Parse IPs from set
                    for line in result.stdout.split('\n'):
                        if 'elements = {' in line:
                            import re
                            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                            
                            for ip_str in ips:
                                if ip_str in ips_info:
                                    enriched[ip_str] = {
                                        **ips_info.get(ip_str, {}),
                                        'reason': reason,
                                        'confidence': 'high',
                                        'source': 'nftables',
                                        'nft_set': set_name
                                    }
                                    self.stats['nftables_recovered'] += 1
                    
                    self.logger.info(f"   ✅ Processed set: {set_name}")
            
            except Exception as e:
                self.logger.debug(f"Error querying NFTables set {set_name}: {e}")
        
        self.logger.info(f"   ✅ Recovered {self.stats['nftables_recovered']} IPs from NFTables")
        return enriched
    
    def add_geolocation(self, ips_info: Dict, max_requests: int = 100) -> Dict:
        """Adiciona geolocalização para IPs sem geo"""
        self.logger.info(f"\n🌍 Adding geolocation (max {max_requests} requests)...")
        
        enriched = {}
        requests_made = 0
        
        for ip_str, info in ips_info.items():
            # Pula se já tem geo
            geo = info.get('geolocation')
            if geo and geo.get('country') and geo.get('country') != 'Unknown':
                enriched[ip_str] = info
                continue
            
            # Limite de requisições
            if requests_made >= max_requests:
                self.logger.warning(f"   ⚠️  Rate limit: stopped at {requests_made} requests")
                enriched[ip_str] = info
                continue
            
            # Busca geolocalização
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                geo_data = self.geo_manager.get_ip_info(ip_obj)
                
                if geo_data and geo_data.get('status') == 'success':
                    enriched[ip_str] = {
                        **info,
                        'geolocation': {
                            'country': geo_data.get('country', 'Unknown'),
                            'city': geo_data.get('city', ''),
                            'isp': geo_data.get('isp', 'Unknown ISP')
                        }
                    }
                    requests_made += 1
                    self.stats['geo_recovered'] += 1
                    
                    if requests_made % 10 == 0:
                        self.logger.info(f"   {requests_made}/{max_requests} geolocation requests...")
                else:
                    enriched[ip_str] = info
            
            except Exception as e:
                self.logger.debug(f"Geolocation error for {ip_str}: {e}")
                enriched[ip_str] = info
        
        self.logger.info(f"   ✅ Added geolocation to {self.stats['geo_recovered']} IPs")
        return enriched
    
    def merge_metadata(self, *metadata_sources: Dict) -> Dict:
        """Merge múltiplas fontes de metadados priorizando informação mais completa"""
        self.logger.info("\n🔄 Merging metadata from all sources...")
        
        merged = {}
        
        # Coleta todos os IPs
        all_ips = set()
        for source in metadata_sources:
            all_ips.update(source.keys())
        
        for ip_str in all_ips:
            # Coleta informações de todas as fontes
            ip_data = {}
            
            for source in metadata_sources:
                if ip_str in source:
                    # Prioriza informações mais completas
                    for key, value in source[ip_str].items():
                        # Sempre atualiza se atual está vazio/unknown
                        if key not in ip_data or not ip_data[key]:
                            ip_data[key] = value
                        # Atualiza geo se atual é mais completa
                        elif key == 'geolocation' and value:
                            if not ip_data[key] or ip_data[key].get('country') == 'Unknown':
                                ip_data[key] = value
                        # Atualiza reason se atual é genérico
                        elif key == 'reason':
                            if ip_data[key] in ['Unknown', 'Previously blocked']:
                                ip_data[key] = value
                        # Atualiza source se atual é legacy
                        elif key == 'source':
                            if ip_data[key] == 'legacy':
                                ip_data[key] = value
            
            merged[ip_str] = ip_data
        
        self.logger.info(f"   ✅ Merged metadata for {len(merged)} IPs")
        return merged
    
    def print_stats(self):
        """Exibe estatísticas finais"""
        self.logger.info("\n" + "="*70)
        self.logger.info("📊 RECOVERY STATISTICS")
        self.logger.info("="*70)
        self.logger.info(f"Total IPs processed: {self.stats['total_ips']}")
        self.logger.info(f"\nBEFORE Recovery:")
        self.logger.info(f"  Without geolocation: {self.stats['without_geo']}")
        self.logger.info(f"  Without valid reason: {self.stats['without_reason']}")
        self.logger.info(f"  Legacy source: {self.stats['legacy_source']}")
        self.logger.info(f"\nRECOVERED:")
        self.logger.info(f"  From CrowdSec: {self.stats['crowdsec_recovered']}")
        self.logger.info(f"  From NFTables: {self.stats['nftables_recovered']}")
        self.logger.info(f"  Geolocation added: {self.stats['geo_recovered']}")
        self.logger.info(f"\nIMPROVEMENT:")
        if self.stats['without_geo'] > 0:
            improvement = self.stats['geo_recovered'] / self.stats['without_geo'] * 100
            self.logger.info(f"  Geolocation coverage: +{improvement:.1f}%")
        if self.stats['legacy_source'] > 0:
            source_recovery = (self.stats['crowdsec_recovered'] + self.stats['nftables_recovered']) / self.stats['legacy_source'] * 100
            self.logger.info(f"  Source identification: +{source_recovery:.1f}%")
        self.logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Recover lost metadata from TribanFT blacklist',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--blacklist', '-b',
        default='/root/blacklist_ipv4.txt',
        help='Path to blacklist file (default: /root/blacklist_ipv4.txt)'
    )
    
    parser.add_argument(
        '--max-geo-requests', '-g',
        type=int,
        default=100,
        help='Maximum geolocation API requests (default: 100)'
    )
    
    parser.add_argument(
        '--dry-run', '-d',
        action='store_true',
        help='Analyze only, do not write changes'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("="*70)
    logger.info("🔧 TribanFT Blacklist Metadata Recovery")
    logger.info("="*70)
    
    # Initialize
    config = get_config()
    recovery = BlacklistMetadataRecovery(config)
    
    # Step 1: Analyze
    analysis = recovery.analyze_blacklist(args.blacklist)
    
    # Step 2: Recover from CrowdSec
    crowdsec_data = recovery.recover_from_crowdsec(analysis['all'])
    
    # Step 3: Recover from NFTables
    nftables_data = recovery.recover_from_nftables(analysis['all'])
    
    # Step 4: Add geolocation
    geo_data = recovery.add_geolocation(analysis['without_geo'], args.max_geo_requests)
    
    # Step 5: Merge all metadata
    final_data = recovery.merge_metadata(
        analysis['all'],
        crowdsec_data,
        nftables_data,
        geo_data
    )
    
    # Step 6: Print statistics
    recovery.print_stats()
    
    # Step 7: Write if not dry-run
    if args.dry_run:
        logger.info("\n🔍 DRY RUN - No changes written")
    else:
        logger.info("\n💾 Writing enhanced blacklist...")
        recovery.writer.write_blacklist(
            args.blacklist,
            final_data,
            new_count=recovery.stats['crowdsec_recovered'] + recovery.stats['nftables_recovered']
        )
        logger.info("✅ Blacklist updated successfully!")
    
    logger.info("\n🏁 Recovery complete!")


if __name__ == "__main__":
    main()
