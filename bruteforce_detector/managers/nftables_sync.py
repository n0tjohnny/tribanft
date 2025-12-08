"""
bruteforce_detector/managers/nftables_sync.py

Sincronização INTELIGENTE com NFTables
- Sync automático SEM geolocalização (rápido)
- Geolocalização apenas quando solicitado (manual)
"""

import subprocess
import ipaddress
import re
from pathlib import Path
from datetime import datetime
from typing import Set, Dict, Tuple
import logging


class NFTablesSync:
    """Sincroniza IPs bloqueados bidirecionalmente entre NFTables e blacklist"""
    
    def __init__(self, config, whitelist_manager=None, geolocation_manager=None):
        self.config = config
        self.whitelist_manager = whitelist_manager
        self.geolocation_manager = geolocation_manager
        self.logger = logging.getLogger(__name__)
        
        # Sets do nftables que contêm IPs bloqueados
        self.nft_sets = {
            'port_scanners': {
                'table': 'inet filter',
                'reason': 'Port scan detected (NFTables)',
                'confidence': 'high'
            },
            'blacklist_ipv4': {
                'table': 'inet filter',
                'reason': 'Blacklisted (NFTables)',
                'confidence': 'high'
            },
            'addr-set-mssqld': {
                'table': 'inet f2b-table',
                'reason': 'MSSQL brute force (Fail2Ban)',
                'confidence': 'high'
            }
        }
    
    def get_set_elements(self, table: str, set_name: str) -> Tuple[Set[str], Dict[str, dict]]:
        """Extrai elementos de um set específico do nftables"""
        ips = set()
        ip_info = {}
        
        try:
            result = subprocess.run(
                ['nft', 'list', 'set', table, set_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            content = result.stdout
            in_elements = False
            buffer = ""
            
            for line in content.split('\n'):
                if 'elements = {' in line:
                    in_elements = True
                    buffer = line.split('elements = {')[1]
                elif in_elements:
                    buffer += " " + line.strip()
                    if '}' in line:
                        break
            
            if buffer:
                pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+limit rate over (\d+)/(\w+))?(?:\s+timeout ([\dd]+))?(?:\s+expires ([\dhms]+))?'
                
                for match in re.finditer(pattern, buffer):
                    ip_str = match.group(1)
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        
                        if ip.version == 4 and not ip.is_private and not ip.is_loopback:
                            ips.add(str(ip))
                            
                            ip_info[str(ip)] = {
                                'rate_limit': match.group(2),
                                'rate_unit': match.group(3),
                                'timeout': match.group(4),
                                'expires': match.group(5),
                                'set': set_name,
                                'table': table
                            }
                    except ValueError:
                        continue
            
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Não foi possível listar set {table}/{set_name}: {e}")
        except Exception as e:
            self.logger.error(f"Erro ao processar {table}/{set_name}: {e}")
        
        return ips, ip_info
    
    def extract_all_nftables_ips(self) -> Dict[str, Dict]:
        """Extrai todos os IPs de todos os sets monitorados do nftables"""
        all_ips = {}
        
        self.logger.info("🔍 Extraindo IPs dos sets do NFTables...")
        
        for set_name, set_config in self.nft_sets.items():
            table = set_config['table']
            self.logger.debug(f"Processando set '{set_name}' da tabela '{table}'...")
            
            ips, info = self.get_set_elements(table, set_name)
            
            if ips:
                self.logger.info(f"   ✅ {set_name}: {len(ips)} IPs encontrados")
                
                for ip in ips:
                    if ip not in all_ips:
                        all_ips[ip] = {
                            'sources': [],
                            'reason': set_config['reason'],
                            'confidence': set_config['confidence'],
                            'nft_info': info.get(ip, {}),
                            'first_seen_nft': datetime.now()
                        }
                    
                    if set_name not in all_ips[ip]['sources']:
                        all_ips[ip]['sources'].append(set_name)
                    
                    if len(all_ips[ip]['sources']) > 1:
                        all_ips[ip]['reason'] = f"Multiple violations: {', '.join(all_ips[ip]['sources'])}"
            else:
                self.logger.debug(f"   ⚠️  {set_name}: nenhum IP encontrado")
        
        # Remove IPs da whitelist
        if self.whitelist_manager:
            ips_to_remove = []
            for ip_str in all_ips.keys():
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if self.whitelist_manager.is_whitelisted(ip):
                        ips_to_remove.append(ip_str)
                except ValueError:
                    ips_to_remove.append(ip_str)
            
            for ip_str in ips_to_remove:
                del all_ips[ip_str]
        
        self.logger.info(f"📊 Total de IPs únicos extraídos do NFTables: {len(all_ips)}")
        return all_ips
    
    def sync_to_blacklist(self, nft_ips: Dict[str, Dict], 
                         add_geolocation: bool = False,
                         max_geo_requests: int = 0) -> Tuple[int, int]:
        """
        Sincroniza IPs bidirecionalmente entre nftables e blacklist
        
        Args:
            nft_ips: Dict de IPs extraídos do nftables
            add_geolocation: Se deve adicionar geolocalização (padrão: False)
            max_geo_requests: Máximo de requisições de geo (0 = ilimitado, padrão: 0)
            
        Returns:
            Tupla (novos_ips_adicionados_ao_blacklist, ips_faltando_no_nftables)
        """
        self.logger.info(f"📝 Sincronizando {len(nft_ips)} IPs do NFTables com blacklist...")
        
        # Lê blacklist existente
        existing_ips = self._read_existing_blacklist()
        self.logger.debug(f"   📋 IPs já no blacklist: {len(existing_ips)}")
        
        # Identifica novos IPs do NFTables
        new_ips_to_blacklist = {}
        geo_requests_made = 0
        
        for ip, info in nft_ips.items():
            if ip not in existing_ips:
                new_ips_to_blacklist[ip] = info
                
                # IMPORTANTE: Adiciona geo apenas se solicitado E dentro do limite
                if add_geolocation and self.geolocation_manager:
                    if max_geo_requests == 0 or geo_requests_made < max_geo_requests:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            geo_info = self.geolocation_manager.get_ip_info(ip_obj)
                            info['geolocation'] = geo_info
                            geo_requests_made += 1
                            
                            if geo_requests_made % 10 == 0:
                                self.logger.debug(f"   🌍 {geo_requests_made} geolocalizações realizadas")
                        except Exception as e:
                            self.logger.debug(f"Erro ao obter geolocalização para {ip}: {e}")
                    else:
                        # Limite atingido, não adiciona mais geo
                        info['geolocation'] = None
                else:
                    # Não foi solicitado geo, marca como None
                    info['geolocation'] = None
        
        # Identifica IPs do blacklist que NÃO estão no NFTables
        ips_missing_in_nftables = {}
        for ip, info in existing_ips.items():
            if ip not in nft_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if self.whitelist_manager and self.whitelist_manager.is_whitelisted(ip_obj):
                        continue
                    ips_missing_in_nftables[ip] = info
                except ValueError:
                    continue
        
        # Log de IPs que precisam ser adicionados ao NFTables
        if ips_missing_in_nftables:
            self.logger.warning(f"   ⚠️  {len(ips_missing_in_nftables)} IPs do blacklist NÃO estão bloqueados no NFTables!")
            
            for ip in list(ips_missing_in_nftables.keys())[:5]:
                info = ips_missing_in_nftables[ip]
                reason = info.get('reason', 'Unknown')
                self.logger.warning(f"      - {ip} ({reason})")
            
            if len(ips_missing_in_nftables) > 5:
                self.logger.warning(f"      ... e mais {len(ips_missing_in_nftables) - 5} IPs")
            
            self.logger.info(f"   💡 Execute com --sync-to-nftables para bloqueá-los")
        
        # Adiciona novos IPs do NFTables ao blacklist
        if new_ips_to_blacklist:
            self.logger.warning(f"   ➕ {len(new_ips_to_blacklist)} novos IPs do NFTables adicionados ao blacklist")
            
            if add_geolocation:
                self.logger.info(f"   🌍 {geo_requests_made} IPs geolocalizados")
                remaining = len(new_ips_to_blacklist) - geo_requests_made
                if remaining > 0:
                    self.logger.info(f"   ⏸️  {remaining} IPs sem geolocalização (adicione depois)")
            
            # Combina IPs existentes com novos
            all_ips = {**existing_ips, **new_ips_to_blacklist}
            
            # Escreve blacklist atualizado
            self._write_blacklist(all_ips, len(new_ips_to_blacklist))
            
            # Log resumido dos novos IPs
            for ip, info in list(new_ips_to_blacklist.items())[:5]:
                geo = info.get('geolocation', {})
                country = geo.get('country', 'Unknown') if geo else 'No Geo'
                sources = ', '.join(info['sources'])
                self.logger.info(f"   🔒 {ip} ({country}) - {sources}")
            
            if len(new_ips_to_blacklist) > 5:
                self.logger.info(f"   ... e mais {len(new_ips_to_blacklist) - 5} IPs")
        else:
            self.logger.info("   ✅ Blacklist já contém todos os IPs do NFTables")
        
        return len(new_ips_to_blacklist), len(ips_missing_in_nftables)
    
    def add_ip_to_nftables(self, ip: str, set_name: str = 'blacklist_ipv4') -> bool:
        """Adiciona um IP a um set do NFTables"""
        try:
            table = 'inet filter'
            result = subprocess.run(
                ['nft', 'add', 'element', table, set_name, f'{{ {ip} }}'],
                capture_output=True,
                text=True,
                check=True
            )
            self.logger.debug(f"✅ IP {ip} adicionado ao set {set_name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"⚠️  Erro ao adicionar {ip} ao NFTables: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Erro inesperado ao adicionar {ip}: {e}")
            return False
    
    def sync_blacklist_to_nftables(self, ips_to_add: Dict[str, Dict]) -> int:
        """Adiciona IPs do blacklist que não estão no NFTables"""
        if not ips_to_add:
            self.logger.info("✅ Todos os IPs do blacklist já estão no NFTables")
            return 0
        
        self.logger.warning(f"🔄 Adicionando {len(ips_to_add)} IPs do blacklist ao NFTables...")
        
        success_count = 0
        fail_count = 0
        
        for ip, info in ips_to_add.items():
            reason = info.get('reason', 'From blacklist')
            
            if self.add_ip_to_nftables(ip, 'blacklist_ipv4'):
                success_count += 1
                if success_count <= 10:  # Log apenas os 10 primeiros
                    self.logger.info(f"   ✅ {ip} - {reason}")
            else:
                fail_count += 1
        
        if success_count > 10:
            self.logger.info(f"   ... e mais {success_count - 10} IPs adicionados")
        
        if success_count > 0:
            self.logger.warning(f"✅ {success_count} IPs adicionados ao NFTables")
        if fail_count > 0:
            self.logger.warning(f"⚠️  {fail_count} IPs falharam")
        
        return success_count
    
    def run_sync(self, sync_to_nftables: bool = False, 
                 add_geolocation: bool = False,
                 max_geo_requests: int = 0) -> Tuple[int, int]:
        """
        Executa sincronização (inteligente)
        
        Args:
            sync_to_nftables: Se True, também adiciona IPs do blacklist ao NFTables
            add_geolocation: Se True, adiciona geolocalização (padrão: False para auto-sync)
            max_geo_requests: Limite de requisições de geo (0 = ilimitado)
        
        Returns:
            Tupla (IPs adicionados ao blacklist, IPs adicionados ao NFTables)
        """
        try:
            if add_geolocation:
                self.logger.info("🔄 Iniciando sincronização NFTables ↔ Blacklist (COM geolocalização)")
            else:
                self.logger.info("🔄 Iniciando sincronização NFTables ↔ Blacklist (SEM geolocalização - rápido)")
            
            # Extrai IPs do nftables
            nft_ips = self.extract_all_nftables_ips()
            
            if not nft_ips:
                self.logger.info("✅ Nenhum IP encontrado no NFTables")
                return 0, 0
            
            # Sincroniza com blacklist
            new_to_blacklist, missing_in_nft = self.sync_to_blacklist(
                nft_ips, 
                add_geolocation=add_geolocation,
                max_geo_requests=max_geo_requests
            )
            
            # Se solicitado, adiciona IPs do blacklist ao NFTables
            new_to_nft = 0
            if sync_to_nftables and missing_in_nft > 0:
                existing_ips = self._read_existing_blacklist()
                ips_to_add_nft = {}
                
                for ip, info in existing_ips.items():
                    if ip not in nft_ips:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if self.whitelist_manager and self.whitelist_manager.is_whitelisted(ip_obj):
                                continue
                            ips_to_add_nft[ip] = info
                        except ValueError:
                            continue
                
                new_to_nft = self.sync_blacklist_to_nftables(ips_to_add_nft)
            
            # Log final
            self.logger.info(f"✅ Sincronização concluída:")
            self.logger.info(f"   📥 {new_to_blacklist} IPs adicionados ao blacklist")
            if sync_to_nftables:
                self.logger.info(f"   📤 {new_to_nft} IPs adicionados ao NFTables")
            elif missing_in_nft > 0:
                self.logger.info(f"   💡 {missing_in_nft} IPs do blacklist não estão no NFTables")
            
            return new_to_blacklist, new_to_nft
            
        except Exception as e:
            self.logger.error(f"❌ Erro durante sincronização: {e}")
            raise
    
    def _read_existing_blacklist(self) -> Dict[str, Dict]:
        """Lê o blacklist existente"""
        from .blacklist_writer import BlacklistWriter
        writer = BlacklistWriter(self.config)
        return writer.read_blacklist(self.config.blacklist_ipv4_file)
    
    def _write_blacklist(self, all_ips: Dict[str, Dict], new_count: int):
        """Escreve o arquivo de blacklist"""
        from .blacklist_writer import BlacklistWriter
        writer = BlacklistWriter(self.config)
        writer.write_blacklist(self.config.blacklist_ipv4_file, all_ips, new_count)
