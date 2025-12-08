#!/usr/bin/env python3
"""
tribanft-ipinfo-query.py

Utilitário para consultar e exportar dados do JSON de resultados do ipinfo.io
"""

import json
import sys
import csv
import argparse
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class IPInfoQueryTool:
    """Ferramenta para consultar resultados do ipinfo.io"""
    
    def __init__(self, results_file: str = "/root/projeto-ip-info-results.json"):
        self.results_file = Path(results_file)
        self.data = self._load_data()
    
    def _load_data(self) -> Dict:
        """Carrega dados do JSON"""
        if not self.results_file.exists():
            print(f"❌ Arquivo não encontrado: {self.results_file}")
            sys.exit(1)
        
        try:
            with open(self.results_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"✅ Carregados {len(data)} IPs")
            return data
        except Exception as e:
            print(f"❌ Erro ao carregar dados: {e}")
            sys.exit(1)
    
    def search_ip(self, ip: str):
        """Busca informações de um IP específico"""
        if ip in self.data:
            print(f"\n📍 Informações de {ip}:")
            print("="*70)
            data = self.data[ip]
            for key, value in sorted(data.items()):
                if value not in [None, '', []]:
                    print(f"  {key:20s}: {value}")
        else:
            print(f"❌ IP {ip} não encontrado no cache")
    
    def search_country(self, country: str):
        """Busca IPs de um país específico"""
        results = []
        for ip, data in self.data.items():
            if data.get('country', '').lower() == country.lower():
                results.append(ip)
        
        if results:
            print(f"\n🌍 {len(results)} IPs encontrados para {country}:")
            for ip in results[:20]:
                isp = self.data[ip].get('org', 'N/A')
                print(f"  {ip:20s} {isp}")
            if len(results) > 20:
                print(f"  ... e mais {len(results) - 20} IPs")
        else:
            print(f"❌ Nenhum IP encontrado para {country}")
    
    def list_countries(self):
        """Lista todos os países no cache"""
        countries = {}
        for ip, data in self.data.items():
            country = data.get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        print(f"\n🌍 Países no cache ({len(countries)} países):")
        print("="*70)
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True):
            print(f"  {country:30s}: {count:6d} IPs")
    
    def export_to_csv(self, output_file: str, fields: List[str] = None):
        """Exporta dados para CSV"""
        if not fields:
            # Campos padrão
            fields = [
                'ip', 'country', 'countryCode', 'region', 'city', 
                'isp', 'org', 'as', 'hostname', 'reverse',
                'hosting', 'proxy', 'vpn', 'mobile',
                'lat', 'lon', 'timezone', 'postal'
            ]
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for ip, data in self.data.items():
                    row = {'ip': ip}
                    for field in fields:
                        if field != 'ip':
                            row[field] = data.get(field, '')
                    writer.writerow(row)
            
            print(f"✅ {len(self.data)} IPs exportados para {output_file}")
        except Exception as e:
            print(f"❌ Erro ao exportar: {e}")
    
    def show_stats(self):
        """Exibe estatísticas do cache"""
        total = len(self.data)
        
        # Conta tipos de serviços
        hosting = sum(1 for d in self.data.values() if d.get('hosting'))
        proxy = sum(1 for d in self.data.values() if d.get('proxy'))
        vpn = sum(1 for d in self.data.values() if d.get('vpn'))
        mobile = sum(1 for d in self.data.values() if d.get('mobile'))
        
        # Conta importados do CSV
        from_csv = sum(1 for d in self.data.values() if d.get('imported_from_csv'))
        
        # Países únicos
        countries = set(d.get('country', 'Unknown') for d in self.data.values())
        
        print("\n📊 ESTATÍSTICAS DO CACHE")
        print("="*70)
        print(f"  Total de IPs:        {total:,}")
        print(f"  Países únicos:       {len(countries)}")
        print(f"  Hosting:             {hosting:,} ({hosting/total*100:.1f}%)")
        print(f"  Proxy:               {proxy:,} ({proxy/total*100:.1f}%)")
        print(f"  VPN:                 {vpn:,} ({vpn/total*100:.1f}%)")
        print(f"  Mobile:              {mobile:,} ({mobile/total*100:.1f}%)")
        print(f"  Importados do CSV:   {from_csv:,}")
        print("="*70)
    
    def filter_and_export(self, output_file: str, filters: Dict):
        """Exporta IPs filtrados"""
        filtered = []
        
        for ip, data in self.data.items():
            match = True
            
            # Aplica filtros
            if 'country' in filters and data.get('country') != filters['country']:
                match = False
            if 'hosting' in filters and data.get('hosting') != filters['hosting']:
                match = False
            if 'proxy' in filters and data.get('proxy') != filters['proxy']:
                match = False
            
            if match:
                filtered.append({'ip': ip, **data})
        
        if filtered:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if filtered:
                    writer = csv.DictWriter(f, fieldnames=filtered[0].keys())
                    writer.writeheader()
                    writer.writerows(filtered)
            
            print(f"✅ {len(filtered)} IPs filtrados exportados para {output_file}")
        else:
            print("❌ Nenhum IP correspondeu aos filtros")


def main():
    parser = argparse.ArgumentParser(
        description='Ferramenta de consulta para resultados do ipinfo.io',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📝 EXEMPLOS DE USO:
  %(prog)s --stats                              # Estatísticas gerais
  %(prog)s --search-ip 1.2.3.4                  # Busca IP específico
  %(prog)s --search-country BR                  # IPs do Brasil
  %(prog)s --list-countries                     # Lista todos os países
  %(prog)s --export results.csv                 # Exporta tudo para CSV
  %(prog)s --export filtered.csv --hosting      # Apenas IPs de hosting
        """
    )
    
    parser.add_argument('--file', '-f', 
                       default='/root/projeto-ip-info-results.json',
                       help='Arquivo JSON de resultados')
    
    parser.add_argument('--stats', '-s', 
                       action='store_true',
                       help='Exibe estatísticas')
    
    parser.add_argument('--search-ip', 
                       help='Busca informações de um IP')
    
    parser.add_argument('--search-country', 
                       help='Busca IPs de um país (código de 2 letras)')
    
    parser.add_argument('--list-countries', 
                       action='store_true',
                       help='Lista todos os países')
    
    parser.add_argument('--export', 
                       help='Exporta para CSV')
    
    parser.add_argument('--hosting', 
                       action='store_true',
                       help='Filtra apenas IPs de hosting')
    
    parser.add_argument('--proxy', 
                       action='store_true',
                       help='Filtra apenas proxies')
    
    args = parser.parse_args()
    
    # Inicializa ferramenta
    tool = IPInfoQueryTool(args.file)
    
    # Executa ações
    if args.stats:
        tool.show_stats()
    
    if args.search_ip:
        tool.search_ip(args.search_ip)
    
    if args.search_country:
        tool.search_country(args.search_country)
    
    if args.list_countries:
        tool.list_countries()
    
    if args.export:
        if args.hosting or args.proxy:
            filters = {}
            if args.hosting:
                filters['hosting'] = True
            if args.proxy:
                filters['proxy'] = True
            tool.filter_and_export(args.export, filters)
        else:
            tool.export_to_csv(args.export)
    
    # Se nenhuma ação, exibe stats
    if not any([args.stats, args.search_ip, args.search_country, 
                args.list_countries, args.export]):
        tool.show_stats()


if __name__ == "__main__":
    main()