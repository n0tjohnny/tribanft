"""
TribanFT IPInfo Query Tool

Command-line utility for querying and exporting IPInfo.io cache data.

Provides:
- IP search and lookup
- Country-based filtering
- Statistics and analytics
- CSV export functionality
- Filtering by hosting/proxy/VPN

Author: TribanFT Project
License: GNU GPL v3
"""

#!/usr/bin/env python3
import json
import sys
import csv
import argparse
from pathlib import Path
from typing import Dict, List


class IPInfoQueryTool:
    """Query tool for IPInfo.io results cache"""
    
    def __init__(self, results_file: str = "/root/projeto-ip-info-results.json"):
        """Initialize with results file path."""
        self.results_file = Path(results_file)
        self.data = self._load_data()
    
    def _load_data(self) -> Dict:
        """Load data from JSON cache."""
        if not self.results_file.exists():
            print(f"❌ File not found: {self.results_file}")
            sys.exit(1)
        
        try:
            with open(self.results_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"✅ Loaded {len(data)} IPs")
            return data
        except Exception as e:
            print(f"❌ Load error: {e}")
            sys.exit(1)
    
    def search_ip(self, ip: str):
        """Search for specific IP information."""
        if ip in self.data:
            print(f"\n🔍 Information for {ip}:")
            print("="*70)
            for key, value in sorted(self.data[ip].items()):
                if value not in [None, '', []]:
                    print(f"  {key:20s}: {value}")
        else:
            print(f"❌ IP {ip} not found in cache")
    
    def search_country(self, country: str):
        """Search IPs by country code."""
        results = [ip for ip, data in self.data.items() 
                  if data.get('country', '').lower() == country.lower()]
        
        if results:
            print(f"\n🌍 {len(results)} IPs found for {country}:")
            for ip in results[:20]:
                print(f"  {ip:20s} {self.data[ip].get('org', 'N/A')}")
            if len(results) > 20:
                print(f"  ... and {len(results) - 20} more")
        else:
            print(f"❌ No IPs found for {country}")
    
    def list_countries(self):
        """List all countries in cache."""
        countries = {}
        for data in self.data.values():
            country = data.get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        print(f"\n🌍 Countries in cache ({len(countries)} countries):")
        print("="*70)
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True):
            print(f"  {country:30s}: {count:6d} IPs")
    
    def export_to_csv(self, output_file: str, fields: List[str] = None):
        """Export data to CSV."""
        if not fields:
            fields = ['ip', 'country', 'countryCode', 'region', 'city', 
                     'isp', 'org', 'as', 'hostname', 'lat', 'lon']
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for ip, data in self.data.items():
                    row = {'ip': ip}
                    row.update({f: data.get(f, '') for f in fields if f != 'ip'})
                    writer.writerow(row)
            
            print(f"✅ {len(self.data)} IPs exported to {output_file}")
        except Exception as e:
            print(f"❌ Export error: {e}")
    
    def show_stats(self):
        """Display cache statistics."""
        total = len(self.data)
        hosting = sum(1 for d in self.data.values() if d.get('hosting'))
        proxy = sum(1 for d in self.data.values() if d.get('proxy'))
        vpn = sum(1 for d in self.data.values() if d.get('vpn'))
        countries = len(set(d.get('country', 'Unknown') for d in self.data.values()))
        
        print("\n📊 CACHE STATISTICS")
        print("="*70)
        print(f"  Total IPs:      {total:,}")
        print(f"  Countries:      {countries}")
        print(f"  Hosting:        {hosting:,} ({hosting/total*100:.1f}%)")
        print(f"  Proxy:          {proxy:,} ({proxy/total*100:.1f}%)")
        print(f"  VPN:            {vpn:,} ({vpn/total*100:.1f}%)")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(description='IPInfo.io query tool')
    parser.add_argument('--file', '-f', default='/root/projeto-ip-info-results.json')
    parser.add_argument('--stats', '-s', action='store_true')
    parser.add_argument('--search-ip', help='Search specific IP')
    parser.add_argument('--search-country', help='Search by country code')
    parser.add_argument('--list-countries', action='store_true')
    parser.add_argument('--export', help='Export to CSV')
    
    args = parser.parse_args()
    tool = IPInfoQueryTool(args.file)
    
    if args.stats or not any([args.search_ip, args.search_country, 
                               args.list_countries, args.export]):
        tool.show_stats()
    if args.search_ip:
        tool.search_ip(args.search_ip)
    if args.search_country:
        tool.search_country(args.search_country)
    if args.list_countries:
        tool.list_countries()
    if args.export:
        tool.export_to_csv(args.export)


if __name__ == "__main__":
    main()