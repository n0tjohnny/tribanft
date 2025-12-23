#!/usr/bin/env python3
"""
TribanFT IPInfo Batch Manager

Batch geolocation processing with caching and rate limiting.

Manages bulk geolocation lookups for blacklist IPs using IPInfo.io API.
Features:
- Auto-loads existing CSV/JSON caches
- Rate limiting (1000/day, 15/minute)
- Persistent caching to minimize API calls
- Batch processing with priority for cached data
- DATABASE SUPPORT via BlacklistAdapter
- File locking for concurrent operation safety

Used as systemd service for background geolocation enrichment.

Author: TribanFT Project
License: GNU GPL v3
"""

import json
import logging
import time
import csv
from typing import Dict, Optional, Any
from pathlib import Path
from datetime import datetime
import ipaddress
import requests

from bruteforce_detector.managers.blacklist_adapter import BlacklistAdapter
from bruteforce_detector.utils.file_lock import FileLockContext, cleanup_stale_lock


class IPInfoBatchManager:
    """Optimized batch manager with auto-load caches"""
    
    def __init__(self, config, api_token: Optional[str] = None):
        """Initialize batch manager with config and API token."""
        self.config = config
        self.logger = logging.getLogger(__name__)

        # DEBUG: Log what config value we're getting
        self.logger.info(f"DEBUG: config.use_database = {config.use_database} (type: {type(config.use_database)})")

        self.blacklist_adapter = BlacklistAdapter(config, use_database=config.use_database)
        
        self.api_token = api_token or self._load_token()
        self.base_url = "https://ipinfo.io"
        
        # Rate limits
        self.daily_limit = 2000
        self.rate_limit_per_minute = 15

        # Paths from config
        self.cache_dir = Path(config.ipinfo_cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.results_file = Path(config.ipinfo_results_file)
        self.stats_file = self.cache_dir / "ipinfo_stats.json"

        # Log loaded paths for debugging (Pattern #1)
        self.logger.info(f"DEBUG: CONFIG: ipinfo_cache_dir = {self.cache_dir}")
        self.logger.info(f"DEBUG: CONFIG: ipinfo_results_file = {self.results_file}")
        self.logger.info(f"DEBUG: CONFIG: ipinfo_token_file = {config.ipinfo_token_file}")
        
        # File locking for concurrent operation safety
        self.lock_file = self.cache_dir / ".ipinfo.lock"
        
        # Clean up stale locks on startup
        if cleanup_stale_lock(self.lock_file, max_age_seconds=300):
            self.logger.info("Cleaned up stale lock file on startup")
        
        self.file_lock = FileLockContext(self.lock_file, timeout=60)
        
        # Auto-load caches
        self.cache = self._load_all_caches()
        self.stats = self._load_stats()
        
        # Rate limiting state
        self.requests_this_minute = 0
        self.minute_window_start = datetime.now()
        self.requests_today = self.stats.get('requests_today', 0)
        self.last_reset_date = self.stats.get('last_reset_date', datetime.now().date().isoformat())
    
    def _load_all_caches(self) -> Dict[str, Dict]:
        """Load all available caches (JSON + CSV)."""
        cache = {}
        
        # JSON cache
        if self.results_file.exists():
            try:
                with open(self.results_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cache.update(data)
                    self.logger.info(f"JSON cache: {len(data)} IPs")
            except Exception as e:
                self.logger.warning(f"JSON cache error: {e}")
        
        # Legacy CSV cache (from config)
        csv_file = Path(self.config.ipinfo_csv_cache_file)
        if csv_file.exists():
            try:
                csv_count = 0
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ip = row.get('query') or row.get('ip')
                        if ip and ip not in cache:
                            cache[ip] = self._csv_to_ipinfo_format(row)
                            csv_count += 1
                self.logger.info(f"CSV cache: {csv_count} IPs")
            except Exception as e:
                self.logger.warning(f"CSV cache error: {e}")
        
        self.logger.info(f"Total cache: {len(cache)} IPs")
        return cache
    
    def _csv_to_ipinfo_format(self, row: Dict) -> Dict:
        """Convert CSV row to IPInfo format."""
        return {
            'ip': row.get('query') or row.get('ip'),
            'country': row.get('country'),
            'region': row.get('region'),
            'city': row.get('city'),
            'postal': row.get('zip'),
            'loc': f"{row.get('lat', '')},{row.get('lon', '')}",
            'timezone': row.get('timezone'),
            'org': row.get('org') or row.get('as'),
            'imported_from_csv': True
        }
    
    def _load_token(self) -> Optional[str]:
        """Load API token from file (from config)."""
        token_file = Path(self.config.ipinfo_token_file)
        if token_file.exists():
            try:
                token = token_file.read_text().strip()
                self.logger.info(f"DEBUG: CONFIG: Loaded API token from {token_file}")
                return token
            except Exception as e:
                self.logger.warning(f"Token error: {e}")
        else:
            self.logger.warning(f"WARNING: Token file not found: {token_file}")
        return None
    
    def _load_stats(self) -> Dict[str, Any]:
        """Load statistics from file."""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Stats error: {e}")
        
        return {
            'requests_today': 0,
            'last_reset_date': datetime.now().date().isoformat(),
            'total_requests': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
    
    def _check_rate_limits(self) -> bool:
        """Check and enforce rate limits."""
        current_date = datetime.now().date().isoformat()
        
        if current_date != self.last_reset_date:
            self.requests_today = 0
            self.last_reset_date = current_date
            self.stats['last_reset_date'] = current_date
            self.logger.info("Daily counter reset")
        
        if self.requests_today >= self.daily_limit:
            self.logger.warning(f"WARNING: Daily limit reached: {self.requests_today}/{self.daily_limit}")
            return False
        
        now = datetime.now()
        elapsed = (now - self.minute_window_start).total_seconds()

        if elapsed >= 60:
            self.requests_this_minute = 0
            self.minute_window_start = now

        if self.requests_this_minute >= self.rate_limit_per_minute:
            # Calculate remaining time in current minute window
            wait_time = max(1, 60 - elapsed)
            self.logger.warning(
                f"Per-minute limit reached ({self.requests_this_minute}/{self.rate_limit_per_minute}), "
                f"waiting {wait_time:.0f}s for window reset..."
            )
            time.sleep(wait_time)
            # Reset window after waiting
            self.requests_this_minute = 0
            self.minute_window_start = datetime.now()
            return False

        return True
    
    def get_ip_info(self, ip_str: str, use_cache: bool = True, _skip_lock: bool = False) -> Optional[Dict]:
        """Get IP info with caching and rate limiting.
        
        Args:
            ip_str: IP address to query
            use_cache: Whether to use cached results
            _skip_lock: Internal parameter to skip locking when already holding lock
        """
        if use_cache and ip_str in self.cache:
            self.stats['cache_hits'] = self.stats.get('cache_hits', 0) + 1
            return self.cache[ip_str]
        
        if not self._check_rate_limits():
            return None
        
        try:
            url = f"{self.base_url}/{ip_str}"
            if self.api_token:
                url += f"?token={self.api_token}"
            
            response = requests.get(url, timeout=10)
            self.requests_this_minute += 1
            
            if response.status_code == 200:
                data = response.json()
                data['query'] = ip_str
                data['timestamp'] = datetime.now().isoformat()
                self.cache[ip_str] = data
                
                self.requests_today += 1
                self.stats['api_calls'] = self.stats.get('api_calls', 0) + 1
                self.stats['requests_today'] = self.requests_today
                
                if self.stats['api_calls'] % 10 == 0:
                    self._save_results(_skip_lock=_skip_lock)
                    self._save_stats(_skip_lock=_skip_lock)
                
                return data
            elif response.status_code == 429:
                self.logger.warning("WARNING: Rate limit 429")
                time.sleep(60)
                self.requests_today = self.daily_limit
                return None
        except Exception as e:
            self.logger.error(f"Request error: {e}")
        
        return None
    
    def process_blacklist_batch(self, max_requests: Optional[int] = None) -> int:
        """Process blacklist with cache priority and file locking."""
        # Use config batch_size if not specified
        if max_requests is None:
            max_requests = self.config.batch_size
            self.logger.info(f"DEBUG: CONFIG: Using batch_size from config = {max_requests}")

        self.logger.info("Processing blacklist...")
        
        # Use file lock to prevent concurrent modifications
        with self.file_lock("blacklist batch processing"):
            blacklist_path = Path(self.config.blacklist_ipv4_file)
            if not blacklist_path.exists():
                self.logger.warning("WARNING: Blacklist not found")
                return 0
            
            existing = self.blacklist_adapter.read_blacklist(str(blacklist_path))
            
            # Find IPs without geo
            ips_without_geo = []
            for ip_str, info in existing.items():
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                
                geo = info.get('geolocation')
                if not geo or geo.get('country') in [None, 'Unknown', 'Unknown Location']:
                    ips_without_geo.append(ip_str)
            
            if not ips_without_geo:
                self.logger.info("SUCCESS: All IPs have geo")
                return 0
            
            self.logger.info(f"{len(ips_without_geo)} IPs without geo")

            # Process with cache priority
            from_cache = from_api = 0
            ips_to_update = {}
            total_updated = 0
            update_interval = 10  # Save to database every N API lookups

            for ip_str in ips_without_geo:
                # Cache hit
                if ip_str in self.cache:
                    full_data = self.cache[ip_str]
                    normalized = self._normalize_ipinfo_response(full_data)
                    ips_to_update[ip_str] = {
                        **existing[ip_str],
                        'geolocation': {
                            'country': normalized.get('country', 'Unknown'),
                            'city': normalized.get('city', ''),
                            'isp': normalized.get('org', 'Unknown ISP')
                        }
                    }
                    from_cache += 1

                # API call (if under limit)
                elif from_api < max_requests:
                    if not self._check_rate_limits():
                        continue

                    full_data = self.get_ip_info(ip_str, use_cache=False, _skip_lock=True)
                    if full_data:
                        normalized = self._normalize_ipinfo_response(full_data)
                        ips_to_update[ip_str] = {
                            **existing[ip_str],
                            'geolocation': {
                                'country': normalized.get('country', 'Unknown'),
                                'city': normalized.get('city', ''),
                                'isp': normalized.get('org', 'Unknown ISP')
                            }
                        }
                        from_api += 1

                        # Incremental save: write to database every N API lookups
                        if from_api % update_interval == 0 and ips_to_update:
                            self.logger.info(f"Incremental save: {len(ips_to_update)} IPs")
                            existing.update(ips_to_update)
                            self.blacklist_adapter.write_blacklist(str(blacklist_path), existing, len(ips_to_update))
                            total_updated += len(ips_to_update)
                            ips_to_update = {}  # Clear for next batch

            self.logger.info(f"Cache: {from_cache} | API: {from_api}")

            # Save any remaining updates (final batch)
            if ips_to_update:
                self.logger.info(f"Final save: {len(ips_to_update)} IPs")
                existing.update(ips_to_update)
                self.blacklist_adapter.write_blacklist(str(blacklist_path), existing, len(ips_to_update))
                total_updated += len(ips_to_update)
                self._save_results(_skip_lock=True)
                self._save_stats(_skip_lock=True)

            # Also save results/stats if we did incremental updates
            elif total_updated > 0:
                self._save_results(_skip_lock=True)
                self._save_stats(_skip_lock=True)

            return from_cache + from_api
    
    def _normalize_ipinfo_response(self, data: Dict) -> Dict:
        """Normalize to IP-API format."""
        loc = data.get('loc', ',').split(',')
        return {
            'country': data.get('country'),
            'city': data.get('city'),
            'isp': data.get('org', '').split()[0] if data.get('org') else None,
            'org': data.get('org'),
            'lat': loc[0] if len(loc) > 0 else None,
            'lon': loc[1] if len(loc) > 1 else None
        }
    
    def _save_results(self, _skip_lock: bool = False):
        """Save cache to JSON with file locking, atomic write, and retry logic.
        
        Args:
            _skip_lock: Internal parameter to skip locking when already holding lock
        """
        max_retries = 3
        retry_delay = 1.0
        
        def _do_save():
            """Perform actual save operation."""
            temp_file = self.results_file.parent / f'{self.results_file.name}.tmp'
            try:
                # Atomic write pattern: write to temp file, then rename
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(self.cache, f, indent=2, ensure_ascii=False)
                
                # Atomic rename
                temp_file.replace(self.results_file)
            except Exception as e:
                self.logger.error(f"Save error: {e}")
                # Clean up temp file if it exists
                if temp_file.exists():
                    temp_file.unlink()
                raise  # Re-raise to trigger retry
        
        for attempt in range(max_retries):
            try:
                if _skip_lock:
                    # Already holding lock, perform save directly
                    _do_save()
                    return
                else:
                    # Not holding lock, acquire it
                    with self.file_lock("cache save"):
                        _do_save()
                        return
                        
            except Exception as e:
                if attempt < max_retries - 1:
                    self.logger.warning(
                        f"WARNING: Cache save failed (attempt {attempt + 1}/{max_retries}): {e}. "
                        f"Retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    self.logger.error(
                        f"ERROR: Cache save failed after {max_retries} attempts: {e}. "
                        "Service will continue but cache may not be persisted."
                    )
    
    def _save_stats(self, _skip_lock: bool = False):
        """Save statistics to file with file locking, atomic write, and retry logic.
        
        Args:
            _skip_lock: Internal parameter to skip locking when already holding lock
        """
        max_retries = 3
        retry_delay = 1.0
        
        def _do_save():
            """Perform actual save operation."""
            temp_file = self.stats_file.parent / f'{self.stats_file.name}.tmp'
            try:
                # Atomic write pattern: write to temp file, then rename
                with open(temp_file, 'w') as f:
                    json.dump(self.stats, f, indent=2)
                
                # Atomic rename
                temp_file.replace(self.stats_file)
            except Exception as e:
                self.logger.error(f"Save stats error: {e}")
                # Clean up temp file if it exists
                if temp_file.exists():
                    temp_file.unlink()
                raise  # Re-raise to trigger retry
        
        for attempt in range(max_retries):
            try:
                if _skip_lock:
                    # Already holding lock, perform save directly
                    _do_save()
                    return
                else:
                    # Not holding lock, acquire it
                    with self.file_lock("stats save"):
                        _do_save()
                        return
                        
            except Exception as e:
                if attempt < max_retries - 1:
                    self.logger.warning(
                        f"WARNING: Stats save failed (attempt {attempt + 1}/{max_retries}): {e}. "
                        f"Retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    self.logger.error(
                        f"ERROR: Stats save failed after {max_retries} attempts: {e}. "
                        "Service will continue but stats may not be persisted."
                    )
    
    def get_stats_summary(self) -> Dict[str, Any]:
        """Get statistics summary."""
        remaining = max(0, self.daily_limit - self.requests_today)
        return {
            'requests_today': self.requests_today,
            'remaining_today': remaining,
            'daily_limit': self.daily_limit,
            'cache_size': len(self.cache),
            'cache_hits': self.stats.get('cache_hits', 0),
            'api_calls': self.stats.get('api_calls', 0)
        }
    
    def print_stats(self):
        """Print statistics."""
        stats = self.get_stats_summary()
        print("\nIPINFO BATCH STATISTICS")
        print("="*70)
        print(f"  Requests Today:    {stats['requests_today']}/{stats['daily_limit']}")
        print(f"  Remaining Today:   {stats['remaining_today']}")
        print(f"  Cache Size:        {stats['cache_size']:,} IPs")
        print(f"  Cache Hits:        {stats['cache_hits']:,}")
        print(f"  API Calls (total): {stats['api_calls']:,}")
        print("="*70)
