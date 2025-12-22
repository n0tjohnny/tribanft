"""
TribanFT IP Geolocation Manager

Provides IP geolocation services with rate limiting and caching.

Integrates with IP-API.com free service to enrich threat intelligence with:
- Geographic location (country, city, coordinates)
- ISP and organization information  
- Connection type and timezone

Features:
- Automatic rate limiting (45 requests/minute)
- 24-hour result caching
- Graceful degradation on API failures

Author: TribanFT Project
License: GNU GPL v3
"""

import requests
import time
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
import ipaddress


class IPGeolocationManager:
    """Manages IP geolocation with rate limiting and caching."""
    
    def __init__(self):
        """Initialize geolocation manager with API configuration."""
        self.logger = logging.getLogger(__name__)
        self.base_url = "http://ip-api.com/json"
        self.rate_limit_remaining = 45  # Free tier limit
        self.rate_limit_reset_time = None
        self.last_request_time = None
        self.cache = {}
        
    def get_ip_info(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[Dict]:
        """
        Retrieve geolocation data for IP address.
        
        Checks cache first, then queries API with rate limiting.
        
        Args:
            ip: IP address object to lookup
            
        Returns:
            Dict with country, city, ISP, coordinates, etc. or None on failure
        """
        ip_str = str(ip)
        
        # Check 24-hour cache
        if ip_str in self.cache:
            cached_data = self.cache[ip_str]
            if datetime.now() - cached_data['timestamp'] < timedelta(hours=24):
                return cached_data['data']
        
        # Rate limiting check
        self._check_rate_limit()
        
        try:
            # Query API with comprehensive field set
            response = requests.get(
                f"{self.base_url}/{ip_str}?fields=22740991", 
                timeout=10
            )
            
            # Update rate limits from response headers
            self._update_rate_limits(response.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    # Cache result
                    self.cache[ip_str] = {
                        'data': data,
                        'timestamp': datetime.now()
                    }
                    return data
                else:
                    self.logger.warning(f"IP-API error for {ip_str}: {data.get('message')}")
            elif response.status_code == 429:
                self.logger.warning("Rate limit exceeded for IP-API")
                self._handle_rate_limit_exceeded(response.headers)
            else:
                self.logger.error(f"HTTP {response.status_code} from IP-API")
                
        except requests.RequestException as e:
            self.logger.error(f"IP-API request failed: {e}")
            
        return None
    
    def _check_rate_limit(self):
        """Wait if rate limit exceeded."""
        if self.rate_limit_remaining <= 0 and self.rate_limit_reset_time:
            now = datetime.now()
            if now < self.rate_limit_reset_time:
                wait_seconds = (self.rate_limit_reset_time - now).total_seconds()
                self.logger.info(f"Rate limit: waiting {wait_seconds:.1f}s")
                time.sleep(wait_seconds + 1)
                self.rate_limit_remaining = 45
    
    def _update_rate_limits(self, headers):
        """Parse rate limit info from response headers."""
        try:
            x_rl = headers.get('X-Rl')
            x_ttl = headers.get('X-Ttl')
            
            if x_rl is not None:
                self.rate_limit_remaining = int(x_rl)
            
            if x_ttl is not None:
                reset_seconds = int(x_ttl)
                self.rate_limit_reset_time = datetime.now() + timedelta(seconds=reset_seconds)
                
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed parsing rate limit headers: {e}")
    
    def _handle_rate_limit_exceeded(self, headers):
        """Handle 429 rate limit response."""
        self.rate_limit_remaining = 0
        self._update_rate_limits(headers)