"""
bruteforce_detector/managers/__init__.py

System management modules - Modular Architecture
"""

from .whitelist import WhitelistManager
from .blacklist import BlacklistManager
from .nftables_manager import NFTablesManager, NFTablesSync
from .state import StateManager
from .geolocation import IPGeolocationManager

# New modular modules
from .log_searcher import LogSearcher
from .blacklist_writer import BlacklistWriter
from .ip_investigator import IPInvestigator
from .ipinfo_batch_manager import IPInfoBatchManager


__all__ = [
    # Main managers
    'WhitelistManager',
    'BlacklistManager',
    'NFTablesManager',
    'StateManager',
    'IPGeolocationManager',

    # Specialized modules
    'LogSearcher',
    'BlacklistWriter',
    'IPInvestigator',
    'NFTablesSync',
    'IPInfoBatchManager'
]

# SQLite support
from .database import BlacklistDatabase
from .blacklist_adapter import BlacklistAdapter

__all__.extend(['BlacklistDatabase', 'BlacklistAdapter'])
