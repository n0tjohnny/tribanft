"""
bruteforce_detector/managers/__init__.py

Módulos de gerenciamento do sistema - Arquitetura Modular
"""

from .whitelist import WhitelistManager
from .blacklist import BlacklistManager
from .nftables import NFTablesManager
from .state import StateManager
from .geolocation import IPGeolocationManager

# Novos módulos modulares
from .log_searcher import LogSearcher
from .blacklist_writer import BlacklistWriter
from .ip_investigator import IPInvestigator
from .nftables_sync import NFTablesSync
from .ipinfo_batch_manager import IPInfoBatchManager


__all__ = [
    # Managers principais
    'WhitelistManager',
    'BlacklistManager',
    'NFTablesManager', 
    'StateManager',
    'IPGeolocationManager',
    
    # Módulos especializados
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
