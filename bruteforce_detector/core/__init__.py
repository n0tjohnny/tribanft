"""
TribanFT Core Framework

Core components for plugin management and extensibility.

Key features:
- Plugin auto-discovery and loading
- Dependency injection for plugins
- Detector and parser registration
- YAML-based rule engine
- YAML-based parser patterns

Author: TribanFT Project
License: GNU GPL v3
"""

from .plugin_manager import PluginManager
from .rule_engine import RuleEngine
from .parser_pattern_loader import ParserPatternLoader

__all__ = ['PluginManager', 'RuleEngine', 'ParserPatternLoader']
