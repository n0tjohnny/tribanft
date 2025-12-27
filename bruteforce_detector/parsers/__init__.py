"""
TribanFT Log Parsers

Parser implementations are located in bruteforce_detector/plugins/parsers/
and are auto-discovered by the PluginManager.

This module only contains the base parser class.
"""

from .base import BaseLogParser

__all__ = ['BaseLogParser']