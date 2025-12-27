"""
TribanFT Helper Utilities

General utility functions for data handling and processing.

Provides safe wrappers for common operations:
- JSON parsing with error handling
- Data sanitization

Used throughout the application for robust data processing.

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Any, Dict
import json


def safe_json_loads(data: str) -> Dict[str, Any]:
    """
    Safely parse JSON string with error handling.
    
    Returns empty dict on parse failure instead of raising exception,
    allowing graceful degradation in data processing.
    
    Args:
        data: JSON string to parse
        
    Returns:
        Parsed dict or empty dict on error
        
    Example:
        >>> safe_json_loads('{"key": "value"}')
        {'key': 'value'}
        >>> safe_json_loads('invalid json')
        {}
    """
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}