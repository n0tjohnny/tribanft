"""
TribanFT Parser Pattern Loader

Loads and caches YAML-based parser pattern definitions.

Provides pattern loading and pre-compilation for log parsers,
similar to RuleEngine but focused on parser-specific patterns.

Author: TribanFT Project
License: GNU GPL v3
"""

import yaml
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


class ParserPatternLoader:
    """
    Loads and caches YAML-based parser patterns.

    Scans patterns directory for YAML files and provides pre-compiled
    regex patterns organized by parser name and pattern group.

    Usage:
        loader = ParserPatternLoader(patterns_dir)
        patterns = loader.get_compiled_patterns('apache', 'sql_injection')

    Attributes:
        patterns_dir: Directory containing parser YAML files
        logger: Logger instance
        _pattern_cache: Cached YAML data by parser name
        _compiled_cache: Cached compiled patterns by (parser, group)
    """

    def __init__(self, patterns_dir: Path):
        """
        Initialize pattern loader.

        Args:
            patterns_dir: Directory to scan for parser YAML files
        """
        self.patterns_dir = Path(patterns_dir)
        self.logger = logging.getLogger(__name__)
        self._pattern_cache: Dict[str, Dict[str, Any]] = {}
        self._compiled_cache: Dict[Tuple[str, str], List[Tuple[re.Pattern, str]]] = {}

        # Auto-load patterns on initialization
        self._load_all_patterns()

    def _load_all_patterns(self):
        """
        Load all YAML pattern files from patterns directory.

        Scans for *.yaml and *.yml files recursively.
        Caches pattern data and compiles regex patterns.
        """
        if not self.patterns_dir.exists():
            self.logger.warning(f"Parser patterns directory not found: {self.patterns_dir}")
            self.logger.warning("Parser pattern matching will not work")
            return

        self.logger.info(f"Loading parser patterns from {self.patterns_dir}")

        # Scan for YAML files
        yaml_files = list(self.patterns_dir.glob("**/*.yaml")) + list(self.patterns_dir.glob("**/*.yml"))

        # Filter out template/example files
        yaml_files = [f for f in yaml_files if not f.name.endswith('.example')]

        for pattern_file in yaml_files:
            try:
                with open(pattern_file, 'r', encoding='utf-8') as f:
                    pattern_data = yaml.safe_load(f)

                # Extract metadata
                metadata = pattern_data.get('metadata', {})
                parser_name = metadata.get('name', pattern_file.stem)

                # Cache the pattern data
                self._pattern_cache[parser_name] = pattern_data

                # Pre-compile all pattern groups
                pattern_groups = pattern_data.get('pattern_groups', {})
                for group_name, patterns in pattern_groups.items():
                    self._compile_pattern_group(parser_name, group_name, patterns)

                self.logger.info(
                    f"✓ Loaded patterns for parser '{parser_name}' from {pattern_file.name} "
                    f"({len(pattern_groups)} groups)"
                )

            except yaml.YAMLError as e:
                self.logger.error(f"YAML parsing error in {pattern_file}: {e}")
            except Exception as e:
                self.logger.error(f"Failed to load patterns from {pattern_file}: {e}")

        self.logger.info(
            f"Loaded patterns for {len(self._pattern_cache)} parsers, "
            f"{len(self._compiled_cache)} pattern groups total"
        )

    def _compile_pattern_group(
        self,
        parser_name: str,
        group_name: str,
        patterns: List[Dict[str, Any]]
    ):
        """
        Compile regex patterns for a pattern group.

        Args:
            parser_name: Name of the parser
            group_name: Name of the pattern group
            patterns: List of pattern dictionaries from YAML
        """
        if not isinstance(patterns, list):
            self.logger.error(
                f"Pattern group '{group_name}' in parser '{parser_name}' is not a list"
            )
            return

        compiled_patterns = []

        for i, pattern_def in enumerate(patterns):
            if not isinstance(pattern_def, dict):
                self.logger.warning(
                    f"Pattern {i} in group '{group_name}' (parser '{parser_name}') "
                    f"is not a dictionary, skipping"
                )
                continue

            try:
                pattern_str = pattern_def.get('regex', '')
                if not pattern_str:
                    self.logger.warning(
                        f"Pattern {i} in group '{group_name}' (parser '{parser_name}') "
                        f"has no 'regex' field, skipping"
                    )
                    continue

                description = pattern_def.get('description', f'Pattern {i}')

                # Parse regex flags (for future enhancement)
                flags = 0
                for flag_name in pattern_def.get('flags', []):
                    if flag_name.upper() == 'IGNORECASE':
                        flags |= re.IGNORECASE
                    elif flag_name.upper() == 'MULTILINE':
                        flags |= re.MULTILINE
                    elif flag_name.upper() == 'DOTALL':
                        flags |= re.DOTALL

                # Compile the regex
                compiled_pattern = re.compile(pattern_str, flags)
                compiled_patterns.append((compiled_pattern, description))

            except re.error as e:
                self.logger.error(
                    f"Invalid regex in parser '{parser_name}', "
                    f"group '{group_name}', pattern {i}: {pattern_str} - {e}"
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to compile pattern {i} in group '{group_name}' "
                    f"(parser '{parser_name}'): {e}"
                )

        # Cache the compiled patterns
        cache_key = (parser_name, group_name)
        self._compiled_cache[cache_key] = compiled_patterns

        self.logger.debug(
            f"Compiled {len(compiled_patterns)} patterns for parser '{parser_name}', "
            f"group '{group_name}'"
        )

    def load_patterns(self, parser_name: str) -> Optional[Dict[str, Any]]:
        """
        Load pattern data for a specific parser.

        Args:
            parser_name: Name of the parser (from METADATA['name'])

        Returns:
            Dictionary containing pattern data or None if not found
        """
        if parser_name in self._pattern_cache:
            return self._pattern_cache[parser_name]

        self.logger.warning(f"No patterns found for parser '{parser_name}'")
        return None

    def get_compiled_patterns(
        self,
        parser_name: str,
        group_name: str
    ) -> List[Tuple[re.Pattern, str]]:
        """
        Get pre-compiled regex patterns for a pattern group.

        Returns list of tuples: (compiled_regex, description)

        Args:
            parser_name: Name of the parser (from METADATA['name'])
            group_name: Name of the pattern group

        Returns:
            List of tuples (compiled_pattern, description)
            Returns empty list if parser/group not found
        """
        cache_key = (parser_name, group_name)

        if cache_key in self._compiled_cache:
            return self._compiled_cache[cache_key]

        # Pattern group not found - log debug message (not error)
        self.logger.debug(
            f"Pattern group '{group_name}' not found for parser '{parser_name}'. "
            f"Returning empty pattern list."
        )

        return []

    def get_available_parsers(self) -> List[str]:
        """
        Get list of parser names with loaded patterns.

        Returns:
            List of parser names
        """
        return list(self._pattern_cache.keys())

    def get_available_groups(self, parser_name: str) -> List[str]:
        """
        Get list of available pattern groups for a parser.

        Args:
            parser_name: Name of the parser

        Returns:
            List of pattern group names, or empty list if parser not found
        """
        pattern_data = self.load_patterns(parser_name)
        if pattern_data:
            return list(pattern_data.get('pattern_groups', {}).keys())
        return []

    def reload_patterns(self):
        """
        Reload all patterns from disk.

        Useful for live updates without restarting service.
        """
        self.logger.info("Reloading parser patterns...")
        self._pattern_cache.clear()
        self._compiled_cache.clear()
        self._load_all_patterns()
        self.logger.info(
            f"Reloaded patterns for {len(self._pattern_cache)} parsers"
        )

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of loaded patterns.

        Returns:
            Dictionary with pattern statistics
        """
        summary = {
            'total_parsers': len(self._pattern_cache),
            'total_groups': len(self._compiled_cache),
            'parsers': {}
        }

        for parser_name in self._pattern_cache.keys():
            groups = self.get_available_groups(parser_name)
            group_counts = {}
            for group_name in groups:
                patterns = self.get_compiled_patterns(parser_name, group_name)
                group_counts[group_name] = len(patterns)

            summary['parsers'][parser_name] = {
                'groups': len(groups),
                'pattern_counts': group_counts
            }

        return summary
