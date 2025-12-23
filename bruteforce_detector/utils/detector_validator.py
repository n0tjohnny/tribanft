"""
TribanFT Detector Configuration Validator

Validates detector configurations to prevent layer coherence issues.

Prevents common misconfigurations like:
- Using PORT_SCAN event_type with apache parser (L3/L4 vs L7 mismatch)
- Filtering by EventTypes that parsers don't generate
- Invalid parser/EventType combinations

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Set, List, Dict
from ..models import EventType
import logging


class DetectorValidationError(Exception):
    """Raised when detector configuration is invalid"""
    pass


class DetectorValidator:
    """
    Validates detector configurations for parser/EventType coherence.

    Ensures detectors only use EventTypes that their configured parsers
    can actually generate, preventing silent failures.
    """

    # Mapping of parser names to EventTypes they can generate
    PARSER_CAPABILITIES: Dict[str, Set[EventType]] = {
        'apache': {
            EventType.HTTP_REQUEST,
            EventType.FAILED_LOGIN,
            EventType.SQL_INJECTION,
            EventType.WORDPRESS_ATTACK,
            EventType.XSS_ATTACK,
            EventType.PATH_TRAVERSAL,
            EventType.COMMAND_INJECTION,
            EventType.FILE_UPLOAD_MALICIOUS,
        },

        'nginx': {
            # Same as apache (uses same parser class)
            EventType.HTTP_REQUEST,
            EventType.FAILED_LOGIN,
            EventType.SQL_INJECTION,
            EventType.WORDPRESS_ATTACK,
            EventType.XSS_ATTACK,
            EventType.PATH_TRAVERSAL,
            EventType.COMMAND_INJECTION,
            EventType.FILE_UPLOAD_MALICIOUS,
        },

        'mssql': {
            EventType.PRELOGIN_INVALID,
            EventType.FAILED_LOGIN,
        },

        'syslog': {
            EventType.FAILED_LOGIN,
            EventType.SSH_ATTACK,
            EventType.RDP_ATTACK,
        },

        'windows_security': {
            EventType.FAILED_LOGIN,
            EventType.RDP_ATTACK,
        },

        'nftables': {
            EventType.PORT_SCAN,
            EventType.NETWORK_SCAN,
        },

        'iptables': {
            EventType.PORT_SCAN,
            EventType.NETWORK_SCAN,
        },
    }

    def __init__(self):
        """Initialize validator with logger"""
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate_detector(self, detector_config: dict) -> None:
        """
        Validate a detector configuration.

        Args:
            detector_config: Detector configuration dict loaded from YAML

        Raises:
            DetectorValidationError: If configuration is invalid
        """
        metadata = detector_config.get('metadata', {})
        detector_name = metadata.get('name', 'unknown')

        # Get configured parsers
        log_sources = detector_config.get('log_sources', {})
        configured_parsers = log_sources.get('parsers', [])

        if not configured_parsers:
            # No parsers configured - warning but not error (might use all parsers)
            self.logger.warning(
                f"Detector '{detector_name}' has no parsers configured. "
                f"Will use all available parsers."
            )
            return

        # Get required event types
        detection = detector_config.get('detection', {})
        required_event_types = detection.get('event_types', [])

        if not required_event_types:
            # No event types - unusual but not invalid
            self.logger.warning(
                f"Detector '{detector_name}' has no event_types configured"
            )
            return

        # Convert string event types to EventType enum
        event_type_enums = []
        for et_str in required_event_types:
            try:
                # Try direct enum value
                event_type_enums.append(EventType(et_str.lower()))
            except ValueError:
                # Try enum name
                try:
                    event_type_enums.append(EventType[et_str.upper()])
                except KeyError:
                    raise DetectorValidationError(
                        f"Detector '{detector_name}': Unknown event_type '{et_str}'"
                    )

        # Validate each parser can generate at least one required event type
        for parser_name in configured_parsers:
            if parser_name not in self.PARSER_CAPABILITIES:
                self.logger.warning(
                    f"Detector '{detector_name}': Unknown parser '{parser_name}'. "
                    f"Skipping validation (might be custom parser)."
                )
                continue

            parser_capabilities = self.PARSER_CAPABILITIES[parser_name]

            # Check if parser can generate ANY of the required event types
            can_generate = set(event_type_enums) & parser_capabilities

            if not can_generate:
                # Parser cannot generate any required event types - ERROR
                raise DetectorValidationError(
                    f"Detector '{detector_name}': Parser '{parser_name}' cannot generate "
                    f"any of the required event_types {[et.value for et in event_type_enums]}. "
                    f"Parser '{parser_name}' can only generate: "
                    f"{[et.value for et in parser_capabilities]}. "
                    f"This detector will NEVER fire!"
                )

            # Check if some event types are unreachable (warning only)
            cannot_generate = set(event_type_enums) - parser_capabilities
            if cannot_generate:
                self.logger.warning(
                    f"Detector '{detector_name}': Parser '{parser_name}' cannot generate "
                    f"event_types {[et.value for et in cannot_generate]}. "
                    f"Detector will only match on {[et.value for et in can_generate]}."
                )

    def validate_all_detectors(self, detector_configs: List[dict]) -> Dict[str, List[str]]:
        """
        Validate multiple detector configurations.

        Args:
            detector_configs: List of detector configuration dicts

        Returns:
            Dict with 'errors' and 'warnings' lists

        Raises:
            DetectorValidationError: If any detector has critical errors
        """
        errors = []
        warnings = []

        for detector_config in detector_configs:
            detector_name = detector_config.get('metadata', {}).get('name', 'unknown')

            try:
                self.validate_detector(detector_config)
            except DetectorValidationError as e:
                error_msg = str(e)
                errors.append(error_msg)
                self.logger.error(error_msg)

        return {
            'errors': errors,
            'warnings': warnings
        }

    @staticmethod
    def get_parser_capabilities(parser_name: str) -> Set[EventType]:
        """
        Get EventTypes that a parser can generate.

        Args:
            parser_name: Name of parser (e.g., 'apache', 'nftables')

        Returns:
            Set of EventType enums the parser can generate
            Empty set if parser unknown
        """
        return DetectorValidator.PARSER_CAPABILITIES.get(parser_name, set())

    @staticmethod
    def get_parsers_for_event_type(event_type: EventType) -> List[str]:
        """
        Get parsers that can generate a specific EventType.

        Args:
            event_type: EventType enum

        Returns:
            List of parser names that can generate this event type
        """
        parsers = []
        for parser_name, capabilities in DetectorValidator.PARSER_CAPABILITIES.items():
            if event_type in capabilities:
                parsers.append(parser_name)
        return parsers

    @staticmethod
    def suggest_parser_for_detector(event_types: List[str]) -> List[str]:
        """
        Suggest appropriate parsers for a detector based on required event types.

        Args:
            event_types: List of event type strings

        Returns:
            List of parser names that can generate ALL required event types
        """
        if not event_types:
            return []

        # Convert to EventType enums
        event_type_enums = []
        for et_str in event_types:
            try:
                event_type_enums.append(EventType(et_str.lower()))
            except ValueError:
                try:
                    event_type_enums.append(EventType[et_str.upper()])
                except KeyError:
                    continue

        if not event_type_enums:
            return []

        # Find parsers that can generate ALL event types
        suitable_parsers = []
        for parser_name, capabilities in DetectorValidator.PARSER_CAPABILITIES.items():
            if all(et in capabilities for et in event_type_enums):
                suitable_parsers.append(parser_name)

        return suitable_parsers
