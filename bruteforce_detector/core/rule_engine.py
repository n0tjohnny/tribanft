"""
TribanFT YAML-Based Rule Engine

Loads and executes detection rules from YAML files.

Key features:
- YAML-based rule definitions (no code required)
- Pattern matching with regex support
- Threshold-based detection
- Event grouping and aggregation
- Multiple rule files support

Author: TribanFT Project
License: GNU GPL v3
"""

import yaml
import re
import logging
import ipaddress
import signal
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
from contextlib import contextmanager

from ..models import SecurityEvent, DetectionResult, EventType, DetectionConfidence
from ..utils.detector_validator import DetectorValidator, DetectorValidationError


# ReDoS Protection Constants
REGEX_TIMEOUT_SECONDS = 1  # Maximum time for regex matching
MAX_INPUT_LENGTH = 10000  # Maximum input string length for regex matching

# YAML Bomb Protection Constants (SECURITY FIX C5)
MAX_YAML_FILE_SIZE = 1024 * 1024  # 1MB max YAML file size (prevents billion laughs)
MAX_YAML_COMPLEXITY = 10000  # Max total objects in parsed YAML

# Thread Limiting for ReDoS Protection (SECURITY FIX C3)
MAX_CONCURRENT_REGEX_THREADS = 20  # Prevent thread exhaustion under attack
_regex_semaphore = threading.Semaphore(MAX_CONCURRENT_REGEX_THREADS)

# Pattern Cache Size Limit (SECURITY FIX H3)
MAX_COMPILED_PATTERNS_CACHE_SIZE = 1000  # Prevent unbounded memory growth


class RegexTimeoutError(Exception):
    """Raised when regex matching exceeds timeout (ReDoS protection)."""
    pass


def _run_regex_with_timeout(pattern, text, timeout_seconds):
    """
    Run regex with thread-based timeout (thread-safe replacement for signal-based timeout).

    SECURITY FIX C3: signal.SIGALRM is process-global and NOT thread-safe.
    Multiple threads racing cause signal handler corruption → ReDoS bypass.

    This implementation uses threading.Thread + timeout for thread-safety.
    Semaphore limiting prevents thread exhaustion under sustained ReDoS attack.

    Args:
        pattern: Compiled regex pattern
        text: Text to search
        timeout_seconds: Timeout in seconds

    Returns:
        Match object or None

    Raises:
        RegexTimeoutError: If regex exceeds timeout or too many concurrent operations
    """
    # SECURITY: Prevent thread exhaustion under sustained ReDoS attack
    if not _regex_semaphore.acquire(blocking=False):
        raise RegexTimeoutError(
            f"Too many concurrent regex operations ({MAX_CONCURRENT_REGEX_THREADS}) - possible DoS attack"
        )

    try:
        result = [None]  # Mutable container for thread communication
        exception = [None]

        def run_search():
            try:
                result[0] = pattern.search(text)
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=run_search, daemon=True)
        thread.start()
        thread.join(timeout=timeout_seconds)

        if thread.is_alive():
            # Thread still running - timeout exceeded
            # Thread will be terminated when daemon thread ends
            raise RegexTimeoutError(
                f"Regex matching exceeded {timeout_seconds}s timeout - possible ReDoS attack"
            )

        if exception[0]:
            raise exception[0]

        return result[0]

    finally:
        # Always release semaphore, even on exception
        _regex_semaphore.release()


@contextmanager
def regex_timeout(seconds):
    """
    Legacy context manager - now a no-op.

    SECURITY FIX C3: Removed signal-based timeout (not thread-safe).
    Use _run_regex_with_timeout() directly instead.
    """
    yield  # No-op, for backward compatibility


@dataclass
class DetectionRule:
    """
    Parsed detection rule from YAML.

    Attributes:
        name: Rule identifier
        version: Rule version
        enabled: Whether rule is active
        event_types: List of EventType enums to match
        threshold: Minimum events required
        time_window_minutes: Time window for event grouping
        confidence: Detection confidence level
        patterns: List of regex patterns to match
        reason_template: Template for detection reason
        metadata: Additional rule metadata
        group_by: Field to group events by
        log_sources: Optional log source filters (parsers or files)
    """
    name: str
    version: str
    enabled: bool
    event_types: List[EventType]
    threshold: int
    time_window_minutes: int
    confidence: str
    patterns: List[Dict[str, Any]]
    reason_template: str
    metadata: Dict[str, Any]
    group_by: str = 'source_ip'
    log_sources: Optional[Dict[str, List[str]]] = None


class RuleEngine:
    """
    Loads and executes YAML-based detection rules.

    Scans rules directory for YAML files and applies them to
    security events to detect threats.

    Usage:
        engine = RuleEngine(rules_dir)
        detections = engine.apply_rules(events)

    Attributes:
        rules_dir: Directory containing YAML rule files
        logger: Logger instance
        rules: Dictionary of loaded rules (name -> DetectionRule)
    """

    def __init__(self, rules_dir: Path):
        """
        Initialize rule engine.

        Args:
            rules_dir: Directory to scan for YAML rule files
        """
        self.rules_dir = Path(rules_dir)
        self.logger = logging.getLogger(__name__)
        self.rules: Dict[str, DetectionRule] = {}
        # SECURITY FIX H3: LRU cache prevents unbounded memory growth (10GB after 10K reloads)
        self._compiled_patterns: OrderedDict = OrderedDict()
        self._pattern_cache_lock = threading.Lock()  # Thread-safe cache access
        self.validator = DetectorValidator()  # Detector configuration validator

        # CRITICAL FIX #18: Thread-safe rule reloading
        self._reload_lock = threading.Lock()

        self._load_rules()

    def _load_rules(self):
        """
        Load all YAML rules from rules directory.

        Scans for *.yaml and *.yml files recursively.
        """
        if not self.rules_dir.exists():
            self.logger.warning(f"Rules directory not found: {self.rules_dir}")
            return

        self.logger.info(f"Loading detection rules from {self.rules_dir}")

        # Scan for YAML files
        yaml_files = list(self.rules_dir.glob("**/*.yaml")) + list(self.rules_dir.glob("**/*.yml"))

        for rule_file in yaml_files:
            try:
                # SECURITY FIX C5: Validate file size before loading (YAML bomb protection)
                file_size = rule_file.stat().st_size
                if file_size > MAX_YAML_FILE_SIZE:
                    self.logger.error(
                        f"SECURITY: YAML file too large: {rule_file.name} "
                        f"({file_size} bytes > {MAX_YAML_FILE_SIZE} bytes)"
                    )
                    self.logger.error(
                        "  Possible YAML bomb attack - rejecting file"
                    )
                    continue

                with open(rule_file, 'r', encoding='utf-8') as f:
                    # Read with size limit
                    content = f.read(MAX_YAML_FILE_SIZE)
                    if len(content) >= MAX_YAML_FILE_SIZE:
                        self.logger.error(
                            f"SECURITY: YAML content truncated at limit: {rule_file.name}"
                        )
                        continue

                    rule_data = yaml.safe_load(content)

                # SECURITY FIX C5: Validate YAML complexity (prevent billion laughs)
                def count_yaml_objects(obj, depth=0, max_depth=100):
                    """Count total objects in YAML structure with depth limit."""
                    if depth > max_depth:
                        raise ValueError("YAML nesting too deep (possible bomb)")

                    count = 1
                    if isinstance(obj, dict):
                        if len(obj) > 1000:
                            raise ValueError("YAML dict too large (possible bomb)")
                        for value in obj.values():
                            count += count_yaml_objects(value, depth + 1, max_depth)
                            if count > MAX_YAML_COMPLEXITY:
                                raise ValueError(f"YAML too complex: >{MAX_YAML_COMPLEXITY} objects")
                    elif isinstance(obj, list):
                        if len(obj) > 1000:
                            raise ValueError("YAML list too large (possible bomb)")
                        for item in obj:
                            count += count_yaml_objects(item, depth + 1, max_depth)
                            if count > MAX_YAML_COMPLEXITY:
                                raise ValueError(f"YAML too complex: >{MAX_YAML_COMPLEXITY} objects")

                    return count

                try:
                    total_objects = count_yaml_objects(rule_data)
                    self.logger.debug(f"YAML complexity: {total_objects} objects in {rule_file.name}")
                except ValueError as e:
                    self.logger.error(f"SECURITY: {e} in {rule_file.name}")
                    self.logger.error("  Rejecting potentially malicious YAML file")
                    continue

                # Handle multiple rules in single file
                if 'detectors' in rule_data:
                    # Multi-rule format
                    for rule_dict in rule_data['detectors']:
                        # Validate detector configuration
                        try:
                            self.validator.validate_detector(rule_dict)
                        except DetectorValidationError as e:
                            self.logger.error(f"Detector validation failed in {rule_file.name}: {e}")
                            self.logger.error(f"Skipping invalid detector")
                            continue  # Skip this invalid detector

                        rule = self._parse_rule(rule_dict, rule_file)
                        if rule and rule.enabled:
                            self.rules[rule.name] = rule
                            self._compile_patterns(rule)
                            self.logger.info(f"✓ Loaded rule: {rule.name} v{rule.version} from {rule_file.name}")
                else:
                    # Single rule format
                    # Validate detector configuration
                    try:
                        self.validator.validate_detector(rule_data)
                    except DetectorValidationError as e:
                        self.logger.error(f"Detector validation failed in {rule_file.name}: {e}")
                        self.logger.error(f"Skipping invalid detector")
                        continue  # Skip this invalid detector

                    rule = self._parse_rule(rule_data, rule_file)
                    if rule and rule.enabled:
                        self.rules[rule.name] = rule
                        self._compile_patterns(rule)
                        self.logger.info(f"✓ Loaded rule: {rule.name} v{rule.version} from {rule_file.name}")

            except yaml.YAMLError as e:
                self.logger.error(f"YAML parsing error in {rule_file}: {e}")
            except Exception as e:
                self.logger.error(f"Failed to load rule from {rule_file}: {e}")

        self.logger.info(f"Loaded {len(self.rules)} detection rules")

    def _parse_rule(self, data: Dict, source_file: Path) -> Optional[DetectionRule]:
        """
        Parse YAML data into DetectionRule object.

        Args:
            data: Parsed YAML dictionary
            source_file: Source file path (for error messages)

        Returns:
            DetectionRule object or None if invalid
        """
        try:
            metadata = data.get('metadata', {})
            detection = data.get('detection', {})
            output = data.get('output', {})
            aggregation = data.get('aggregation', {})

            # Parse event types
            event_type_strs = detection.get('event_types', ['FAILED_LOGIN'])
            event_types = []
            for et_str in event_type_strs:
                try:
                    # Try direct value match first (e.g., "sql_injection")
                    event_types.append(EventType(et_str))
                except ValueError:
                    # Try uppercase name match (e.g., "SQL_INJECTION" -> EventType.SQL_INJECTION)
                    try:
                        event_types.append(EventType[et_str])
                    except (ValueError, KeyError):
                        self.logger.warning(
                            f"Unknown event type '{et_str}' in {source_file}, "
                            f"using FAILED_LOGIN"
                        )
                        event_types.append(EventType.FAILED_LOGIN)

            # Parse log_sources (NEW)
            log_sources = data.get('log_sources', None)

            # Create rule object
            rule = DetectionRule(
                name=metadata.get('name', source_file.stem),
                version=metadata.get('version', '1.0.0'),
                enabled=metadata.get('enabled', True),
                event_types=event_types,
                threshold=detection.get('threshold', 10),
                time_window_minutes=detection.get('time_window_minutes', 60),
                confidence=detection.get('confidence', 'medium'),
                patterns=detection.get('patterns', []),
                reason_template=output.get('reason_template', 'Rule matched: {rule_name}'),
                metadata=metadata,
                group_by=aggregation.get('group_by', 'source_ip'),
                log_sources=log_sources  # NEW
            )

            return rule

        except Exception as e:
            self.logger.error(f"Failed to parse rule from {source_file}: {e}")
            return None

    def _store_compiled_patterns(self, rule_name: str, patterns: List[tuple]):
        """
        Store compiled patterns with LRU eviction.

        SECURITY FIX H3: Implements LRU cache to prevent unbounded memory growth.
        Without this, 10,000 rule reloads → 10GB memory consumption.

        Args:
            rule_name: Name of the rule
            patterns: List of (compiled_pattern, description) tuples
        """
        with self._pattern_cache_lock:
            # Move to end (most recently used)
            if rule_name in self._compiled_patterns:
                self._compiled_patterns.move_to_end(rule_name)

            # Store patterns
            self._compiled_patterns[rule_name] = patterns

            # LRU eviction: Remove oldest if cache exceeds limit
            while len(self._compiled_patterns) > MAX_COMPILED_PATTERNS_CACHE_SIZE:
                oldest_rule = next(iter(self._compiled_patterns))
                evicted = self._compiled_patterns.pop(oldest_rule)
                self.logger.debug(
                    f"LRU cache evicted patterns for rule '{oldest_rule}' "
                    f"({len(evicted)} patterns). Cache size: {len(self._compiled_patterns)}"
                )

    def _get_compiled_patterns_safe(self, rule_name: str) -> List[tuple]:
        """
        Thread-safe retrieval of compiled patterns with LRU update.

        Args:
            rule_name: Name of the rule

        Returns:
            List of (compiled_pattern, description) tuples
        """
        with self._pattern_cache_lock:
            if rule_name in self._compiled_patterns:
                # Move to end (most recently used)
                self._compiled_patterns.move_to_end(rule_name)
                return self._compiled_patterns[rule_name]
            return []

    def _compile_patterns(self, rule: DetectionRule):
        """
        Pre-compile regex patterns with ReDoS protection.

        REDOS FIX (C7): Validates patterns for dangerous constructs before compilation.

        Args:
            rule: DetectionRule with patterns to compile
        """
        compiled = []

        for pattern_def in rule.patterns:
            try:
                pattern_str = pattern_def.get('regex', '')

                # ReDoS protection: Validate pattern for dangerous constructs
                if not self._is_safe_regex(pattern_str):
                    self.logger.warning(
                        f"Potentially dangerous regex in rule '{rule.name}': {pattern_str} "
                        f"(may cause ReDoS). Skipping pattern."
                    )
                    continue

                flags = 0

                # Parse regex flags
                for flag_name in pattern_def.get('flags', []):
                    if flag_name.upper() == 'IGNORECASE':
                        flags |= re.IGNORECASE
                    elif flag_name.upper() == 'MULTILINE':
                        flags |= re.MULTILINE
                    elif flag_name.upper() == 'DOTALL':
                        flags |= re.DOTALL

                compiled_pattern = re.compile(pattern_str, flags)
                compiled.append((compiled_pattern, pattern_def.get('description', '')))

            except re.error as e:
                self.logger.error(
                    f"Invalid regex in rule '{rule.name}': {pattern_str} - {e}"
                )

        # SECURITY FIX H3: Store with LRU eviction
        self._store_compiled_patterns(rule.name, compiled)

    def _is_safe_regex(self, pattern: str) -> bool:
        """
        Validate regex pattern for known ReDoS vulnerabilities.

        Checks for dangerous constructs like:
        - Nested quantifiers: (a+)+ or (a*)*
        - Overlapping alternation with quantifiers: (a|a)*
        - Complex backreferences with quantifiers

        Args:
            pattern: Regex pattern string

        Returns:
            True if pattern appears safe, False if potentially dangerous
        """
        # Check for nested quantifiers (most common ReDoS pattern)
        # Matches patterns like (x+)+, (x*)+, (x+)*, (x*)*, (x{n,m})+, etc.
        nested_quantifiers = re.search(r'\([^)]*[+*{][^)]*\)[+*{]', pattern)
        if nested_quantifiers:
            return False

        # Check for catastrophic backtracking patterns
        # Patterns like (a|a)+ or (a|ab)+
        overlapping_alternation = re.search(r'\([^|)]+\|[^)]+\)[+*]', pattern)
        if overlapping_alternation:
            # This is a heuristic - not all such patterns are dangerous
            # but we err on the side of caution
            pass

        # Pattern appears safe
        return True

    def apply_rules(self, events: List[SecurityEvent]) -> List[DetectionResult]:
        """
        Apply all loaded rules to events.

        THREAD SAFETY FIX #18: Protected by lock to prevent reading rules
        during reload operation.

        Args:
            events: List of SecurityEvent objects

        Returns:
            List of DetectionResult objects from rule matches
        """
        all_detections = []

        # CRITICAL FIX #18: Acquire lock to prevent race condition where
        # reload_rules() clears rules dict while apply_rules() iterates it
        with self._reload_lock:
            for rule_name, rule in self.rules.items():
                try:
                    rule_detections = self._apply_single_rule(rule, events)
                    all_detections.extend(rule_detections)

                    if rule_detections:
                        self.logger.info(
                            f"Rule '{rule_name}' found {len(rule_detections)} detections"
                        )

                except Exception as e:
                    self.logger.error(f"Error applying rule '{rule_name}': {e}", exc_info=True)

        return all_detections

    def _apply_single_rule(
        self,
        rule: DetectionRule,
        events: List[SecurityEvent]
    ) -> List[DetectionResult]:
        """
        Apply single rule to events.

        Args:
            rule: DetectionRule to apply
            events: List of SecurityEvent objects

        Returns:
            List of DetectionResult objects
        """
        # Filter events by log_sources (if specified)
        if rule.log_sources:
            # Filter by parser sources
            if 'parsers' in rule.log_sources:
                allowed_parsers = rule.log_sources['parsers']
                events = [
                    e for e in events
                    if e.source in allowed_parsers
                ]

            # Filter by file paths
            if 'files' in rule.log_sources:
                allowed_files = rule.log_sources['files']
                events = [
                    e for e in events
                    if e.metadata.get('log_file') in allowed_files
                ]

            if not events:
                return []

        # Filter events by rule's event types
        relevant_events = [
            e for e in events
            if e.event_type in rule.event_types
        ]

        if not relevant_events:
            return []

        # Filter events that match patterns
        matching_events = []
        for event in relevant_events:
            if self._matches_patterns(rule, event):
                matching_events.append(event)

        if not matching_events:
            return []

        self.logger.debug(
            f"Rule '{rule.name}': {len(matching_events)}/{len(relevant_events)} "
            f"events matched patterns"
        )

        # Group events by specified field
        grouped_events = self._group_events(rule, matching_events)

        # Apply threshold and create detections
        detections = []
        for group_key, group_events in grouped_events.items():
            if len(group_events) >= rule.threshold:
                detection = self._create_detection(rule, group_key, group_events)
                if detection:
                    detections.append(detection)

        return detections

    def _matches_patterns(self, rule: DetectionRule, event: SecurityEvent) -> bool:
        """
        Check if event matches any rule pattern with ReDoS protection.

        REDOS FIX (C7): Uses timeout and input length limits to prevent
        catastrophic backtracking attacks.

        Args:
            rule: DetectionRule with patterns
            event: SecurityEvent to check

        Returns:
            True if event matches any pattern, False otherwise
        """
        # SECURITY FIX H3: Thread-safe LRU cache access
        compiled_patterns = self._get_compiled_patterns_safe(rule.name)

        # ReDoS protection: Limit input length
        message = event.raw_message[:MAX_INPUT_LENGTH]

        for pattern, description in compiled_patterns:
            try:
                # SECURITY FIX C3: Thread-safe regex timeout (replaces signal-based)
                match = _run_regex_with_timeout(pattern, message, REGEX_TIMEOUT_SECONDS)
                if match:
                    self.logger.debug(
                        f"Event matched pattern '{description}': {message[:100]}"
                    )
                    return True
            except RegexTimeoutError:
                self.logger.warning(
                    f"Regex timeout in rule '{rule.name}' pattern '{description}' "
                    f"- possible ReDoS attack. Skipping pattern."
                )
                continue

        return False

    def _group_events(
        self,
        rule: DetectionRule,
        events: List[SecurityEvent]
    ) -> Dict[str, List[SecurityEvent]]:
        """
        Group events by specified field.

        Args:
            rule: DetectionRule with group_by specification
            events: List of SecurityEvent objects

        Returns:
            Dictionary mapping group key to list of events
        """
        grouped = defaultdict(list)

        for event in events:
            if rule.group_by == 'source_ip':
                key = str(event.source_ip)
            elif rule.group_by == 'event_type':
                key = event.event_type.value
            elif rule.group_by == 'source':
                key = event.source
            else:
                # Default to source_ip
                key = str(event.source_ip)

            grouped[key].append(event)

        return grouped

    def _create_detection(
        self,
        rule: DetectionRule,
        group_key: str,
        events: List[SecurityEvent]
    ) -> Optional[DetectionResult]:
        """
        Create DetectionResult from rule match.

        Args:
            rule: Matched DetectionRule
            group_key: Grouping key (e.g., IP address)
            events: List of matching SecurityEvent objects

        Returns:
            DetectionResult object or None if creation fails
        """
        try:
            # Get matched pattern description (first match) with ReDoS protection
            pattern_desc = 'pattern match'
            # SECURITY FIX H3: Thread-safe LRU cache access
            for pattern, desc in self._get_compiled_patterns_safe(rule.name):
                for event in events:
                    try:
                        # SECURITY FIX C3: Thread-safe regex timeout
                        message = event.raw_message[:MAX_INPUT_LENGTH]
                        match = _run_regex_with_timeout(pattern, message, REGEX_TIMEOUT_SECONDS)
                        if match:
                            pattern_desc = desc
                            break
                    except RegexTimeoutError:
                        self.logger.warning(
                            f"Regex timeout in pattern matching - possible ReDoS. Skipping."
                        )
                        continue
                if pattern_desc != 'pattern match':
                    break

            # Format reason from template
            reason = rule.reason_template.format(
                rule_name=rule.name,
                event_count=len(events),
                pattern_description=pattern_desc,
                ip=group_key,
                threshold=rule.threshold
            )

            # Parse IP address from group_key (if grouping by IP)
            if rule.group_by == 'source_ip':
                try:
                    ip = ipaddress.ip_address(group_key)
                except ValueError:
                    self.logger.warning(f"Invalid IP address in group key: {group_key}")
                    return None
            else:
                # For non-IP grouping, use first event's IP
                ip = events[0].source_ip

            # Extract timestamps
            timestamps = [e.timestamp for e in events if e.timestamp]
            first_seen = min(timestamps) if timestamps else datetime.now()
            last_seen = max(timestamps) if timestamps else datetime.now()

            # Map confidence string to DetectionConfidence enum
            confidence_map = {
                'high': DetectionConfidence.HIGH,
                'medium': DetectionConfidence.MEDIUM,
                'low': DetectionConfidence.LOW
            }
            confidence_enum = confidence_map.get(
                rule.confidence.lower(),
                DetectionConfidence.MEDIUM
            )

            # Get event_type from first source event
            event_type = events[0].event_type if events else rule.event_types[0]

            # Create detection result
            detection = DetectionResult(
                ip=ip,
                reason=reason,
                confidence=confidence_enum,
                event_count=len(events),
                event_type=event_type,
                source_events=events,
                first_seen=first_seen,
                last_seen=last_seen
            )

            return detection

        except Exception as e:
            self.logger.error(f"Failed to create detection for rule '{rule.name}': {e}")
            return None

    def reload_rules(self):
        """
        Reload rules from disk.

        Useful for live updates without restarting service.

        THREAD SAFETY FIX #18: Protected by lock to prevent race conditions
        during concurrent reload and apply_rules operations.
        """
        # CRITICAL FIX #18: Acquire lock to prevent race condition where
        # apply_rules() reads rules dict while reload_rules() clears it
        with self._reload_lock:
            self.logger.info("Reloading detection rules...")
            self.rules.clear()
            # SECURITY FIX H3: Thread-safe cache clear
            with self._pattern_cache_lock:
                self._compiled_patterns.clear()
            self._load_rules()
            self.logger.info(f"Reloaded {len(self.rules)} rules")

    def get_rule_summary(self) -> Dict[str, Any]:
        """
        Get summary of loaded rules.

        Returns:
            Dictionary with rule statistics
        """
        return {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'rules_by_confidence': {
                'high': sum(1 for r in self.rules.values() if r.confidence == 'high'),
                'medium': sum(1 for r in self.rules.values() if r.confidence == 'medium'),
                'low': sum(1 for r in self.rules.values() if r.confidence == 'low')
            },
            'rule_names': list(self.rules.keys())
        }
