"""
TribanFT Configuration Synchronization Utility

Automatically syncs new options from config.conf.template to active config.conf
while preserving user settings.

This module ensures users automatically receive new configuration options from
template updates without losing their customized settings.

Author: TribanFT Project
License: GNU GPL v3
"""

import configparser
import logging
from pathlib import Path
from typing import Optional, Tuple
import shutil
from datetime import datetime

logger = logging.getLogger(__name__)


def find_template_file() -> Optional[Path]:
    """
    Locate config.conf.template in the project.

    Searches multiple standard locations where the template might be installed.

    Returns:
        Path to template file if found, None otherwise
    """
    # Try multiple locations
    candidates = [
        Path(__file__).parent.parent / 'config.conf.template',  # From package
        Path('/usr/share/tribanft/config.conf.template'),        # System install
        Path.home() / '.local/share/tribanft/config.conf.template',  # User install
    ]

    for path in candidates:
        if path.exists():
            logger.debug(f"Found template at: {path}")
            return path

    logger.warning("Template file not found in standard locations")
    return None


def sync_config(config_file: Path, template_file: Path,
                backup: bool = True) -> Tuple[int, int]:
    """
    Sync new sections/keys from template to config file.

    This function intelligently merges new configuration options from the
    template into the active config file while preserving all user settings.

    Process:
    1. Backup existing config (if requested)
    2. Load both template and active config
    3. Identify missing sections and keys
    4. Add only NEW sections/keys with template defaults
    5. NEVER overwrite existing user values

    Args:
        config_file: Path to active config.conf
        template_file: Path to config.conf.template
        backup: Whether to backup config before modifying (default: True)

    Returns:
        Tuple of (sections_added, keys_added)

    Security Note:
        - Preserves user settings (never overwrites existing values)
        - Creates timestamped backup before modifications
        - Gracefully handles parse errors
    """
    if not config_file.exists():
        logger.warning(f"Config file not found: {config_file}")
        logger.info(f"Copying template to: {config_file}")
        config_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(template_file, config_file)
        logger.info(f"Created new config from template")
        return (0, 0)

    # Backup original
    if backup:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = config_file.with_suffix(f'.conf.backup-{timestamp}')
        shutil.copy(config_file, backup_path)
        logger.info(f"Backup created: {backup_path}")

    # Load template
    template_parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    try:
        template_parser.read(template_file)
    except Exception as e:
        logger.error(f"Failed to parse template file: {e}")
        return (0, 0)

    # Load active config
    config_parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    try:
        config_parser.read(config_file)
    except Exception as e:
        logger.error(f"Failed to parse config file: {e}")
        return (0, 0)

    sections_added = 0
    keys_added = 0

    # Find new sections
    template_sections = set(template_parser.sections())
    config_sections = set(config_parser.sections())
    new_sections = template_sections - config_sections

    # Add missing sections
    for section in sorted(new_sections):  # Sort for consistent ordering
        logger.info(f"Adding new section: [{section}]")
        config_parser.add_section(section)
        sections_added += 1

        # Add all keys from template for this section
        for key, value in template_parser.items(section):
            config_parser.set(section, key, value)
            keys_added += 1
            logger.debug(f"  + {key} = {value}")

    # Check existing sections for new keys
    for section in sorted(config_sections & template_sections):
        template_keys = set(dict(template_parser.items(section)).keys())
        config_keys = set(dict(config_parser.items(section)).keys())
        new_keys = template_keys - config_keys

        for key in sorted(new_keys):  # Sort for consistent ordering
            value = template_parser.get(section, key)
            config_parser.set(section, key, value)
            keys_added += 1
            logger.info(f"Adding [{section}] {key} = {value}")

    # Write updated config
    if sections_added > 0 or keys_added > 0:
        try:
            with open(config_file, 'w') as f:
                config_parser.write(f)
            logger.warning(f"Config synced: +{sections_added} sections, +{keys_added} keys")
        except Exception as e:
            logger.error(f"Failed to write updated config: {e}")
            return (0, 0)
    else:
        logger.info("Config up-to-date, no changes needed")

    return (sections_added, keys_added)


def auto_sync_on_startup():
    """
    Automatically sync config on service startup.

    Called from config.py before loading configuration.
    Ensures users automatically receive new template options while
    preserving their existing settings.

    This function:
    - Silently succeeds if no config file exists (fresh install)
    - Logs warnings but continues if template not found
    - Creates backup before any modifications
    - Gracefully handles all errors without breaking startup
    """
    # Import here to avoid circular dependency
    from .config import find_config_file

    config_file = find_config_file()
    if not config_file:
        logger.debug("No config file found, skipping auto-sync")
        return

    template_file = find_template_file()
    if not template_file:
        logger.warning("Template file not found, cannot auto-sync")
        logger.info("Config sync skipped - continuing with existing config")
        return

    logger.info(f"Auto-sync: config={config_file}, template={template_file}")

    try:
        sections, keys = sync_config(config_file, template_file, backup=True)
        if sections > 0 or keys > 0:
            logger.warning(
                f"CONFIG AUTO-SYNC: Added {sections} sections, {keys} keys from template"
            )
            logger.info(
                f"Your existing settings were preserved. "
                f"Backup created with timestamp."
            )
    except Exception as e:
        logger.error(f"Auto-sync failed: {e}", exc_info=True)
        logger.warning("Continuing with existing config (sync skipped)")
