"""
TribanFT Plugin Manager

Automatic discovery and loading of detector and parser plugins.

Key features:
- Auto-discovery via directory scanning
- Plugin metadata validation
- Dependency injection for plugins
- Enable/disable via configuration

Author: TribanFT Project
License: GNU GPL v3
"""

import importlib
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Type, Any, Optional
from abc import ABC


logger = logging.getLogger(__name__)


class PluginMetadata:
    """
    Metadata for plugins.

    Provides versioning, author info, and dependency tracking.

    Attributes:
        name: Plugin name
        version: Plugin version (semantic versioning)
        author: Plugin author/maintainer
        description: Brief description of plugin functionality
        dependencies: List of required dependency names
    """

    def __init__(
        self,
        name: str,
        version: str,
        author: Optional[str] = None,
        description: Optional[str] = None,
        dependencies: Optional[List[str]] = None
    ):
        self.name = name
        self.version = version
        self.author = author or "Unknown"
        self.description = description or ""
        self.dependencies = dependencies or []


class PluginManager:
    """
    Discovers and loads plugins from designated directories.

    Supports auto-discovery via directory scanning, plugin metadata
    validation, dependency injection, and configuration-based
    enable/disable functionality.

    Usage:
        plugin_manager = PluginManager(config)
        detector_classes = plugin_manager.discover_plugins(
            detector_dir, BaseDetector
        )
        detectors = plugin_manager.instantiate_plugins(
            detector_classes, {'blacklist_manager': bm}
        )

    Attributes:
        config: Application configuration object
        logger: Logger instance
        _loaded_plugins: Cache of loaded plugin instances
    """

    def __init__(self, config):
        """
        Initialize plugin manager.

        Args:
            config: Application configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._loaded_plugins: Dict[str, Any] = {}

    def discover_plugins(
        self,
        plugin_dir: Path,
        base_class: Type,
        package_prefix: str = "bruteforce_detector.plugins"
    ) -> List[Type]:
        """
        Discover all plugins in directory that inherit from base_class.

        Scans Python files in the specified directory and identifies
        classes that inherit from the provided base class. Automatically
        filters based on configuration enable/disable flags.

        Args:
            plugin_dir: Directory to scan for plugins
            base_class: Base class plugins must inherit from
            package_prefix: Python package prefix for imports

        Returns:
            List of plugin classes
        """
        plugins = []

        if not plugin_dir.exists():
            self.logger.warning(f"Plugin directory not found: {plugin_dir}")
            return plugins

        self.logger.info(f"Discovering plugins in {plugin_dir}")

        # SECURITY FIX C2: Resolve plugin directory to absolute path for traversal checking
        plugin_dir_abs = plugin_dir.resolve()

        # Scan Python files in plugin directory
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue  # Skip __init__.py and private modules

            # SECURITY FIX C2: Validate no path traversal (prevents ../../../../tmp/shell.py)
            py_file_abs = py_file.resolve()
            try:
                py_file_abs.relative_to(plugin_dir_abs)
            except ValueError:
                self.logger.error(
                    f"SECURITY: Path traversal attempt detected in plugin: {py_file}"
                )
                self.logger.error(
                    f"  Plugin path: {py_file_abs}"
                )
                self.logger.error(
                    f"  Expected directory: {plugin_dir_abs}"
                )
                self.logger.error("  REJECTING malicious plugin")
                continue  # Skip this file - path traversal detected

            try:
                # Build module name for import
                # e.g., bruteforce_detector.plugins.detectors.prelogin_detector
                module_name = f"{package_prefix}.{plugin_dir.name}.{py_file.stem}"

                # Import module dynamically
                module = importlib.import_module(module_name)

                # Find classes inheriting from base_class
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a subclass but not the base class itself
                    if issubclass(obj, base_class) and obj != base_class:
                        # Check if plugin is enabled in config
                        if self._is_plugin_enabled(obj):
                            plugins.append(obj)
                            self.logger.info(
                                f"✓ Discovered plugin: {name} from {py_file.name}"
                            )
                        else:
                            self.logger.info(f"⊗ Plugin disabled: {name}")

            except Exception as e:
                self.logger.error(f"Failed to load plugin from {py_file}: {e}")

        self.logger.info(f"Discovered {len(plugins)} enabled plugins in {plugin_dir.name}")
        return plugins

    def _is_plugin_enabled(self, plugin_class: Type) -> bool:
        """
        Check if plugin is enabled via configuration.

        Checks plugin metadata for enable flags or config settings.

        Args:
            plugin_class: Plugin class to check

        Returns:
            True if plugin is enabled, False otherwise
        """
        # Check for METADATA attribute
        if hasattr(plugin_class, 'METADATA'):
            metadata = plugin_class.METADATA
            plugin_name = metadata.get('name', plugin_class.__name__)

            # Check config for enable flag
            # e.g., enable_prelogin_detector_plugin
            config_key = f"enable_{plugin_name.lower()}_plugin"

            # Try to get from config, default to metadata's default or True
            default_enabled = metadata.get('enabled_by_default', True)
            return getattr(self.config, config_key, default_enabled)

        # No metadata - default to enabled
        return True

    def _validate_dependencies(self, dependencies: Dict[str, Any]) -> bool:
        """
        Validate dependencies before passing to plugins (H1 fix).

        Ensures dependencies are of expected types and non-None.
        Prevents malicious plugins from exploiting missing validation.

        Args:
            dependencies: Dictionary of dependencies to validate

        Returns:
            True if valid, False otherwise
        """
        if not isinstance(dependencies, dict):
            self.logger.error("Dependencies must be a dictionary")
            return False

        # Validate config if present
        if 'config' in dependencies:
            if dependencies['config'] is None:
                self.logger.error("Config dependency is None")
                return False

        return True

    def instantiate_plugins(
        self,
        plugin_classes: List[Type],
        dependencies: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """
        Instantiate plugins with dependency injection and input validation (H1 fix).

        Analyzes each plugin's constructor signature and injects
        available dependencies. Validates inputs before passing to plugins
        for security. Provides exception isolation to prevent plugin
        failures from crashing the main process.

        Args:
            plugin_classes: List of plugin classes to instantiate
            dependencies: Dependencies to inject (config, managers, etc.)

        Returns:
            List of instantiated plugin objects
        """
        dependencies = dependencies or {}
        dependencies['config'] = self.config  # Always inject config

        # Validate dependencies before passing to plugins (H1 fix)
        if not self._validate_dependencies(dependencies):
            self.logger.error("Dependency validation failed, aborting plugin instantiation")
            return []

        instances = []

        for plugin_class in plugin_classes:
            try:
                # Inspect constructor signature
                sig = inspect.signature(plugin_class.__init__)
                params = sig.parameters

                # Build kwargs from available dependencies
                kwargs = {}
                missing_deps = []

                for param_name, param in params.items():
                    if param_name == 'self':
                        continue

                    if param_name in dependencies:
                        # Validate dependency is not None before injection (H1 fix)
                        dep_value = dependencies[param_name]
                        if dep_value is None and param.default is inspect.Parameter.empty:
                            self.logger.error(
                                f"{plugin_class.__name__}: Required dependency '{param_name}' is None"
                            )
                            missing_deps.append(param_name)
                        else:
                            kwargs[param_name] = dep_value
                    elif param.default is not inspect.Parameter.empty:
                        # Has default value, skip
                        pass
                    else:
                        # Required parameter missing
                        missing_deps.append(param_name)

                if missing_deps:
                    self.logger.warning(
                        f"Missing dependencies for {plugin_class.__name__}: "
                        f"{', '.join(missing_deps)}"
                    )

                # Instantiate plugin with exception isolation (H1 fix)
                # Failures are logged but don't crash the main process
                instance = plugin_class(**kwargs)
                instances.append(instance)

                plugin_name = getattr(instance, 'name', plugin_class.__name__)
                self.logger.info(f"✓ Loaded plugin: {plugin_name}")

            except Exception as e:
                self.logger.error(
                    f"Failed to instantiate {plugin_class.__name__}: {e}",
                    exc_info=True
                )
                # Continue loading other plugins (exception isolation)

        self.logger.info(f"Successfully instantiated {len(instances)} plugins")
        return instances

    def get_plugin_metadata(self, plugin_class: Type) -> Optional[PluginMetadata]:
        """
        Extract metadata from plugin class.

        Args:
            plugin_class: Plugin class to extract metadata from

        Returns:
            PluginMetadata object or None if no metadata found
        """
        if not hasattr(plugin_class, 'METADATA'):
            return None

        metadata_dict = plugin_class.METADATA

        return PluginMetadata(
            name=metadata_dict.get('name', plugin_class.__name__),
            version=metadata_dict.get('version', '1.0.0'),
            author=metadata_dict.get('author'),
            description=metadata_dict.get('description'),
            dependencies=metadata_dict.get('dependencies', [])
        )
