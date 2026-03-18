"""Plugin system for RETRO-Ollama."""

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from src.logging_config import get_logger
from src.exceptions import PTAIException

logger = get_logger("ptai.plugins")

PLUGINS_DIR = Path("plugins")


class PluginError(PTAIException):
    """Plugin error."""
    pass


class Plugin:
    """Base plugin class."""

    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    
    def __init__(self):
        self.enabled = True
        self._commands: Dict[str, Callable] = {}
        self._hooks: Dict[str, List[Callable]] = {}

    def register_command(self, name: str, func: Callable) -> None:
        """Register a command."""
        self._commands[name] = func

    def register_hook(self, name: str, func: Callable) -> None:
        """Register a hook."""
        if name not in self._hooks:
            self._hooks[name] = []
        self._hooks[name].append(func)

    def get_commands(self) -> Dict[str, Callable]:
        """Get registered commands."""
        return self._commands

    def get_hooks(self) -> Dict[str, List[Callable]]:
        """Get registered hooks."""
        return self._hooks

    def on_load(self) -> None:
        """Called when plugin is loaded."""
        logger.info(f"Plugin {self.name} loaded")

    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        logger.info(f"Plugin {self.name} unloaded")

    def on_enable(self) -> None:
        """Called when plugin is enabled."""
        self.enabled = True

    def on_disable(self) -> None:
        """Called when plugin is disabled."""
        self.enabled = False


class PluginMetadata:
    """Plugin metadata."""

    def __init__(
        self,
        name: str,
        version: str,
        description: str = "",
        author: str = "",
        dependencies: List[str] = None,
    ):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.dependencies = dependencies or []


class PluginManager:
    """Manages plugins."""

    def __init__(self, plugins_dir: Optional[Path] = None):
        self.plugins_dir = plugins_dir or PLUGINS_DIR
        self._plugins: Dict[str, Plugin] = {}
        self._commands: Dict[str, Callable] = {}
        self._hooks: Dict[str, List[Callable]] = {}

    def discover_plugins(self) -> List[PluginMetadata]:
        """Discover available plugins."""
        if not self.plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return []

        plugins = []
        for file in self.plugins_dir.glob("*.py"):
            if file.name.startswith("_"):
                continue
            
            try:
                spec = importlib.util.spec_from_file_location(file.stem, file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[file.stem] = module
                    spec.loader.exec_module(module)
                    
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, Plugin) and obj is not Plugin:
                            plugin = obj()
                            plugins.append(PluginMetadata(
                                name=plugin.name or file.stem,
                                version=plugin.version,
                                description=plugin.description,
                                author=plugin.author,
                            ))
            except Exception as e:
                logger.error(f"Failed to load plugin {file}: {e}")

        return plugins

    def load_plugin(self, plugin_name: str) -> Plugin:
        """Load a plugin by name."""
        if plugin_name in self._plugins:
            logger.warning(f"Plugin {plugin_name} already loaded")
            return self._plugins[plugin_name]

        plugin_file = self.plugins_dir / f"{plugin_name}.py"
        if not plugin_file.exists():
            raise PluginError(f"Plugin file not found: {plugin_name}.py")

        try:
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[plugin_name] = module
                spec.loader.exec_module(module)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, Plugin) and obj is not Plugin:
                        plugin = obj()
                        self._plugins[plugin_name] = plugin
                        plugin.on_load()
                        
                        for cmd_name, cmd_func in plugin.get_commands().items():
                            self._commands[f"{plugin_name}.{cmd_name}"] = cmd_func
                        
                        logger.info(f"Loaded plugin: {plugin_name}")
                        return plugin
        except Exception as e:
            raise PluginError(f"Failed to load plugin {plugin_name}: {e}")

        raise PluginError(f"No plugin class found in {plugin_name}.py")

    def unload_plugin(self, plugin_name: str) -> None:
        """Unload a plugin."""
        if plugin_name not in self._plugins:
            logger.warning(f"Plugin {plugin_name} not loaded")
            return

        plugin = self._plugins[plugin_name]
        plugin.on_unload()

        commands_to_remove = [k for k in self._commands if k.startswith(f"{plugin_name}.")]
        for cmd in commands_to_remove:
            del self._commands[cmd]

        del self._plugins[plugin_name]
        logger.info(f"Unloaded plugin: {plugin_name}")

    def enable_plugin(self, plugin_name: str) -> None:
        """Enable a plugin."""
        if plugin_name not in self._plugins:
            raise PluginError(f"Plugin not loaded: {plugin_name}")
        
        self._plugins[plugin_name].on_enable()
        logger.info(f"Enabled plugin: {plugin_name}")

    def disable_plugin(self, plugin_name: str) -> None:
        """Disable a plugin."""
        if plugin_name not in self._plugins:
            raise PluginError(f"Plugin not loaded: {plugin_name}")
        
        self._plugins[plugin_name].on_disable()
        logger.info(f"Disabled plugin: {plugin_name}")

    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """Get a loaded plugin."""
        return self._plugins.get(plugin_name)

    def get_all_plugins(self) -> Dict[str, Plugin]:
        """Get all loaded plugins."""
        return self._plugins.copy()

    def get_commands(self) -> Dict[str, Callable]:
        """Get all registered commands."""
        return self._commands.copy()

    def execute_command(self, command: str, *args: Any, **kwargs: Any) -> Any:
        """Execute a plugin command."""
        if command not in self._commands:
            raise PluginError(f"Command not found: {command}")
        
        return self._commands[command](*args, **kwargs)

    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """Register a hook callback."""
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(callback)

    def trigger_hook(self, hook_name: str, *args: Any, **kwargs: Any) -> List[Any]:
        """Trigger all callbacks for a hook."""
        results = []
        if hook_name in self._hooks:
            for callback in self._hooks[hook_name]:
                try:
                    result = callback(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Hook {hook_name} callback failed: {e}")
        return results


plugin_manager = PluginManager()


def register_plugin_command(plugin_name: str, command_name: str) -> Callable:
    """Decorator to register a plugin command."""
    def decorator(func: Callable) -> Callable:
        if plugin_name in plugin_manager._plugins:
            plugin_manager._plugins[plugin_name].register_command(command_name, func)
        return func
    return decorator


def register_plugin_hook(plugin_name: str, hook_name: str) -> Callable:
    """Decorator to register a plugin hook."""
    def decorator(func: Callable) -> Callable:
        if plugin_name in plugin_manager._plugins:
            plugin_manager._plugins[plugin_name].register_hook(hook_name, func)
        return func
    return decorator


__all__ = [
    "Plugin",
    "PluginMetadata",
    "PluginManager",
    "PluginError",
    "plugin_manager",
    "register_plugin_command",
    "register_plugin_hook",
]
