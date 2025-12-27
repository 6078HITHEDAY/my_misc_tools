from typing import Any, Callable, Dict, Optional


class ToolPlugin:
    """
    Simple plugin interface to register modular operations.
    """

    name: str = "plugin"
    description: str = ""

    def run(self, **kwargs: Any) -> Any:  # pragma: no cover - interface only
        raise NotImplementedError


_PLUGINS: Dict[str, ToolPlugin] = {}


def register_plugin(factory: Callable[[], ToolPlugin]) -> ToolPlugin:
    plugin = factory()
    _PLUGINS[plugin.name] = plugin
    return plugin


def get_plugin(name: str) -> Optional[ToolPlugin]:
    return _PLUGINS.get(name)


def list_plugins() -> Dict[str, str]:
    return {name: plugin.description for name, plugin in _PLUGINS.items()}
