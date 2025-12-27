import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

AI_CONFIG_PATH = Path.home() / ".ctf_tools_ai.json"
SUPPORTED_PROVIDERS = ["openai", "anthropic", "qianfan", "qwen", "ollama", "deepseek"]

ENV_MAPPING: Dict[str, Dict[str, str]] = {
    "openai": {
        "api_key": "OPENAI_API_KEY",
        "base_url": "OPENAI_BASE_URL",
        "endpoint": "OPENAI_ENDPOINT",
        "model": "OPENAI_MODEL",
    },
    "anthropic": {
        "api_key": "ANTHROPIC_API_KEY",
        "base_url": "ANTHROPIC_BASE_URL",
        "endpoint": "ANTHROPIC_ENDPOINT",
        "model": "ANTHROPIC_MODEL",
    },
    "qianfan": {
        "api_key": "QIANFAN_API_KEY",
        "base_url": "QIANFAN_BASE_URL",
        "endpoint": "QIANFAN_ENDPOINT",
        "model": "QIANFAN_MODEL",
    },
    "qwen": {
        "api_key": "DASHSCOPE_API_KEY",
        "base_url": "QWEN_BASE_URL",
        "endpoint": "QWEN_ENDPOINT",
        "model": "QWEN_MODEL",
    },
    "ollama": {
        "api_key": "OLLAMA_API_KEY",
        "base_url": "OLLAMA_BASE_URL",
        "endpoint": "OLLAMA_ENDPOINT",
        "model": "OLLAMA_MODEL",
    },
    "deepseek": {
        "api_key": "DEEPSEEK_API_KEY",
        "base_url": "DEEPSEEK_BASE_URL",
        "endpoint": "DEEPSEEK_ENDPOINT",
        "model": "DEEPSEEK_MODEL",
    },
}


@dataclass
class ProviderConfig:
    api_key: str = ""
    base_url: str = ""
    endpoint: str = ""
    model: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "endpoint": self.endpoint,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "ProviderConfig":
        return cls(
            api_key=data.get("api_key", "") or "",
            base_url=data.get("base_url", "") or "",
            endpoint=data.get("endpoint", "") or "",
            model=data.get("model", "") or "",
        )


@dataclass
class AIConfig:
    provider: str = "openai"
    providers: Dict[str, ProviderConfig] = field(
        default_factory=lambda: {name: ProviderConfig() for name in SUPPORTED_PROVIDERS}
    )

    def to_dict(self) -> Dict[str, object]:
        return {
            "provider": self.provider,
            "providers": {name: cfg.to_dict() for name, cfg in self.providers.items()},
        }


def mask_secret(value: str) -> str:
    """Mask sensitive value for display without leaking full secret."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}***{value[-2:]}"


def _merge_env(provider: str, cfg: ProviderConfig) -> ProviderConfig:
    mapping = ENV_MAPPING.get(provider, {})
    for field_name, env_var in mapping.items():
        env_val = os.getenv(env_var, "")
        if env_val and not getattr(cfg, field_name):
            setattr(cfg, field_name, env_val)
    return cfg


def load_ai_config(path: Path = AI_CONFIG_PATH) -> AIConfig:
    config = AIConfig()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            config.provider = data.get("provider", config.provider)
            providers = data.get("providers", {})
            for name in SUPPORTED_PROVIDERS:
                if name in providers:
                    config.providers[name] = ProviderConfig.from_dict(providers.get(name, {}))
        except Exception:
            # Fall back to defaults/env if file malformed.
            pass
    for name in SUPPORTED_PROVIDERS:
        cfg = config.providers.get(name, ProviderConfig())
        config.providers[name] = _merge_env(name, cfg)
    if config.provider not in SUPPORTED_PROVIDERS:
        config.provider = SUPPORTED_PROVIDERS[0]
    return config


def save_ai_config(config: AIConfig, path: Path = AI_CONFIG_PATH) -> None:
    payload = config.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        # Best-effort; ignore on platforms that don't support chmod.
        pass


def resolve_provider_config(
    config: Optional[AIConfig] = None, provider: Optional[str] = None
) -> ProviderConfig:
    cfg = config or load_ai_config()
    target = provider or cfg.provider
    if target not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {target}")
    # Ensure env variables are merged at call time.
    provider_cfg = cfg.providers.get(target, ProviderConfig())
    return _merge_env(target, provider_cfg)


def active_provider(config: Optional[AIConfig] = None) -> str:
    cfg = config or load_ai_config()
    if cfg.provider not in SUPPORTED_PROVIDERS:
        return SUPPORTED_PROVIDERS[0]
    return cfg.provider
