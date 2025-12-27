import json
import time
from typing import Dict, List, Optional, Tuple

import requests

from .ai_config import ProviderConfig, active_provider, resolve_provider_config


class AIError(RuntimeError):
    """Raised when the AI provider call fails or is misconfigured."""


def _build_openai_payload(cfg: ProviderConfig, messages: List[Dict[str, str]], model: Optional[str], temperature: float, max_tokens: int) -> Tuple[str, Dict[str, str], Dict[str, object]]:
    base_url = cfg.base_url or "https://api.openai.com/v1"
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload: Dict[str, object] = {
        "model": cfg.model or model or "gpt-3.5-turbo",
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {cfg.api_key}"}
    return url, headers, payload


def _build_anthropic_payload(cfg: ProviderConfig, messages: List[Dict[str, str]], model: Optional[str], temperature: float, max_tokens: int) -> Tuple[str, Dict[str, str], Dict[str, object]]:
    base_url = cfg.base_url or "https://api.anthropic.com"
    url = f"{base_url.rstrip('/')}/v1/messages"
    payload: Dict[str, object] = {
        "model": cfg.model or model or "claude-3-sonnet-20240229",
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {
        "x-api-key": cfg.api_key,
        "anthropic-version": "2023-06-01",
    }
    return url, headers, payload


def _build_qianfan_payload(cfg: ProviderConfig, messages: List[Dict[str, str]], model: Optional[str], temperature: float, max_tokens: int) -> Tuple[str, Dict[str, str], Dict[str, object]]:
    base_url = cfg.base_url or "https://qianfan.baidubce.com"
    endpoint = cfg.endpoint or "/v2/chat/completions"
    url = f"{base_url.rstrip('/')}{endpoint}"
    payload: Dict[str, object] = {
        "model": cfg.model or model or "ERNIE-Speed-128K",
        "messages": messages,
        "temperature": temperature,
        "max_output_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
    return url, headers, payload


def _build_qwen_payload(cfg: ProviderConfig, messages: List[Dict[str, str]], model: Optional[str], temperature: float, max_tokens: int) -> Tuple[str, Dict[str, str], Dict[str, object]]:
    base_url = cfg.base_url or "https://dashscope.aliyuncs.com"
    endpoint = cfg.endpoint or "/api/v1/services/aigc/text-generation/generation"
    url = f"{base_url.rstrip('/')}{endpoint}"
    payload: Dict[str, object] = {
        "model": cfg.model or model or "qwen-turbo",
        "input": {"messages": messages},
        "parameters": {"temperature": temperature, "max_tokens": max_tokens},
    }
    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
    return url, headers, payload


def _build_deepseek_payload(cfg: ProviderConfig, messages: List[Dict[str, str]], model: Optional[str], temperature: float, max_tokens: int) -> Tuple[str, Dict[str, str], Dict[str, object]]:
    base_url = cfg.base_url or "https://api.deepseek.com"
    endpoint = cfg.endpoint or "/chat/completions"
    url = f"{base_url.rstrip('/')}{endpoint}"
    payload: Dict[str, object] = {
        "model": cfg.model or model or "deepseek-chat",
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
    return url, headers, payload


def _parse_response(provider: str, data: Dict[str, object]) -> str:
    if provider == "openai":
        choices = data.get("choices") or []
        if choices and isinstance(choices, list):
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if message and isinstance(message, dict):
                return str(message.get("content", "")).strip()
    elif provider == "anthropic":
        content = data.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                return str(first.get("text", "")).strip()
    elif provider == "qianfan":
        # Qianfan may return result or choices depending on gateway compatibility.
        if "result" in data:
            return str(data.get("result", "")).strip()
        choices = data.get("choices") or []
        if choices and isinstance(choices, list):
            msg = choices[0].get("message") if isinstance(choices[0], dict) else None
            if msg and isinstance(msg, dict):
                return str(msg.get("content", "")).strip()
    elif provider == "qwen":
        output = data.get("output")
        if isinstance(output, dict) and "text" in output:
            return str(output.get("text", "")).strip()
        choices = data.get("choices") or []
        if choices and isinstance(choices, list):
            msg = choices[0].get("message") if isinstance(choices[0], dict) else None
            if msg and isinstance(msg, dict):
                return str(msg.get("content", "")).strip()
    elif provider == "deepseek":
        choices = data.get("choices") or []
        if choices and isinstance(choices, list):
            msg = choices[0].get("message") if isinstance(choices[0], dict) else None
            if msg and isinstance(msg, dict):
                return str(msg.get("content", "")).strip()
    # Fallback to entire text payload
    return json.dumps(data, ensure_ascii=False)


_LAST_CALL_TS = 0.0


def call_ai_chat(
    messages: List[Dict[str, str]],
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 512,
    override_api_key: Optional[str] = None,
    timeout: int = 30,
    retries: int = 1,
    min_interval: float = 0.5,
) -> str:
    """
    Send a minimal chat-style request to the configured provider and return response text.
    """
    active = provider or active_provider()
    cfg = resolve_provider_config(provider=active)
    if not cfg.api_key and override_api_key:
        cfg.api_key = override_api_key
    if not cfg.api_key and active not in {"ollama"}:
        raise AIError(f"{active} 未配置 API Key，请先通过 ai-config 或环境变量完成配置。")

    if active == "openai":
        url, headers, payload = _build_openai_payload(cfg, messages, model, temperature, max_tokens)
    elif active == "anthropic":
        url, headers, payload = _build_anthropic_payload(cfg, messages, model, temperature, max_tokens)
    elif active == "qianfan":
        url, headers, payload = _build_qianfan_payload(cfg, messages, model, temperature, max_tokens)
    elif active == "qwen":
        url, headers, payload = _build_qwen_payload(cfg, messages, model, temperature, max_tokens)
    elif active == "ollama":
        base_url = cfg.base_url or "http://localhost:11434"
        endpoint = cfg.endpoint or "/api/chat"
        url = f"{base_url.rstrip('/')}{endpoint}"
        payload = {
            "model": cfg.model or model or "llama3",
            "messages": messages,
            "stream": False,
        }
        headers = {}
    elif active == "deepseek":
        url, headers, payload = _build_deepseek_payload(cfg, messages, model, temperature, max_tokens)
    else:
        raise AIError(f"不支持的服务商: {active}")

    global _LAST_CALL_TS
    if min_interval > 0:
        now = time.monotonic()
        wait = min_interval - (now - _LAST_CALL_TS)
        if wait > 0:
            time.sleep(wait)

    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
            _LAST_CALL_TS = time.monotonic()
        except Exception as exc:  # pragma: no cover - network
            last_exc = exc
            if attempt >= retries:
                raise AIError(f"请求 AI 服务失败: {exc}") from exc
            time.sleep(1.0)
            continue

        if resp.status_code >= 400:
            if attempt < retries and resp.status_code >= 500:
                time.sleep(1.0)
                continue
            raise AIError(f"AI 调用失败 ({resp.status_code}): {resp.text}")

        try:
            data = resp.json()
        except Exception as exc:
            raise AIError(f"解析 AI 响应失败: {exc}") from exc

        return _parse_response(active, data)

    raise AIError(f"AI 调用失败: {last_exc}")
