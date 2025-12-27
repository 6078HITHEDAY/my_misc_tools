import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .ai_client import AIError, call_ai_chat
from .stego_tools import detect_zip_pseudo_encryption
from .stego_extra import list_png_chunks, extract_exif
from .image_stego import lsb_extract, decode_qr, split_gif_frames
from .auto_decoder import auto_decode

STRUCTURED_REQUIREMENTS = (
    "请返回 JSON 对象，包含以下键: "
    "status(字符串), type(字符串), steps(字符串数组), params(对象), result(字符串), reasoning(字符串)，"
    "可选 extra(对象)。不要输出除 JSON 之外的内容。"
)


def _make_messages(task: str, user_content: str) -> List[Dict[str, str]]:
    system = (
        "你是 CTF 解码助手，负责识别编码/密码/隐写并给出明确步骤。"
        "保持回答紧凑，仅输出 JSON，字段含义："
        "status=success/fail/pending，type=判定的类型或算法，steps=解码/分析步骤列表，"
        "params=关键参数（如密钥/偏移/映射），result=最终明文或结论，reasoning=简要依据，"
        "extra 可包含递归建议或可选策略。"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": f"任务: {task}\n{STRUCTURED_REQUIREMENTS}\n输入:\n{user_content}"},
    ]


def _summarize_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return f"文件不存在: {path}"
    lines = [f"文件: {p.name} ({p.suffix}), 大小 {p.stat().st_size} bytes"]
    suffix = p.suffix.lower()
    try:
        if suffix in [".png", ".jpg", ".jpeg", ".bmp", ".gif"]:
            qr = ""
            try:
                qr = decode_qr(path)
            except Exception:
                qr = ""
            try:
                lsb = lsb_extract(path, bits=1, channels="R", max_bytes=16)
                lsb_hex = lsb.hex() if lsb else ""
            except Exception:
                lsb_hex = ""
            try:
                exif = extract_exif(path)
                exif_count = len(exif) if exif else 0
            except Exception:
                exif_count = 0
            if suffix == ".png":
                try:
                    chunks = list_png_chunks(path)
                except Exception:
                    chunks = []
                lines.append(f"PNG chunks: {chunks[:8]}")
            if suffix == ".gif":
                try:
                    frames = split_gif_frames(path)
                    lines.append(f"GIF 帧数: {len(frames)}")
                except Exception:
                    pass
            if qr:
                lines.append(f"QR 解码: {qr}")
            if lsb_hex:
                lines.append(f"LSB hex 预览: {lsb_hex}")
            if exif_count:
                lines.append(f"EXIF 项数: {exif_count}")
        if suffix in [".zip", ".rar", ".7z", ".7zip"]:
            try:
                findings = detect_zip_pseudo_encryption(path)
                lines.append(f"ZIP 伪加密: {findings}")
            except Exception:
                pass
    except Exception:
        pass
    return "\n".join(lines)


def ai_assist_cipher(
    text: str,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, object]:
    local = _local_cipher_probe(text)
    if local:
        return local
    messages = _make_messages("编码/经典密码识别与解码", f"密文:\n{text}\n{STRUCTURED_REQUIREMENTS}")
    raw = call_ai_chat(messages, provider=provider, model=model, override_api_key=api_key)
    return _parse_ai_json(raw)


def ai_assist_crypto(
    text: str,
    hint: str = "",
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, object]:
    hash_hint = _detect_common_hash(text)
    if hash_hint:
        return hash_hint
    body = f"哈希/加密或爆破任务输入:\n{text}"
    if hint:
        body += f"\n额外提示: {hint}"
    messages = _make_messages("哈希/对称加密/爆破策略建议", body)
    raw = call_ai_chat(messages, provider=provider, model=model, override_api_key=api_key)
    return _parse_ai_json(raw)


def ai_assist_stego(
    path: str,
    extra: str = "",
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, object]:
    summary = _summarize_file(path)
    body = f"{summary}"
    if extra:
        body += f"\n补充说明: {extra}"
    messages = _make_messages("隐写/文件分析建议", body)
    raw = call_ai_chat(messages, provider=provider, model=model, override_api_key=api_key)
    return _parse_ai_json(raw)


def _parse_ai_json(raw: str) -> Dict[str, object]:
    try:
        return json.loads(raw)
    except Exception:
        # Fallback wrap to keep CLI usable even if provider返回非 JSON.
        return {
            "status": "unknown",
            "type": "unparsed",
            "steps": [],
            "params": {},
            "result": "",
            "reasoning": f"AI 输出无法解析为 JSON，原文: {raw}",
        }


def render_ai_result(data: Dict[str, object]) -> str:
    """Pretty print structured AI result for CLI/GUI."""
    lines = [
        f"状态: {data.get('status', '')}",
        f"识别类型: {data.get('type', '')}",
        f"核心参数: {json.dumps(data.get('params', {}), ensure_ascii=False)}",
        f"结果: {data.get('result', '')}",
        f"推理: {data.get('reasoning', '')}",
    ]
    steps = data.get("steps", [])
    if steps:
        lines.append("步骤:")
        for idx, step in enumerate(steps, 1):
            lines.append(f"  {idx}. {step}")
    extra = data.get("extra")
    if extra:
        lines.append(f"额外建议: {json.dumps(extra, ensure_ascii=False)}")
    return "\n".join(lines)


def _local_cipher_probe(text: str) -> Optional[Dict[str, object]]:
    candidates = auto_decode(text)
    if not candidates:
        return None
    steps = [f"{name}: {result}" for name, result in candidates]
    return {
        "status": "success-local",
        "type": "auto-detect",
        "steps": steps,
        "params": {},
        "result": candidates[0][1],
        "reasoning": "本地特征已识别，未调用 AI。",
    }


def _detect_common_hash(text: str) -> Optional[Dict[str, object]]:
    if not text:
        return None
    t = text.strip().lower()
    if all(c in "0123456789abcdef" for c in t):
        mapping = {32: "md5", 40: "sha1", 64: "sha256"}
        algo = mapping.get(len(t))
        if algo:
            return {
                "status": "hint",
                "type": algo,
                "steps": [f"疑似 {algo}，可用 hashbrute --algo {algo} 爆破"],
                "params": {},
                "result": "",
                "reasoning": "依据长度与十六进制字符匹配常见哈希。",
            }
    return None
