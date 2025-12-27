import itertools
from pathlib import Path
from typing import List, Optional

from PIL import Image, ImageSequence

try:
    from pyzbar.pyzbar import decode as qr_decode
except Exception:  # pragma: no cover - pyzbar optional
    qr_decode = None


def lsb_extract(image_path: str, bits: int = 1, channels: str = "RGB", max_bytes: Optional[int] = None) -> bytes:
    """
    Extract least significant bits from an image and return raw bytes.
    """
    img = Image.open(image_path).convert("RGB")
    data_bits = []
    channel_indices = [idx for idx, ch in enumerate("RGB") if ch in channels.upper()]

    for pixel in img.getdata():
        for idx in channel_indices:
            byte = pixel[idx]
            for bit_index in range(bits):
                data_bits.append((byte >> bit_index) & 1)
                if max_bytes and len(data_bits) >= max_bytes * 8:
                    return _bits_to_bytes(data_bits)
    return _bits_to_bytes(data_bits)


def _bits_to_bytes(bits: List[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i : i + 8]
        if len(chunk) < 8:
            break
        value = 0
        for bit in reversed(chunk):
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def split_gif_frames(gif_path: str, output_dir: Optional[str] = None) -> List[str]:
    img = Image.open(gif_path)
    out_dir = Path(output_dir) if output_dir else Path(gif_path).with_suffix("") / "frames"
    out_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for idx, frame in enumerate(ImageSequence.Iterator(img)):
        frame_path = out_dir / f"frame_{idx:03d}.png"
        frame.save(frame_path)
        saved.append(str(frame_path))
    return saved


def decode_qr(image_path: str) -> Optional[str]:
    if qr_decode is None:
        raise RuntimeError("pyzbar is not available (zbar library may be missing).")
    img = Image.open(image_path)
    results = qr_decode(img)
    if not results:
        return None
    return results[0].data.decode("utf-8")
