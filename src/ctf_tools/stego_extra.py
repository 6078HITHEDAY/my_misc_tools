from pathlib import Path
from typing import Dict, List

from PIL import Image


def extract_exif(image_path: str) -> Dict:
    """
    Return EXIF metadata as a dict if available.
    """
    img = Image.open(image_path)
    exif_data = img.getexif()
    if not exif_data:
        return {}
    return {Image.ExifTags.TAGS.get(tag, tag): exif_data.get(tag) for tag in exif_data}


def list_png_chunks(png_path: str) -> List[str]:
    """
    List PNG chunk types in order.
    """
    with open(png_path, "rb") as fh:
        data = fh.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Not a PNG file.")
    idx = 8
    chunks: List[str] = []
    while idx + 8 <= len(data):
        length = int.from_bytes(data[idx : idx + 4], "big")
        chunk_type = data[idx + 4 : idx + 8].decode("ascii", errors="ignore")
        chunks.append(chunk_type)
        idx += 12 + length  # length + type + crc + length field
        if idx > len(data):
            break
    return chunks
