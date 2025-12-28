"""
PyInstaller archive unpacking helpers.

Supports:
- Detecting PyInstaller CArchive via MEI magic.
- Extracting the outer CArchive to a directory (pyd/dll/resources/PYZ-00.pyz).
- Parsing and unpacking PYZ archives (best-effort, supports common layout and
  simple zlib-compressed entries; encrypted PYZ with custom keys may need manual key).
"""

import io
import marshal
import struct
import zlib
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

MEI_MAGIC = b"MEI\014\013\012\013\016"


class PyiError(Exception):
    """Raised for PyInstaller unpack errors."""


def detect_pyinstaller(exe_path: Path) -> Dict[str, int]:
    data = exe_path.read_bytes()
    mpos = data.rfind(MEI_MAGIC)
    if mpos == -1:
        raise PyiError("未检测到 PyInstaller 魔数")
    try:
        magic, pkglen, tocpos, toclen, pyvers = struct.unpack("!8siiii", data[mpos : mpos + 24])
    except struct.error as exc:
        raise PyiError(f"解析 cookie 失败: {exc}") from exc
    return {
        "magic_pos": mpos,
        "pkg_len": pkglen,
        "toc_pos": tocpos,
        "toc_len": toclen,
        "py_ver": pyvers,
        "pkg_start": len(data) - pkglen,
    }


def extract_carchive(exe_path: Path, out_dir: Path) -> Dict[str, int]:
    info = detect_pyinstaller(exe_path)
    data = exe_path.read_bytes()
    pkg = data[info["pkg_start"] :]
    bio = io.BytesIO(pkg)
    bio.seek(info["toc_pos"])
    toc = bio.read(info["toc_len"])
    tocbio = io.BytesIO(toc)
    try:
        (entry_count,) = struct.unpack("!i", tocbio.read(4))
    except struct.error as exc:
        raise PyiError(f"解析 TOC 失败: {exc}") from exc

    def read_str(fp: io.BytesIO) -> str:
        (slen,) = struct.unpack("!H", fp.read(2))
        return fp.read(slen).decode("utf-8", errors="replace")

    entries = []
    for _ in range(entry_count):
        dpos, dlen, _ = struct.unpack("!iii", tocbio.read(12))
        name = read_str(tocbio)
        entries.append((name, dpos, dlen))

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, pos, length in entries:
        bio.seek(pos)
        bindata = bio.read(length)
        out_path = out_dir / name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bindata)
    return {"entries": entry_count, "py_ver": info["py_ver"]}


def _find_zlib_stream(data: bytes, start_min: int = 8, start_max: int = 64) -> Tuple[bytes, int, int]:
    """
    Try to locate a zlib-compressed TOC within PYZ file.
    Returns (toc_bytes, toc_start_offset, toc_consumed_len)
    """
    for offset in range(start_min, start_max):
        comp = data[offset:]
        try:
            decomp = zlib.decompressobj()
            toc = decomp.decompress(comp)
            unused = decomp.unused_data
            if toc and unused is not None:
                consumed = len(comp) - len(unused)
                return toc, offset, consumed
        except Exception:
            continue
    raise PyiError("未找到可解压的 TOC zlib 数据")


def unpack_pyz(pyz_path: Path, out_dir: Path, key: Optional[bytes] = None) -> Dict[str, int]:
    """
    Unpack PYZ archive. Best effort for Python 3.x pyz (PyInstaller).
    - key: optional XOR key bytes (for简单异或场景); 不支持 AES key 自动解密。
    """
    data = pyz_path.read_bytes()
    if not data.startswith(b"PYZ\x00"):
        raise PyiError("PYZ 头部无效")

    toc, toc_offset, toc_consumed = _find_zlib_stream(data)
    if key:
        toc = bytes(b ^ key[i % len(key)] for i, b in enumerate(toc))
    try:
        toc_dict = marshal.loads(toc)
    except Exception as exc:
        raise PyiError(f"解析 PYZ TOC 失败，可能需要正确的 key 或匹配的 Python 版本: {exc}") from exc

    pyz_start = toc_offset + toc_consumed
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    failed: Dict[str, str] = {}

    for name, (ispkg, pos, length) in toc_dict.items():
        entry_data = data[pyz_start + pos : pyz_start + pos + length]
        try:
            entry_data = zlib.decompress(entry_data)
        except Exception:
            # 如果不是 zlib 压缩就保持原样
            pass
        out_name = name.replace(".", "/")
        if ispkg:
            out_name += "/__init__.pyc"
        else:
            out_name += ".pyc"
        out_path = out_dir / out_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            out_path.write_bytes(entry_data)
            extracted += 1
        except Exception as exc:
            failed[name] = str(exc)
    if failed:
        (out_dir / "_failed.txt").write_text("\n".join(f"{k}: {v}" for k, v in failed.items()), encoding="utf-8")
    return {"entries": len(toc_dict), "extracted": extracted, "failed": len(failed)}


def decrypt_key_from_pyimod(pyimod_path: Path) -> Optional[bytes]:
    """
    Best-effort attempt to locate pyimod00_crypto_key in pyimod02_archive extracted file.
    Only handles simple cases where key is a literal bytes/str in the marshalled code.
    """
    data = pyimod_path.read_bytes()
    # naive scan for ASCII key literal
    marker = b"pyimod00_crypto_key"
    idx = data.find(marker)
    if idx == -1:
        return None
    snippet = data[idx : idx + 200]
    # find next quote
    for quote in (b"'", b'"'):
        qpos = snippet.find(quote)
        if qpos != -1:
            end = snippet.find(quote, qpos + 1)
            if end != -1:
                key = snippet[qpos + 1 : end]
                return key
    return None
