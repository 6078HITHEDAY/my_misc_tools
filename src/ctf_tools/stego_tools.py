import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import List, Optional


def detect_zip_pseudo_encryption(zip_path: str) -> List[dict]:
    """
    Check entries for pseudo-encryption: encrypted flag set but data readable without password.
    """
    results = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            encrypted_flag = bool(info.flag_bits & 0x1)
            status = "not_encrypted"
            detail = "Not marked encrypted."
            if encrypted_flag:
                try:
                    zf.read(info.filename)  # attempt without password
                    status = "pseudo_encrypted"
                    detail = "Flagged encrypted but content readable without password."
                except RuntimeError:
                    status = "encrypted"
                    detail = "Encrypted content (password required)."
            results.append(
                {
                    "filename": info.filename,
                    "encrypted_flag": encrypted_flag,
                    "status": status,
                    "detail": detail,
                }
            )
    return results


def binwalk_extract(file_path: str, output_dir: Optional[str] = None) -> str:
    """
    Run binwalk extraction (-e) if available. Returns path to output directory.
    """
    if shutil.which("binwalk") is None:
        raise FileNotFoundError("binwalk is not installed or not on PATH.")
    target = Path(output_dir) if output_dir else Path(file_path).with_suffix("") / "binwalk_extracted"
    target.mkdir(parents=True, exist_ok=True)
    cmd = ["binwalk", "-e", "-q", "--directory", str(target), file_path]
    subprocess.check_call(cmd)
    return str(target)
