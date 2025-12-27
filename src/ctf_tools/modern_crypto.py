import base64
from typing import Literal

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

CipherName = Literal["aes", "des"]
DataFormat = Literal["utf8", "hex", "base64"]
HashAlgorithm = Literal["md5", "sha1", "sha256", "sha512"]
ModeName = Literal["ecb", "cbc"]


def _load_bytes(data: str, fmt: DataFormat) -> bytes:
    if fmt == "utf8":
        return data.encode("utf-8")
    if fmt == "hex":
        return bytes.fromhex(data)
    if fmt == "base64":
        return base64.b64decode(data)
    raise ValueError(f"Unsupported data format: {fmt}")


def _dump_bytes(data: bytes, fmt: DataFormat) -> str:
    if fmt == "utf8":
        return data.decode("utf-8")
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError(f"Unsupported data format: {fmt}")


def _build_cipher(name: CipherName, key: bytes, mode: ModeName, iv: bytes = b""):
    if name == "aes":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        block_size = AES.block_size
        if mode == "ecb":
            return AES.new(key, AES.MODE_ECB), block_size
        if mode == "cbc":
            if len(iv) != block_size:
                raise ValueError(f"AES CBC IV must be {block_size} bytes.")
            return AES.new(key, AES.MODE_CBC, iv=iv), block_size
    if name == "des":
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes.")
        block_size = DES.block_size
        if mode == "ecb":
            return DES.new(key, DES.MODE_ECB), block_size
        if mode == "cbc":
            if len(iv) != block_size:
                raise ValueError(f"DES CBC IV must be {block_size} bytes.")
            return DES.new(key, DES.MODE_CBC, iv=iv), block_size
    raise ValueError(f"Unsupported cipher/mode: {name} {mode}")


def encrypt_ecb(
    cipher: CipherName,
    plaintext: str,
    key: str,
    input_format: DataFormat = "utf8",
    key_format: DataFormat = "utf8",
    output_format: DataFormat = "hex",
) -> str:
    return encrypt(cipher, plaintext, key, None, input_format, key_format, output_format, mode="ecb")


def decrypt_ecb(
    cipher: CipherName,
    ciphertext: str,
    key: str,
    input_format: DataFormat = "hex",
    key_format: DataFormat = "utf8",
    output_format: DataFormat = "utf8",
) -> str:
    return decrypt(cipher, ciphertext, key, None, input_format, key_format, output_format, mode="ecb")


def encrypt(
    cipher: CipherName,
    plaintext: str,
    key: str,
    iv: str = None,
    input_format: DataFormat = "utf8",
    key_format: DataFormat = "utf8",
    output_format: DataFormat = "hex",
    mode: ModeName = "ecb",
    iv_format: DataFormat = "utf8",
) -> str:
    pt_bytes = _load_bytes(plaintext, input_format)
    key_bytes = _load_bytes(key, key_format)
    iv_bytes = _load_bytes(iv, iv_format) if iv is not None else b""
    cipher_obj, block_size = _build_cipher(cipher, key_bytes, mode, iv_bytes)
    padded = pad(pt_bytes, block_size)
    encrypted = cipher_obj.encrypt(padded)
    return _dump_bytes(encrypted, output_format)


def decrypt(
    cipher: CipherName,
    ciphertext: str,
    key: str,
    iv: str = None,
    input_format: DataFormat = "hex",
    key_format: DataFormat = "utf8",
    output_format: DataFormat = "utf8",
    mode: ModeName = "ecb",
    iv_format: DataFormat = "utf8",
) -> str:
    ct_bytes = _load_bytes(ciphertext, input_format)
    key_bytes = _load_bytes(key, key_format)
    iv_bytes = _load_bytes(iv, iv_format) if iv is not None else b""
    cipher_obj, block_size = _build_cipher(cipher, key_bytes, mode, iv_bytes)
    decrypted = cipher_obj.decrypt(ct_bytes)
    unpadded = unpad(decrypted, block_size)
    return _dump_bytes(unpadded, output_format)
