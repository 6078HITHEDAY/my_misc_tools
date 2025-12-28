import argparse
from typing import Dict, List, Optional

from . import (
    base32_decode,
    base32_encode,
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
    base16_decode,
    base16_encode,
    base58_encode,
    base58_decode,
    base85_encode,
    base85_decode,
    bacon_decode,
    bacon_encode,
    caesar_shift,
    convert_base,
    decrypt_ecb,
    encrypt_ecb,
    hash_data,
    html_entity_encode,
    html_entity_decode,
    unicode_escape_encode,
    unicode_escape_decode,
    buddha_decode,
    buddha_encode,
    core_values_decode,
    core_values_encode,
    auto_decode,
    brute_force_hash,
    lsb_extract,
    split_gif_frames,
    decode_qr,
    extract_exif,
    list_png_chunks,
    encrypt,
    decrypt,
    morse_decode,
    morse_encode,
    pigpen_decode,
    pigpen_encode,
    quoted_printable_decode,
    quoted_printable_encode,
    xor_cipher,
    xor_bruteforce_single_byte,
    uu_encode,
    uu_decode,
    hex_to_ascii,
    bin_to_ascii,
    rail_fence_decrypt,
    rail_fence_encrypt,
    reverse_string,
    rot13,
    rot5,
    rot18,
    rot47,
    rot8000,
    rot_special,
    atbash,
    vigenere_encrypt,
    vigenere_decrypt,
    simple_replace,
    detect_zip_pseudo_encryption,
    binwalk_extract,
    swap_case,
    to_lower,
    to_upper,
    url_decode,
    url_encode,
    decode_bytes_best_effort,
    pyi_unpack,
)
from .base_utils import registry as base_registry, base64_to_hex, base64_decompress
from .history import log_event
from .ai_config import (
    SUPPORTED_PROVIDERS,
    load_ai_config,
    resolve_provider_config,
    save_ai_config,
    mask_secret,
    ProviderConfig,
)
from .ai_assist import (
    ai_assist_cipher,
    ai_assist_crypto,
    ai_assist_stego,
    render_ai_result,
)
from .ai_client import AIError


def _parse_mapping(pairs: List[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for pair in pairs:
        if ":" not in pair:
            raise argparse.ArgumentTypeError(
                f"Invalid mapping '{pair}'. Use the form source:target."
            )
        source, target = pair.split(":", 1)
        mapping[source] = target
    return mapping


def _load_text(args: argparse.Namespace) -> str:
    if args.in_file:
        with open(args.in_file, "rb") as fh:
            content = fh.read()
        preferred = getattr(args, "encoding", None)
        if not preferred:
            enc_guess = detect_encoding_via_file(Path(args.in_file))
            preferred = enc_guess or None
        return decode_bytes_best_effort(content, preferred_encoding=preferred)
    return args.text


def _maybe_write_output(args: argparse.Namespace, output: str) -> None:
    binary = getattr(args, "binary", False)
    if args.out_file:
        mode = "wb" if binary or isinstance(output, bytes) else "w"
        with open(args.out_file, mode) as fh:
            if isinstance(output, bytes) and not binary:
                fh.write(output.hex())
            else:
                fh.write(output if isinstance(output, (str, bytes)) else str(output))
    else:
        if isinstance(output, bytes) and not binary:
            print(output.hex())
        else:
            print(output)
    if getattr(args, "no_history", False):
        return
    log_event(
        action=getattr(args, "command", "unknown"),
        payload={
            "input": getattr(args, "text", None),
            "in_file": getattr(args, "in_file", None),
            "out_file": getattr(args, "out_file", None),
        },
    )

def _run_base_multi(args: argparse.Namespace) -> str:
    codecs = base_registry()
    variant = args.type
    text = _load_text(args)
    if variant == "base58":
        if args.mode == "encode":
            return base58_encode(text)
        else:
            return base58_decode(text)
    if variant not in codecs:
        raise ValueError(f"Unsupported base type: {variant}")
    enc, dec = codecs[variant]
    if args.mode == "encode":
        return enc(text.encode("utf-8", errors="replace"))
    data_bytes = dec(text)
    if args.to_hex:
        return data_bytes.hex()
    return decode_bytes_best_effort(data_bytes, preferred_encoding=getattr(args, "encoding", None))


def _run_ai_config(args: argparse.Namespace) -> str:
    config = load_ai_config()
    target = args.provider or config.provider
    if target not in SUPPORTED_PROVIDERS:
        raise argparse.ArgumentTypeError(f"不支持的服务商: {target}")
    cfg: ProviderConfig = config.providers.get(target, ProviderConfig())

    changed = False
    for field in ["api_key", "base_url", "endpoint", "model"]:
        value = getattr(args, field.replace("-", "_"))
        if value is not None:
            setattr(cfg, field, value)
            changed = True

    config.providers[target] = cfg
    if args.set_active:
        config.provider = target
        changed = True

    if changed:
        save_ai_config(config)

    resolved = resolve_provider_config(config, target)
    lines = [
        f"当前默认服务商: {config.provider}",
        f"查看/更新服务商: {target}",
        f"api_key: {mask_secret(resolved.api_key) or '[未配置]'}",
        f"base_url: {resolved.base_url or '[未配置]'}",
        f"endpoint: {resolved.endpoint or '[未配置]'}",
        f"model: {resolved.model or '[未配置]'}",
    ]
    if changed:
        lines.append("配置已保存；若字段留空仍会自动读取对应环境变量。")
    else:
        lines.append("未提供更新参数，展示当前合并后的配置（空值将尝试读取环境变量）。")
    return "\n".join(lines)


def _run_ai_assist(args: argparse.Namespace) -> str:
    try:
        if args.mode == "cipher":
            data = ai_assist_cipher(args.text, provider=args.provider, api_key=args.api_key)
        elif args.mode == "crypto":
            data = ai_assist_crypto(args.text, hint=args.hint or "", provider=args.provider, api_key=args.api_key)
        else:
            if not args.file:
                raise argparse.ArgumentTypeError("stego 模式需要 --file")
            data = ai_assist_stego(args.file, extra=args.hint or "", provider=args.provider, api_key=args.api_key)
        return render_ai_result(data)
    except AIError as exc:
        return f"AI 调用失败: {exc}"


def _load_cipher_from_args(args: argparse.Namespace) -> str:
    if args.cipher:
        return args.cipher
    if args.file:
        if not os.path.exists(args.file):
            raise argparse.ArgumentTypeError(f"文件不存在: {args.file}")
        with open(args.file, "rb") as fh:
            preferred = getattr(args, "encoding", None)
            if not preferred:
                enc_guess = detect_encoding_via_file(Path(args.file))
                preferred = enc_guess or None
            return decode_bytes_best_effort(fh.read(), preferred_encoding=preferred)
    raise argparse.ArgumentTypeError("需要提供 --cipher 或 --file")


def _write_output_if_needed(text: str, path: Optional[str]) -> str:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return text


def _run_ai_cli(args: argparse.Namespace) -> str:
    provider = args.provider
    api_key = args.api_key
    task_hint = args.task or ""
    try:
        if args.ai_cmd == "identify":
            text = _load_cipher_from_args(args)
            result = ai_assist_cipher(text, provider=provider, api_key=api_key)
        elif args.ai_cmd == "decrypt":
            text = _load_cipher_from_args(args)
            result = ai_assist_cipher(text, provider=provider, api_key=api_key)
        else:  # analyze
            if args.file and os.path.exists(args.file):
                result = ai_assist_stego(args.file, extra=args.hint or task_hint, provider=provider, api_key=api_key)
            elif args.cipher:
                result = ai_assist_crypto(args.cipher, hint=args.hint or task_hint, provider=provider, api_key=api_key)
            else:
                raise argparse.ArgumentTypeError("analyze 需要 --cipher 或 --file")
        rendered = render_ai_result(result)
        _write_output_if_needed(rendered, args.output)
        log_event(
            action="ai",
            payload={
                "subcommand": args.ai_cmd,
                "provider": provider,
                "file": getattr(args, "file", None),
                "output": args.output,
            },
        )
        return rendered
    except AIError as exc:
        return f"AI 调用失败: {exc}"


def _run_pyi_unpack(args: argparse.Namespace) -> str:
    exe_path = Path(args.exe)
    out_dir = Path(args.out)
    if args.pyz_only:
        pyz = exe_path
    else:
        info = pyi_unpack.extract_carchive(exe_path, out_dir)
        pyz_candidates = list(out_dir.glob("**/PYZ-*.pyz"))
        if not pyz_candidates:
            return f"解包完成，共 {info['entries']} 个条目，但未找到 PYZ 文件。"
        pyz = pyz_candidates[0]
    key_bytes = args.key.encode("utf-8") if args.key else None
    pyz_out = out_dir / "pyz_contents"
    try:
        res = pyi_unpack.unpack_pyz(pyz, pyz_out, key=key_bytes)
        msg = f"PYZ 解包完成: {res['extracted']}/{res['entries']}，失败 {res['failed']}，输出: {pyz_out}"
    except Exception as exc:  # pragma: no cover - best effort path
        msg = f"PYZ 解包失败: {exc}"
    return msg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lightweight CTF helper toolkit.")
    parser.add_argument(
        "--no-history", action="store_true", help="Do not record the operation in history."
    )
    parser.add_argument(
        "--encoding",
        help="输入文本/文件编码，默认自动尝试 utf-8/gb18030/big5/shift_jis/cp1252/latin-1。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Base 系列（统一二级菜单）
    base_parser = subparsers.add_parser("base", help="Base 系列编解码")
    base_parser.add_argument("mode", choices=["encode", "decode"])
    base_parser.add_argument("type", choices=sorted(set(base_registry().keys())))
    base_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    base_parser.add_argument("--in-file", help="Read input from file.")
    base_parser.add_argument("--to-hex", action="store_true", help="解码后输出 Hex。")
    base_parser.add_argument("--base64-hex", action="store_true", help="对 base64 输入直接输出 hex。")
    base_parser.add_argument("--base64-decompress", action="store_true", help="base64 解码后尝试 zlib/gzip 解压缩。")
    base_parser.set_defaults(
        func=lambda args: base64_to_hex(_load_text(args))
        if args.base64_hex
        else (base64_decompress(_load_text(args)) if args.base64_decompress else _run_base_multi(args))
    )

    # URL
    url_parser = subparsers.add_parser("url", help="URL percent-encode/decode")
    url_parser.add_argument("mode", choices=["encode", "decode"])
    url_parser.add_argument("text", help="Input text to process.")
    url_parser.add_argument(
        "--safe",
        default="",
        help="Characters to leave unencoded during URL encoding.",
    )
    url_parser.set_defaults(
        func=lambda args: url_encode(args.text, args.safe)
        if args.mode == "encode"
        else url_decode(args.text)
    )

    html_parser = subparsers.add_parser("html", help="HTML 实体编码/解码")
    html_parser.add_argument("mode", choices=["encode", "decode"])
    html_parser.add_argument("text", help="Input text or HTML entities.")
    html_parser.set_defaults(
        func=lambda args: html_entity_encode(args.text)
        if args.mode == "encode"
        else html_entity_decode(args.text)
    )

    # Caesar and ROT13
    caesar_parser = subparsers.add_parser("caesar", help="Caesar cipher encode/decode")
    caesar_parser.add_argument("text", help="Input text to shift.")
    caesar_parser.add_argument(
        "--shift",
        type=int,
        default=3,
        help="Shift to apply (positive for right shift, negative for left). Default is 3.",
    )
    caesar_parser.set_defaults(func=lambda args: caesar_shift(args.text, args.shift))

    rot13_parser = subparsers.add_parser("rot13", help="ROT13 convenience wrapper")
    rot13_parser.add_argument("text", help="Input text to process.")
    rot13_parser.set_defaults(func=lambda args: rot13(args.text))

    rot5_parser = subparsers.add_parser("rot5", help="ROT5 digits")
    rot5_parser.add_argument("text", help="Input text.")
    rot5_parser.set_defaults(func=lambda args: rot5(args.text))

    rot18_parser = subparsers.add_parser("rot18", help="ROT13+ROT5 combo")
    rot18_parser.add_argument("text", help="Input text.")
    rot18_parser.set_defaults(func=lambda args: rot18(args.text))

    rot47_parser = subparsers.add_parser("rot47", help="ROT47 printable ASCII")
    rot47_parser.add_argument("text", help="Input text.")
    rot47_parser.set_defaults(func=lambda args: rot47(args.text))

    rot8000_parser = subparsers.add_parser("rot8000", help="Rotate unicode codepoints by 0x8000")
    rot8000_parser.add_argument("text", help="Input text.")
    rot8000_parser.set_defaults(func=lambda args: rot8000(args.text))

    rot_special_parser = subparsers.add_parser("rotspecial", help="Rot special (alias ROT47)")
    rot_special_parser.add_argument("text", help="Input text.")
    rot_special_parser.set_defaults(func=lambda args: rot_special(args.text))

    atbash_parser = subparsers.add_parser("atbash", help="Atbash substitution")
    atbash_parser.add_argument("text", help="Input text.")
    atbash_parser.set_defaults(func=lambda args: atbash(args.text))

    vig_parser = subparsers.add_parser("vigenere", help="Vigenere cipher encode/decode")
    vig_parser.add_argument("mode", choices=["encrypt", "decrypt"])
    vig_parser.add_argument("text", help="Input text.")
    vig_parser.add_argument("--key", required=True, help="Cipher key.")
    vig_parser.set_defaults(
        func=lambda args: vigenere_encrypt(args.text, args.key)
        if args.mode == "encrypt"
        else vigenere_decrypt(args.text, args.key)
    )

    # Morse
    morse_parser = subparsers.add_parser("morse", help="Morse code encode/decode")
    morse_parser.add_argument("mode", choices=["encode", "decode"])
    morse_parser.add_argument("text", help="Input text or Morse code.")
    morse_parser.set_defaults(
        func=lambda args: morse_encode(args.text)
        if args.mode == "encode"
        else morse_decode(args.text)
    )

    # Rail fence
    rail_parser = subparsers.add_parser("railfence", help="Rail Fence cipher")
    rail_parser.add_argument("mode", choices=["encrypt", "decrypt"])
    rail_parser.add_argument("text", help="Input text.")
    rail_parser.add_argument(
        "--rails",
        type=int,
        default=3,
        help="Number of rails to use (default: 3).",
    )
    rail_parser.set_defaults(
        func=lambda args: rail_fence_encrypt(args.text, args.rails)
        if args.mode == "encrypt"
        else rail_fence_decrypt(args.text, args.rails)
    )

    # String utilities
    reverse_parser = subparsers.add_parser("reverse", help="Reverse string")
    reverse_parser.add_argument("text", help="Input text.")
    reverse_parser.set_defaults(func=lambda args: reverse_string(args.text))

    hex_ascii_parser = subparsers.add_parser("hexascii", help="Hex -> ASCII 文本")
    hex_ascii_parser.add_argument("text", help="Hex string.")
    hex_ascii_parser.set_defaults(func=lambda args: hex_to_ascii(args.text))

    bin_ascii_parser = subparsers.add_parser("binascii", help="二进制串 -> ASCII 文本")
    bin_ascii_parser.add_argument("text", help="Binary string (可含空格分组).")
    bin_ascii_parser.set_defaults(func=lambda args: bin_to_ascii(args.text))

    case_parser = subparsers.add_parser("case", help="Case conversions")
    case_parser.add_argument("mode", choices=["upper", "lower", "swap"])
    case_parser.add_argument("text", help="Input text.")
    case_parser.set_defaults(
        func=lambda args: to_upper(args.text)
        if args.mode == "upper"
        else to_lower(args.text)
        if args.mode == "lower"
        else swap_case(args.text)
    )

    replace_parser = subparsers.add_parser(
        "replace", help="Simple character/string replacement"
    )
    replace_parser.add_argument("text", help="Input text.")
    replace_parser.add_argument(
        "-m",
        "--map",
        nargs="+",
        required=True,
        help="Mappings in the form source:target (e.g., a:@ b:3).",
    )
    replace_parser.set_defaults(
        func=lambda args: simple_replace(args.text, _parse_mapping(args.map))
    )

    # Base conversion
    baseconv = subparsers.add_parser("baseconv", help="Convert between bases 2/8/10/16")
    baseconv.add_argument("value", help="Value to convert.")
    baseconv.add_argument("--from-base", type=int, default=10, help="Source base.")
    baseconv.add_argument("--to-base", type=int, default=16, help="Target base.")
    baseconv.set_defaults(func=lambda args: convert_base(args.value, args.from_base, args.to_base))

    # Hashing
    hash_parser = subparsers.add_parser("hash", help="Hash data with MD5/SHA family")
    hash_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    hash_parser.add_argument("--algo", choices=["md5", "sha1", "sha224", "sha256", "sha512", "crc32"], default="md5")
    hash_parser.add_argument("--input-format", choices=["utf8", "hex", "base64"], default="utf8")
    hash_parser.add_argument("--in-file", help="Read input from file.")
    hash_parser.add_argument("--out-file", help="Write hash output to file.")
    hash_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            hash_data(_load_text(args), algorithm=args.algo, input_format=args.input_format),
        )
    )

    # Modern crypto: AES/DES ECB
    for cipher_name in ["aes", "des"]:
        cipher_parser = subparsers.add_parser(cipher_name, help=f"{cipher_name.upper()} ECB/CBC encrypt/decrypt")
        cipher_parser.add_argument("action", choices=["encrypt", "decrypt"])
        cipher_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
        cipher_parser.add_argument("--key", required=True, help="Key material.")
        cipher_parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb")
        cipher_parser.add_argument("--iv", help="IV for CBC mode.")
        cipher_parser.add_argument("--input-format", choices=["utf8", "hex", "base64"], default="utf8")
        cipher_parser.add_argument("--output-format", choices=["utf8", "hex", "base64"], default="hex")
        cipher_parser.add_argument("--key-format", choices=["utf8", "hex", "base64"], default="utf8")
        cipher_parser.add_argument("--iv-format", choices=["utf8", "hex", "base64"], default="hex")
        cipher_parser.add_argument("--in-file", help="Read input from file.")
        cipher_parser.add_argument("--out-file", help="Write result to file.")
        cipher_parser.set_defaults(
            func=lambda args, name=cipher_name: _maybe_write_output(
                args,
                encrypt(
                    name,
                    _load_text(args),
                    args.key,
                    iv=args.iv,
                    input_format=args.input_format,
                    key_format=args.key_format,
                    output_format=args.output_format,
                    mode=args.mode,
                    iv_format=args.iv_format,
                )
                if args.action == "encrypt"
                else decrypt(
                    name,
                    _load_text(args),
                    args.key,
                    iv=args.iv,
                    input_format=args.input_format,
                    key_format=args.key_format,
                    output_format=args.output_format,
                    mode=args.mode,
                    iv_format=args.iv_format,
                ),
            )
        )

    # Extended classical encodings
    bacon_parser = subparsers.add_parser("bacon", help="Bacon cipher encode/decode")
    bacon_parser.add_argument("mode", choices=["encode", "decode"])
    bacon_parser.add_argument("text", help="Input text or Bacon code.")
    bacon_parser.set_defaults(
        func=lambda args: bacon_encode(args.text) if args.mode == "encode" else bacon_decode(args.text)
    )

    pigpen_parser = subparsers.add_parser("pigpen", help="Pigpen cipher encode/decode")
    pigpen_parser.add_argument("mode", choices=["encode", "decode"])
    pigpen_parser.add_argument("text", help="Input text or Pigpen code.")
    pigpen_parser.set_defaults(
        func=lambda args: pigpen_encode(args.text) if args.mode == "encode" else pigpen_decode(args.text)
    )

    qp_parser = subparsers.add_parser("qp", help="Quoted-Printable encode/decode")
    qp_parser.add_argument("mode", choices=["encode", "decode"])
    qp_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    qp_parser.add_argument("--input-format", choices=["utf8", "hex", "base64"], default="utf8")
    qp_parser.add_argument("--output-format", choices=["utf8", "hex", "base64"], default="utf8")
    qp_parser.add_argument("--in-file", help="Read input from file.")
    qp_parser.add_argument("--out-file", help="Write result to file.")
    qp_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            quoted_printable_encode(_load_text(args), args.input_format)
            if args.mode == "encode"
            else quoted_printable_decode(_load_text(args), args.output_format),
        )
    )

    uu_parser = subparsers.add_parser("uu", help="UUencode 编码/解码")
    uu_parser.add_argument("mode", choices=["encode", "decode"])
    uu_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    uu_parser.add_argument("--input-format", choices=["utf8", "hex", "base64"], default="utf8")
    uu_parser.add_argument("--output-format", choices=["utf8", "hex", "base64"], default="utf8")
    uu_parser.add_argument("--in-file", help="Read input from file.")
    uu_parser.add_argument("--out-file", help="Write result to file.")
    uu_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            uu_encode(_load_text(args), args.input_format)
            if args.mode == "encode"
            else uu_decode(_load_text(args), args.output_format),
        )
    )

    unicode_parser = subparsers.add_parser("unicode", help="Unicode escape 编码/解码")
    unicode_parser.add_argument("mode", choices=["encode", "decode"])
    unicode_parser.add_argument("text", help="Input text.")
    unicode_parser.set_defaults(
        func=lambda args: unicode_escape_encode(args.text)
        if args.mode == "encode"
        else unicode_escape_decode(args.text)
    )

    xor_parser = subparsers.add_parser("xor", help="XOR 加/解密")
    xor_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    xor_parser.add_argument("--key", help="XOR key (utf8/hex/base64).")
    xor_parser.add_argument("--guess", action="store_true", help="尝试单字节 XOR 自动猜测密钥。")
    xor_parser.add_argument("--input-format", choices=["utf8", "hex", "base64"], default="utf8")
    xor_parser.add_argument("--key-format", choices=["utf8", "hex", "base64"], default="utf8")
    xor_parser.add_argument("--output-format", choices=["hex", "utf8", "base64"], default="hex")
    xor_parser.add_argument("--in-file", help="Read input from file.")
    def _xor_runner(args: argparse.Namespace) -> str:
        data_str = _load_text(args)
        if args.input_format == "hex":
            data_bytes = bytes.fromhex(data_str)
        elif args.input_format == "base64":
            import base64

            data_bytes = base64.b64decode(data_str)
        else:
            data_bytes = data_str.encode("utf-8")
        if args.guess:
            key, plain = xor_bruteforce_single_byte(data_bytes)
            return f"猜测密钥: {key:02x}, 明文: {decode_bytes_best_effort(plain, preferred_encoding=getattr(args, 'encoding', None))}"
        if not args.key:
            raise argparse.ArgumentTypeError("需要提供 --key 或使用 --guess")
        return xor_cipher(
            data_str,
            args.key,
            input_format=args.input_format,
            key_format=args.key_format,
            output_format=args.output_format,
        )

    xor_parser.set_defaults(func=_xor_runner)

    # Auto decode
    auto_parser = subparsers.add_parser("auto", help="尝试自动识别常见编码")
    auto_parser.add_argument("text", help="Input text to probe.")
    auto_parser.set_defaults(func=lambda args: auto_decode(args.text))

    # Hash brute-force
    brute_parser = subparsers.add_parser("hashbrute", help="弱口令字典哈希爆破")
    brute_parser.add_argument("hash", help="Target hash value.")
    brute_parser.add_argument("--algo", choices=["md5", "sha1", "sha256", "sha512"], default="md5")
    brute_parser.add_argument("--dict", help="Dictionary file (one password per line).")
    brute_parser.add_argument("--no-rules", action="store_true", help="Disable simple mangling rules.")
    brute_parser.set_defaults(
        func=lambda args: brute_force_hash(
            args.hash,
            algo=args.algo,
            dictionary=open(args.dict, "r", encoding="utf-8", errors="ignore").read().splitlines()
            if args.dict
            else None,
            use_rules=not args.no_rules,
        )
    )

    # LSB extract
    lsb_parser = subparsers.add_parser("lsb", help="提取图片LSB隐写")
    lsb_parser.add_argument("file", help="Image file.")
    lsb_parser.add_argument("--bits", type=int, default=1, help="Bits per channel to extract.")
    lsb_parser.add_argument("--channels", default="RGB", help="Channels to use, e.g., R, RG, RGB.")
    lsb_parser.add_argument("--max-bytes", type=int, help="Limit extraction size.")
    lsb_parser.add_argument("--out-file", help="Optional file to save raw bytes.")
    lsb_parser.add_argument("--binary", action="store_true", help="Write raw bytes instead of hex.")
    lsb_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            lsb_extract(args.file, bits=args.bits, channels=args.channels, max_bytes=args.max_bytes),
        )
    )

    # GIF split
    gif_parser = subparsers.add_parser("gifsplit", help="分离GIF帧")
    gif_parser.add_argument("file", help="GIF file.")
    gif_parser.add_argument("--out", help="Output directory.")
    gif_parser.set_defaults(func=lambda args: "\n".join(split_gif_frames(args.file, args.out)))

    # QR decode
    qr_parser = subparsers.add_parser("qr", help="二维码解码")
    qr_parser.add_argument("file", help="Image file with QR code.")
    qr_parser.set_defaults(func=lambda args: decode_qr(args.file))

    exif_parser = subparsers.add_parser("exif", help="读取图片 EXIF 信息")
    exif_parser.add_argument("file", help="Image file.")
    exif_parser.set_defaults(func=lambda args: extract_exif(args.file))

    png_parser = subparsers.add_parser("pngchunks", help="列出 PNG chunk 信息")
    png_parser.add_argument("file", help="PNG file.")
    png_parser.set_defaults(func=lambda args: "\n".join(list_png_chunks(args.file)))

    # Cultural encodings
    cv_parser = subparsers.add_parser("corevalues", help="社会主义核心价值观编码")
    cv_parser.add_argument("mode", choices=["encode", "decode"])
    cv_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    cv_parser.add_argument("--in-file", help="Read input from file.")
    cv_parser.add_argument("--out-file", help="Write result to file.")
    cv_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            core_values_encode(_load_text(args))
            if args.mode == "encode"
            else core_values_decode(_load_text(args)),
        )
    )

    buddha_parser = subparsers.add_parser("buddha", help="与佛论禅编码/解码（基于自定义Base64映射）")
    buddha_parser.add_argument("mode", choices=["encode", "decode"])
    buddha_parser.add_argument("text", nargs="?", help="Input text (ignored if --in-file).")
    buddha_parser.add_argument("--in-file", help="Read input from file.")
    buddha_parser.add_argument("--out-file", help="Write result to file.")
    buddha_parser.set_defaults(
        func=lambda args: _maybe_write_output(
            args,
            buddha_encode(_load_text(args))
            if args.mode == "encode"
            else buddha_decode(_load_text(args)),
        )
    )

    # Stego helpers
    zip_parser = subparsers.add_parser("zipcheck", help="检测ZIP伪加密")
    zip_parser.add_argument("zipfile", help="ZIP file path.")
    zip_parser.set_defaults(
        func=lambda args: print(detect_zip_pseudo_encryption(args.zipfile))
    )

    binwalk_parser = subparsers.add_parser("binwalk", help="调用binwalk基础提取")
    binwalk_parser.add_argument("file", help="File to scan/extract.")
    binwalk_parser.add_argument("--out", help="Output directory.")
    binwalk_parser.set_defaults(
        func=lambda args: print(binwalk_extract(args.file, args.out))
    )

    pyi_parser = subparsers.add_parser("pyi-unpack", help="解包 PyInstaller 可执行文件")
    pyi_parser.add_argument("exe", help="PyInstaller 打包的 exe 路径")
    pyi_parser.add_argument("--out", default="pyi_out", help="输出目录（默认 pyi_out）")
    pyi_parser.add_argument("--pyz-only", action="store_true", help="仅尝试解包已有 PYZ（假设已解出 CArchive）")
    pyi_parser.add_argument("--key", help="可选，解密 PYZ 的简单 XOR key（字节字符串）")
    pyi_parser.set_defaults(func=_run_pyi_unpack)

    ai_parser = subparsers.add_parser("ai-config", help="AI API 配置管理（支持 OpenAI/Anthropic/千帆）")
    ai_parser.add_argument(
        "--provider",
        choices=SUPPORTED_PROVIDERS,
        help="要查看或更新的服务商（默认当前激活的服务商）。",
    )
    ai_parser.add_argument(
        "--api-key",
        dest="api_key",
        help="API 密钥，留空则保留文件/环境变量现有配置。",
    )
    ai_parser.add_argument(
        "--base-url",
        dest="base_url",
        help="自定义 base_url/host，用于私有化或代理访问。",
    )
    ai_parser.add_argument(
        "--endpoint",
        dest="endpoint",
        help="可选 endpoint/路径配置，未提供时留空。",
    )
    ai_parser.add_argument(
        "--model",
        help="模型名称（如 gpt-4o、claude-3-sonnet 等）。",
    )
    ai_parser.add_argument(
        "--set-active",
        action="store_true",
        help="保存后将该服务商设为默认调用对象。",
    )
    ai_parser.set_defaults(func=_run_ai_config)

    ai_assist_parser = subparsers.add_parser("ai-assist", help="AI 辅助识别/解码/分析")
    ai_assist_parser.add_argument(
        "mode",
        choices=["cipher", "crypto", "stego"],
        help="cipher: 编码/经典密码; crypto: 哈希/加密/爆破; stego: 隐写/文件。",
    )
    ai_assist_parser.add_argument(
        "text",
        nargs="?",
        help="输入文本/密文（stego 模式可留空，需搭配 --file）。",
    )
    ai_assist_parser.add_argument(
        "--file",
        help="隐写/压缩包等文件路径，仅 stego 模式使用。",
    )
    ai_assist_parser.add_argument(
        "--hint",
        help="额外提示（如疑似算法、已知明文片段等）。",
    )
    ai_assist_parser.add_argument(
        "--provider",
        choices=SUPPORTED_PROVIDERS,
        help="强制覆盖配置文件指定的服务商（默认读取配置文件）。",
    )
    ai_assist_parser.add_argument(
        "--api-key",
        dest="api_key",
        help="临时 API Key（优先级低于配置文件）。",
    )
    ai_assist_parser.set_defaults(func=_run_ai_assist)

    ai_root = subparsers.add_parser("ai", help="AI 命令集: identify/decrypt/analyze")
    ai_root_sub = ai_root.add_subparsers(dest="ai_cmd", required=True)

    def _common_ai_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--provider", choices=SUPPORTED_PROVIDERS, help="覆盖默认服务商")
        p.add_argument("--api-key", dest="api_key", help="临时 API Key（低于配置文件优先级）")
        p.add_argument("--output", help="将结果写入文件")
        p.add_argument("--task", help="任务类型提示（可选）")

    ai_identify = ai_root_sub.add_parser("identify", help="密文识别/解码建议")
    ai_identify.add_argument("--cipher", help="密文/文本输入")
    ai_identify.add_argument("--file", help="从文件读取密文")
    _common_ai_args(ai_identify)
    ai_identify.set_defaults(func=_run_ai_cli)

    ai_decrypt = ai_root_sub.add_parser("decrypt", help="AI 参与的解码")
    ai_decrypt.add_argument("--cipher", help="密文/文本输入")
    ai_decrypt.add_argument("--file", help="从文件读取密文")
    ai_decrypt.add_argument("--hint", help="额外提示（如密钥猜测）")
    _common_ai_args(ai_decrypt)
    ai_decrypt.set_defaults(func=_run_ai_cli)

    ai_analyze = ai_root_sub.add_parser("analyze", help="文件/哈希/隐写分析")
    ai_analyze.add_argument("--cipher", help="文本输入（用于哈希/加密分析）")
    ai_analyze.add_argument("--file", help="文件路径（隐写/压缩包等）")
    ai_analyze.add_argument("--hint", help="额外提示")
    _common_ai_args(ai_analyze)
    ai_analyze.set_defaults(func=_run_ai_cli)

    ai_assist_parser = subparsers.add_parser("ai-assist", help="AI 辅助识别/解码/分析")
    ai_assist_parser.add_argument(
        "mode",
        choices=["cipher", "crypto", "stego"],
        help="cipher: 编码/经典密码; crypto: 哈希/加密/爆破; stego: 隐写/文件。",
    )
    ai_assist_parser.add_argument(
        "text",
        nargs="?",
        help="输入文本/密文（stego 模式可留空，需搭配 --file）。",
    )
    ai_assist_parser.add_argument(
        "--file",
        help="隐写/压缩包等文件路径，仅 stego 模式使用。",
    )
    ai_assist_parser.add_argument(
        "--hint",
        help="额外提示（如疑似算法、已知明文片段等）。",
    )
    ai_assist_parser.set_defaults(func=_run_ai_assist)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    if result is not None and not isinstance(result, bool):
        print(result)
    if not getattr(args, "no_history", False):
        log_event(
            action=getattr(args, "command", "unknown"),
            payload={
                "input": getattr(args, "text", None),
                "in_file": getattr(args, "in_file", None),
                "out_file": getattr(args, "out_file", None),
            },
        )


if __name__ == "__main__":
    main()
