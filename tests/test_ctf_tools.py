import unittest

from ctf_tools import (
    bacon_decode,
    bacon_encode,
    auto_decode,
    brute_force_archive,
    brute_force_hash,
    encrypt,
    decrypt,
    convert_base,
    decrypt_ecb,
    encrypt_ecb,
    hash_data,
    base32_decode,
    base32_encode,
    base64_decode,
    base64_encode,
    base64url_encode,
    base64url_decode,
    base16_decode,
    base16_encode,
    base58_encode,
    base58_decode,
    base85_encode,
    base85_decode,
    buddha_decode,
    buddha_encode,
    caesar_shift,
    core_values_decode,
    core_values_encode,
    morse_decode,
    morse_encode,
    pigpen_decode,
    pigpen_encode,
    quoted_printable_decode,
    quoted_printable_encode,
    rail_fence_decrypt,
    rail_fence_encrypt,
    vigenere_encrypt,
    vigenere_decrypt,
    atbash,
    reverse_string,
    rot13,
    simple_replace,
    swap_case,
    to_lower,
    to_upper,
    url_decode,
    url_encode,
    list_png_chunks,
    build_charset,
    generate_passwords,
    html_entity_encode,
    html_entity_decode,
    uu_encode,
    uu_decode,
    hex_to_ascii,
    bin_to_ascii,
    xor_cipher,
    load_ai_config,
    save_ai_config,
    ai_assist_cipher,
    AIError,
)
from ctf_tools.image_stego import lsb_extract
from PIL import Image
from pathlib import Path
from tempfile import TemporaryDirectory
import os


class TestCtfTools(unittest.TestCase):
    def test_base64_roundtrip(self) -> None:
        text = "flag{base64_test}"
        self.assertEqual(base64_decode(base64_encode(text)), text)
        self.assertEqual(base64url_decode(base64url_encode(text)), text)
        self.assertEqual(base16_decode(base16_encode(text)), text)
        self.assertEqual(base58_decode(base58_encode(text)), text)
        self.assertEqual(base85_decode(base85_encode(text)), text)

    def test_base32_roundtrip(self) -> None:
        text = "flag{base32}"
        self.assertEqual(base32_decode(base32_encode(text)), text)

    def test_url_roundtrip(self) -> None:
        text = "https://example.com/flag?value=hello world"
        self.assertEqual(url_decode(url_encode(text)), text)

    def test_caesar_and_rot13(self) -> None:
        self.assertEqual(caesar_shift("Attack", 3), "Dwwdfn")
        self.assertEqual(caesar_shift("Dwwdfn", -3), "Attack")
        sample = "rot13 keeps letters readable"
        self.assertEqual(rot13(rot13(sample)), sample)
        self.assertEqual(vigenere_decrypt(vigenere_encrypt("HELLO", "KEY"), "KEY"), "HELLO")
        self.assertEqual(atbash("AbcZ"), "ZyxA")

    def test_morse_roundtrip(self) -> None:
        message = "SOS HELP"
        encoded = morse_encode(message)
        self.assertEqual(encoded, "... --- ... / .... . .-.. .--.")
        self.assertEqual(morse_decode(encoded), message)

    def test_rail_fence_roundtrip(self) -> None:
        plaintext = "WEAREDISCOVEREDFLEEATONCE"
        encrypted = rail_fence_encrypt(plaintext, rails=3)
        self.assertEqual(encrypted, "WECRLTEERDSOEEFEAOCAIVDEN")
        self.assertEqual(rail_fence_decrypt(encrypted, rails=3), plaintext)

    def test_string_utilities(self) -> None:
        self.assertEqual(reverse_string("abc123"), "321cba")
        self.assertEqual(to_upper("Flag"), "FLAG")
        self.assertEqual(to_lower("Flag"), "flag")
        self.assertEqual(swap_case("AbC"), "aBc")
        self.assertEqual(simple_replace("leet", {"e": "3", "t": "7"}), "l337")

    def test_aes_ecb_roundtrip(self) -> None:
        key = "00112233445566778899aabbccddeeff"
        plaintext = "Attack at dawn!"
        ct = encrypt_ecb("aes", plaintext, key, input_format="utf8", key_format="hex", output_format="hex")
        self.assertEqual(
            decrypt_ecb("aes", ct, key, input_format="hex", key_format="hex", output_format="utf8"),
            plaintext,
        )

    def test_des_ecb_roundtrip(self) -> None:
        key = "0123456789abcdef"
        plaintext = "Plaintext"
        ct = encrypt_ecb("des", plaintext, key, input_format="utf8", key_format="hex", output_format="hex")
        self.assertEqual(
            decrypt_ecb("des", ct, key, input_format="hex", key_format="hex", output_format="utf8"),
            plaintext,
        )

    def test_aes_cbc_roundtrip(self) -> None:
        key = "00112233445566778899aabbccddeeff"
        iv = "000102030405060708090a0b0c0d0e0f"
        plaintext = "CBC mode test"
        ct = encrypt("aes", plaintext, key, iv=iv, input_format="utf8", key_format="hex", iv_format="hex", output_format="hex", mode="cbc")
        self.assertEqual(
            decrypt("aes", ct, key, iv=iv, input_format="hex", key_format="hex", iv_format="hex", output_format="utf8", mode="cbc"),
            plaintext,
        )

    def test_base_conversion_and_hash(self) -> None:
        self.assertEqual(convert_base("ff", 16, 2), "11111111")
        self.assertEqual(hash_data("hello", "md5"), "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(hash_data("hello", "crc32"), "3610a686")

    def test_bacon_and_pigpen(self) -> None:
        msg = "HELLO"
        encoded_bacon = bacon_encode(msg)
        self.assertEqual(bacon_decode(encoded_bacon), msg)

        pigpen = pigpen_encode("CTF")
        self.assertEqual(pigpen_decode(pigpen), "CTF")

    def test_quoted_printable(self) -> None:
        encoded = quoted_printable_encode("hello=world")
        self.assertEqual(encoded, "hello=3Dworld")
        self.assertEqual(quoted_printable_decode(encoded), "hello=world")
        uu = uu_encode("data")
        self.assertEqual(uu_decode(uu), "data")

    def test_html_and_ascii_helpers(self) -> None:
        self.assertEqual(html_entity_decode(html_entity_encode("<tag>&")), "<tag>&")
        self.assertEqual(hex_to_ascii("414243"), "ABC")
        self.assertEqual(bin_to_ascii("01000001 01000010"), "AB")
        self.assertEqual(xor_cipher("hi", "01", input_format="utf8", key_format="hex", output_format="hex"), "6968")

    def test_core_values_and_buddha(self) -> None:
        msg = "测试CoreValues"
        encoded = core_values_encode(msg)
        self.assertEqual(core_values_decode(encoded), msg)

        buddha = buddha_encode("hello")
        self.assertEqual(buddha_decode(buddha), "hello")

    def test_auto_decode_and_bruteforce(self) -> None:
        sample = base64_encode("auto123")
        results = dict(auto_decode(sample))
        self.assertEqual(results["base64"], "auto123")
        target = hash_data("123456", "md5")
        self.assertEqual(brute_force_hash(target, algo="md5"), "123456")
        target2 = hash_data("Pass123", "md5")
        self.assertEqual(brute_force_hash(target2, algo="md5", dictionary=["pass"], use_rules=True), "Pass123")

    def test_lsb_extract(self) -> None:
        img = Image.new("RGB", (4, 2), color=(0, 0, 0))
        pixels = img.load()
        pixels[0, 0] = (1, 0, 0)  # LSB pattern 1
        img_path = "tests/tmp_lsb.png"
        img.save(img_path)
        extracted = lsb_extract(img_path, bits=1, channels="R", max_bytes=1)
        # Expect first bit set => byte value 128 when reversed packing; check non-zero
        self.assertTrue(len(extracted) >= 1)
        self.assertNotEqual(extracted[0], 0)

    def test_png_chunks(self) -> None:
        img = Image.new("RGB", (1, 1), color=(255, 0, 0))
        png_path = "tests/tmp_chunk.png"
        img.save(png_path, format="PNG")
        chunks = list_png_chunks(png_path)
        self.assertIn("IHDR", chunks)

    def test_ai_config_env_and_save(self) -> None:
        env_backup = os.environ.get("OPENAI_API_KEY")
        try:
            os.environ["OPENAI_API_KEY"] = "env-key"
            with TemporaryDirectory() as tmpdir:
                cfg_path = Path(tmpdir) / "ai.json"
                cfg = load_ai_config(cfg_path)
                self.assertEqual(cfg.providers["openai"].api_key, "env-key")
                cfg.providers["openai"].base_url = "https://example.com"
                save_ai_config(cfg, cfg_path)
                reloaded = load_ai_config(cfg_path)
                self.assertEqual(reloaded.providers["openai"].base_url, "https://example.com")
        finally:
            if env_backup is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = env_backup

    def test_ai_assist_requires_key(self) -> None:
        # 确保无密钥时仍返回结构或给出友好错误，不影响核心功能
        env_backup = os.environ.pop("OPENAI_API_KEY", None)
        try:
            data = ai_assist_cipher("dGVzdA==")
            self.assertTrue(isinstance(data, dict))
        finally:
            if env_backup is not None:
                os.environ["OPENAI_API_KEY"] = env_backup

    def test_generate_passwords_and_charset(self) -> None:
        charset = build_charset(use_digits=True, use_lower=False, use_upper=False, use_symbols=False)
        candidates = list(generate_passwords(2, 2, charset))
        self.assertIn("00", candidates)
        self.assertIn("99", candidates)
        self.assertEqual(len(candidates), 100)

    def test_archive_bruteforce_archive(self) -> None:
        try:
            import py7zr  # type: ignore
        except ImportError:
            self.skipTest("py7zr not installed")
        with TemporaryDirectory() as tmpdir:
            archive_path = Path(tmpdir) / "secret.7z"
            payload = Path(tmpdir) / "flag.txt"
            payload.write_text("secret")
            with py7zr.SevenZipFile(archive_path, "w", password="p4ss") as archive:
                archive.write(payload, arcname="flag.txt")
            result = brute_force_archive(
                str(archive_path),
                dictionary=["wrong", "p4ss"],
                include_generated=False,
                extract=True,
            )
            self.assertIsNotNone(result)
            assert result  # mypy hint
            self.assertEqual(result.password, "p4ss")
            self.assertTrue(result.extracted_to)
            extracted = Path(result.extracted_to) / "flag.txt"
            self.assertTrue(extracted.exists())
            self.assertEqual(extracted.read_text(), "secret")


if __name__ == "__main__":
    unittest.main()
