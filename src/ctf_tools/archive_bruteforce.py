import lzma
import string
from dataclasses import dataclass
from itertools import chain, product
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Tuple

DEFAULT_SYMBOLS = "!@#$%^&*"
PRINTABLE = "".join(chr(i) for i in range(32, 127))

ProgressCallback = Callable[[int, Optional[int]], None]


@dataclass
class ArchiveCrackResult:
    """Result returned when a password is found."""

    password: str
    attempts: int
    extracted_to: Optional[str]
    format: str


def build_charset(
    use_digits: bool = True,
    use_lower: bool = True,
    use_upper: bool = False,
    use_symbols: bool = False,
    use_space: bool = False,
    use_printable: bool = False,
    extra_symbols: str = DEFAULT_SYMBOLS,
) -> str:
    """
    Build a character set string for brute-force generation.
    """
    charset = ""
    if use_printable:
        charset += PRINTABLE
    else:
        if use_digits:
            charset += string.digits
        if use_lower:
            charset += string.ascii_lowercase
        if use_upper:
            charset += string.ascii_uppercase
        if use_symbols:
            charset += extra_symbols
        if use_space:
            charset += " "
    charset = "".join(dict.fromkeys(charset))  # remove duplicates while keeping order
    if not charset:
        raise ValueError("Character set cannot be empty.")
    return charset


def generate_passwords(min_length: int, max_length: int, charset: str) -> Iterator[str]:
    """
    Generate password candidates with lengths in the given range using the
    supplied character set.
    """
    if min_length < 1 or max_length < min_length:
        raise ValueError("Invalid length range for brute-force generation.")
    if not charset:
        raise ValueError("Character set cannot be empty.")
    for length in range(min_length, max_length + 1):
        for combo in product(charset, repeat=length):
            yield "".join(combo)


def _count_generated(min_length: int, max_length: int, charset_size: int) -> int:
    total = 0
    for length in range(min_length, max_length + 1):
        total += charset_size**length
    return total


def _iter_dict_file(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pwd = line.strip()
            if pwd:
                yield pwd


class _BaseArchiveHandler:
    format: str

    def test_password(self, password: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def extract_all(self, password: str, output_dir: Optional[Path]) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "_BaseArchiveHandler":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class _ZipHandler(_BaseArchiveHandler):
    format = "zip"

    def __init__(self, path: Path, target_member: Optional[str] = None):
        import zipfile

        self.path = path
        self._zipfile = zipfile.ZipFile(path, "r")
        self._members = [target_member] if target_member else self._zipfile.namelist()
        if not self._members:
            raise ValueError("ZIP archive is empty.")

    def test_password(self, password: str) -> bool:
        pwd = password.encode("utf-8")
        try:
            # Read the first entry; a wrong password raises RuntimeError.
            self._zipfile.read(self._members[0], pwd=pwd)
            return True
        except RuntimeError:
            return False

    def extract_all(self, password: str, output_dir: Optional[Path]) -> str:
        target = output_dir or self.path.with_suffix("")
        target.mkdir(parents=True, exist_ok=True)
        self._zipfile.extractall(path=target, pwd=password.encode("utf-8"))
        return str(target)

    def close(self) -> None:
        self._zipfile.close()


class _SevenZipHandler(_BaseArchiveHandler):
    format = "7z"

    def __init__(self, path: Path, target_member: Optional[str] = None):
        try:
            import py7zr  # type: ignore
        except ImportError as exc:  # pragma: no cover - import guard
            raise ImportError("py7zr is required for 7z archives.") from exc
        self._py7zr = py7zr
        self.path = path
        self._target = target_member

    def test_password(self, password: str) -> bool:
        try:
            with self._py7zr.SevenZipFile(self.path, mode="r", password=password) as archive:
                names = archive.getnames()
                if self._target:
                    names = [self._target]
                if names:
                    archive.read([names[0]])
                else:
                    archive.list()
            return True
        except self._py7zr.exceptions.PasswordRequired:
            return False
        except lzma.LZMAError:
            return False

    def extract_all(self, password: str, output_dir: Optional[Path]) -> str:
        target = output_dir or self.path.with_suffix("")
        target.mkdir(parents=True, exist_ok=True)
        with self._py7zr.SevenZipFile(self.path, mode="r", password=password) as archive:
            if self._target:
                archive.extract(targets=[self._target], path=target)
            else:
                archive.extractall(path=target)
        return str(target)


class _RarHandler(_BaseArchiveHandler):
    format = "rar"

    def __init__(self, path: Path, target_member: Optional[str] = None):
        try:
            import rarfile  # type: ignore
        except ImportError as exc:  # pragma: no cover - import guard
            raise ImportError("rarfile is required for RAR archives.") from exc
        self._rarfile = rarfile
        self.path = path
        try:
            self._rf = rarfile.RarFile(path)
        except rarfile.RarCannotExec as exc:
            raise RuntimeError(
                "RAR support requires unrar/bsdtar on PATH; install one of them to proceed."
            ) from exc
        self._target = target_member
        self._members = [m for m in self._rf.infolist() if (not target_member or m.filename == target_member)]
        if not self._members:
            raise ValueError("RAR archive is empty.")

    def test_password(self, password: str) -> bool:
        try:
            self._rf.setpassword(password)
            self._rf.read(self._members[0])
            return True
        except self._rarfile.RarWrongPassword:
            return False

    def extract_all(self, password: str, output_dir: Optional[Path]) -> str:
        target = output_dir or self.path.with_suffix("")
        target.mkdir(parents=True, exist_ok=True)
        self._rf.setpassword(password)
        if self._target:
            self._rf.extract(self._target, path=target)
        else:
            self._rf.extractall(path=target)
        return str(target)

    def close(self) -> None:
        self._rf.close()


def _get_handler(path: Path, target_member: Optional[str] = None) -> _BaseArchiveHandler:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return _ZipHandler(path, target_member)
    if suffix in {".7z", ".7zip"}:
        return _SevenZipHandler(path, target_member)
    if suffix == ".rar":
        return _RarHandler(path, target_member)
    raise ValueError("Unsupported archive format. Supported: ZIP, 7Z, RAR.")


def brute_force_archive(
    archive_path: str,
    dictionary_file: Optional[str] = None,
    dictionary: Optional[Iterable[str]] = None,
    include_generated: bool = True,
    min_length: int = 1,
    max_length: int = 4,
    charset: Optional[str] = None,
    with_upper: bool = True,
    with_symbols: bool = False,
    with_space: bool = False,
    printable: bool = False,
    progress_callback: Optional[ProgressCallback] = None,
    progress_interval: int = 500,
    extract: bool = False,
    output_dir: Optional[str] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    target_member: Optional[str] = None,
) -> Optional[ArchiveCrackResult]:
    """
    Attempt to brute-force a compressed archive using a dictionary and/or
    generated candidates.
    """
    archive = Path(archive_path)
    if not archive.exists():
        raise FileNotFoundError(f"Archive not found: {archive}")
    sources = []
    total_attempts = 0

    if dictionary_file:
        dict_path = Path(dictionary_file)
        if not dict_path.exists():
            raise FileNotFoundError(f"Dictionary file not found: {dictionary_file}")
        total_attempts += sum(1 for _ in _iter_dict_file(dict_path))
        sources.append(_iter_dict_file(dict_path))

    if dictionary:
        sources.append(pwd.strip() for pwd in dictionary)
        try:
            total_attempts += len(dictionary)  # type: ignore[arg-type]
        except Exception:
            pass

    if include_generated:
        final_charset = charset or build_charset(
            use_digits=True,
            use_lower=True,
            use_upper=with_upper,
            use_symbols=with_symbols,
            use_space=with_space,
            use_printable=printable,
        )
        total_attempts += _count_generated(min_length, max_length, len(final_charset))
        sources.append(generate_passwords(min_length, max_length, final_charset))

    if not sources:
        raise ValueError("No candidate source provided; supply a dictionary or enable brute-force generation.")

    attempts = 0
    found: Optional[str] = None
    output: Optional[str] = None
    archive_format = ""
    with _get_handler(archive, target_member) as handler:
        archive_format = handler.format
        for source in sources:
            for pwd in source:
                if not pwd:
                    continue
                if should_stop and should_stop():
                    return None
                attempts += 1
                if handler.test_password(pwd):
                    found = pwd
                    if extract:
                        output = handler.extract_all(pwd, Path(output_dir) if output_dir else None)
                    break
                if progress_callback and progress_interval > 0:
                    if attempts == 1 or attempts % progress_interval == 0 or (
                        total_attempts and attempts == total_attempts
                    ):
                        progress_callback(attempts, total_attempts or None)
            if found:
                break
    if found:
        if progress_callback and (not total_attempts or attempts != total_attempts):
            progress_callback(attempts, total_attempts or None)
        return ArchiveCrackResult(
            password=found,
            attempts=attempts,
            extracted_to=output,
            format=archive_format,
        )
    if progress_callback:
        progress_callback(attempts, total_attempts or None)
    return None
