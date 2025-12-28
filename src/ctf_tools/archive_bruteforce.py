import lzma
import string
from dataclasses import dataclass
from itertools import chain, product
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Tuple, List

DEFAULT_SYMBOLS = "!@#$%^&*"
PRINTABLE = "".join(chr(i) for i in range(32, 127))
DEFAULT_COMMON_PASSWORDS = [
    "123456",
    "123456789",
    "1234",
    "111111",
    "abc123",
    "password",
    "12345",
    "000000",
    "1q2w3e4r",
    "qwerty",
]

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


def _generate_numeric_passwords(min_length: int, max_length: int) -> Iterator[str]:
    """
    Specialized fast generator for numeric-only passwords; uses range + zfill
    to avoid Cartesian product overhead.
    """
    if min_length < 1 or max_length < min_length:
        raise ValueError("Invalid length range for brute-force generation.")
    for length in range(min_length, max_length + 1):
        upper = 10**length
        for num in range(0, upper):
            yield str(num).zfill(length)


def _count_generated(min_length: int, max_length: int, charset_size: int) -> int:
    total = 0
    for length in range(min_length, max_length + 1):
        total += charset_size**length
    return total


def _build_candidate_sources(
    dictionary_file: Optional[str],
    dictionary: Optional[Iterable[str]],
    include_generated: bool,
    min_length: int,
    max_length: int,
    charset: Optional[str],
    with_upper: bool,
    with_symbols: bool,
    with_space: bool,
    printable: bool,
    use_common: bool,
    common_passwords: Optional[Iterable[str]],
    common_first: bool,
) -> Tuple[List[Tuple[str, Iterator[str], Optional[int]]], int]:
    """
    Build candidate iterators along with their approximate counts.
    """
    sources: List[Tuple[str, Iterator[str], Optional[int]]] = []
    total_attempts = 0

    def _push(name: str, it: Iterator[str], count: Optional[int]) -> None:
        nonlocal sources, total_attempts
        sources.append((name, it, count))
        if count:
            total_attempts += count

    if dictionary_file:
        dict_path = Path(dictionary_file)
        if not dict_path.exists():
            raise FileNotFoundError(f"Dictionary file not found: {dictionary_file}")
        # Count lines for progress (second pass for actual iteration).
        dict_count = sum(1 for _ in _iter_dict_file(dict_path))
        _push("dictionary_file", _iter_dict_file(dict_path), dict_count)

    if dictionary:
        source_iter = (pwd.strip() for pwd in dictionary if pwd)
        dict_len: Optional[int] = None
        try:
            dict_len = len(dictionary)  # type: ignore[arg-type]
        except Exception:
            dict_len = None
        _push("dictionary_iter", source_iter, dict_len)

    common_iter: Optional[Iterator[str]] = None
    if use_common:
        if common_passwords:
            common_iter = (pwd.strip() for pwd in common_passwords if pwd)
        else:
            common_iter = (pwd for pwd in DEFAULT_COMMON_PASSWORDS)
        common_count = None
        try:
            common_count = len(common_passwords) if common_passwords is not None else len(DEFAULT_COMMON_PASSWORDS)  # type: ignore[arg-type]
        except Exception:
            common_count = None
        if common_first:
            _push("common", common_iter, common_count)

    if include_generated:
        final_charset = charset or build_charset(
            use_digits=True,
            use_lower=True,
            use_upper=with_upper,
            use_symbols=with_symbols,
            use_space=with_space,
            use_printable=printable,
        )
        gen_total = _count_generated(min_length, max_length, len(final_charset))
        if set(final_charset) == set(string.digits):
            generator = _generate_numeric_passwords(min_length, max_length)
            _push("numeric", generator, gen_total)
        else:
            _push("generated", generate_passwords(min_length, max_length, final_charset), gen_total)

    if use_common and common_iter and not common_first:
        _push("common", common_iter, common_count)

    return sources, total_attempts


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
        except (self._rarfile.RarWrongPassword, self._rarfile.Error):
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
    use_common: bool = True,
    common_passwords: Optional[Iterable[str]] = None,
    common_first: bool = True,
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
    sources, total_attempts = _build_candidate_sources(
        dictionary_file,
        dictionary,
        include_generated,
        min_length,
        max_length,
        charset,
        with_upper,
        with_symbols,
        with_space,
        printable,
        use_common,
        common_passwords,
        common_first,
    )
    if not sources:
        raise ValueError("No candidate source provided; supply a dictionary or enable brute-force generation.")

    attempts = 0
    found: Optional[str] = None
    output: Optional[str] = None
    archive_format = ""
    with _get_handler(archive, target_member) as handler:
        archive_format = handler.format
        for _, source_iter, source_total in sources:
            for pwd in source_iter:
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
