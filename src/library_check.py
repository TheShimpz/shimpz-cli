"""Prove, without running anything, that every ELF file of an Assistant image resolves its shared libraries.

usage: python3 -I -S -B shimpz_library_check.py ROOT

The image build runs this with the official interpreter and standard library alone (`-I -S`, so no site directory,
`.pth` file, or venv module is ever read) over the final filesystem at ROOT. It reads every file below the scanned roots
as data: each ELF file's program headers and dynamic section give its interpreter, its DT_NEEDED names, and its
DT_RPATH or DT_RUNPATH, and each needed name must resolve, as the dynamic loader resolves it, to an ELF file of the
image's own class and machine inside the image. No loader, binary, or library from the image is ever executed. A file
that declares an audit library (DT_AUDIT, DT_DEPAUDIT) is refused outright, as is any symbolic link that leaves the
image's payload or library directories, and any finding fails the build.
"""

import os
import stat
import struct
import sys
from pathlib import Path

# The directories whose every file is inspected: the venv and project, the official interpreter tree, and the system
# libraries. A symbolic link may lead only into these or the loader's own directories.
SCANNED = ("/opt/shimpz", "/usr/local", "/usr/lib")
MACHINES = {"x86_64": (62, "x86_64-linux-gnu"), "aarch64": (183, "aarch64-linux-gnu")}
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 15, 29
DT_AUDIT, DT_DEPAUDIT = 0x6FFFFEFC, 0x6FFFFEFB
NAMED = (DT_NEEDED, DT_RPATH, DT_RUNPATH)
MAX_ELF_BYTES = 1 << 30
MAX_LINKS = 32


class RefusalError(Exception):
    """One reason the image is refused."""


class Image:
    """The final filesystem at ROOT, read only as data."""

    def __init__(self, root: str, machine: int, triplet: str) -> None:
        self.root = root.rstrip("/")
        self.machine = machine
        self.system = (f"/lib/{triplet}", f"/usr/lib/{triplet}", "/lib", "/usr/lib")
        self.allowed = (*SCANNED, f"/lib/{triplet}", "/lib", "/lib64", "/usr/lib64")
        self.elves: dict[str, dict[str, object]] = {}

    def host(self, path: str) -> Path:
        return Path(self.root + path)

    def resolve(self, path: str) -> str | None:
        """Follow symbolic links inside the image; return the final path, or None when nothing is there.

        Whatever a link names must lie inside the payload or library directories, whether it exists or not.
        """
        original = path
        for _ in range(MAX_LINKS):
            parts = [part for part in path.split("/") if part and part != "."]
            current = ""
            for index, part in enumerate(parts):
                if part == "..":
                    current = current.rsplit("/", 1)[0]
                    continue
                candidate = f"{current}/{part}"
                if not self.host(candidate).is_symlink() and not self.host(candidate).exists():
                    self._admit(original, "/".join((candidate, *parts[index + 1 :])))
                    return None
                if self.host(candidate).is_symlink():
                    target = str(self.host(candidate).readlink())
                    base = target if target.startswith("/") else f"{current}/{target}"
                    rest = "/".join(parts[index + 1 :])
                    path = f"{base}/{rest}" if rest else base
                    break
                current = candidate
            else:
                final = current or "/"
                self._admit(original, final)
                return final
        raise RefusalError(f"{original} has too many symbolic links")

    def _admit(self, original: str, path: str) -> None:
        if not any(path == root or path.startswith(root + "/") for root in self.allowed):
            raise RefusalError(f"{original} leads outside the image's payload and library directories")

    def elf(self, path: str) -> dict[str, object] | None:
        """Return one regular file's ELF identity and dynamic names, or None when it is not ELF."""
        if path in self.elves:
            return self.elves[path]
        with self.host(path).open("rb") as handle:
            if handle.read(4) != b"\x7fELF":
                return None
            data = b"\x7fELF" + handle.read(MAX_ELF_BYTES)
        self.elves[path] = _parse(path, data)
        return self.elves[path]


def _parse(path: str, data: bytes) -> dict[str, object]:
    if len(data) > MAX_ELF_BYTES or len(data) < 64 or data[4] != 2 or data[5] != 1:
        raise RefusalError(f"{path} is not a little-endian 64-bit ELF file")
    (machine,) = struct.unpack_from("<H", data, 18)
    (phoff,) = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    if count and (size != 56 or phoff + count * 56 > len(data)):
        raise RefusalError(f"{path} has invalid program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56) for index in range(count)]
    if any(offset + filesz > len(data) for _, _, offset, _, _, filesz, _, _ in headers):
        raise RefusalError(f"{path} has a segment beyond its end")
    interpreter = next(
        (data[offset : offset + filesz].split(b"\0", 1)[0] for kind, _, offset, _, _, filesz, _, _ in headers
         if kind == PT_INTERP),
        None,
    )
    entries = _dynamic(data, headers)
    if {tag for tag, _ in entries} & {DT_AUDIT, DT_DEPAUDIT}:
        raise RefusalError(f"{path} declares an audit library")
    return {
        "machine": machine,
        "interpreter": None if interpreter is None else _text(path, interpreter),
        "names": _names(path, data, headers, entries),
    }


def _dynamic(data: bytes, headers: list[tuple[int, ...]]) -> list[tuple[int, int]]:
    entries: list[tuple[int, int]] = []
    for kind, _, offset, _, _, filesz, _, _ in headers:
        if kind != PT_DYNAMIC:
            continue
        for position in range(offset, offset + filesz - 15, 16):
            tag, value = struct.unpack_from("<qQ", data, position)
            if tag == DT_NULL:
                break
            entries.append((tag, value))
    return entries


def _names(path: str, data: bytes, headers: list, entries: list[tuple[int, int]]) -> dict[int, list[str]]:
    """The DT_NEEDED, DT_RPATH, and DT_RUNPATH strings, read from the string table its loaded segments map."""
    named = [(tag, value) for tag, value in entries if tag in NAMED]
    if not named:
        return {}
    address = next((value for tag, value in entries if tag == DT_STRTAB), None)
    length = next((value for tag, value in entries if tag == DT_STRSZ), 0)
    start = next(
        (address - vaddr + offset for kind, _, offset, vaddr, _, filesz, _, _ in headers
         if kind == PT_LOAD and address is not None and vaddr <= address < vaddr + filesz),
        None,
    )
    if start is None:
        raise RefusalError(f"{path} names a string table outside its loaded segments")
    strings = data[start : start + length]
    names: dict[int, list[str]] = {}
    for tag, value in named:
        if value >= len(strings):
            raise RefusalError(f"{path} names a string beyond its string table")
        names.setdefault(tag, []).append(_text(path, strings[value:].split(b"\0", 1)[0]))
    return names


def _text(path: str, raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RefusalError(f"{path} names a string that is not UTF-8") from None


def _search_path(path: str, names: dict[int, list[str]]) -> list[str]:
    """DT_RUNPATH, or DT_RPATH when there is none, with $ORIGIN expanded; any other dynamic string is refused."""
    origin = path.rsplit("/", 1)[0] or "/"
    directories = []
    for entry in ":".join(names.get(DT_RUNPATH) or names.get(DT_RPATH) or []).split(":"):
        if not entry:
            continue
        expanded = entry.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if "$" in expanded or not expanded.startswith("/"):
            raise RefusalError(f"{path} has a search path the image cannot resolve: {entry}")
        directories.append(expanded)
    return directories


def _inspect(image: Image, path: str) -> None:
    """Admit one payload entry: a link stays inside the image, and a regular file is read once as ELF or data."""
    resolved = image.resolve(path)
    if resolved is None:
        raise RefusalError(f"{path} is a dangling symbolic link")
    mode = image.host(resolved).stat().st_mode
    if stat.S_ISDIR(mode):
        return
    if not stat.S_ISREG(mode):
        raise RefusalError(f"{path} is neither a regular file, a directory, nor a link")
    image.elf(resolved)


def _loadable(image: Image, candidate: str) -> bool:
    resolved = image.resolve(candidate)
    if resolved is None or not stat.S_ISREG(image.host(resolved).stat().st_mode):
        return False
    elf = image.elf(resolved)
    return elf is not None and elf["machine"] == image.machine


def _verify(image: Image, path: str, elf: dict) -> None:
    if elf["machine"] != image.machine:
        raise RefusalError(f"{path} is built for another machine")
    interpreter = elf["interpreter"]
    if interpreter is not None and not _loadable(image, interpreter):
        raise RefusalError(f"{path} needs the missing program interpreter {interpreter}")
    directories = [*_search_path(path, elf["names"]), *image.system]
    for needed in elf["names"].get(DT_NEEDED, []):
        candidates = [needed] if "/" in needed else [f"{directory}/{needed}" for directory in directories]
        if not any(_loadable(image, candidate) for candidate in candidates):
            raise RefusalError(f"{path} needs {needed}, which the image does not provide")


def check(root: str) -> list[str]:
    """Return every finding for the image at ROOT."""
    if os.uname().machine not in MACHINES:
        return [f"unsupported build machine {os.uname().machine}"]
    image = Image(root, *MACHINES[os.uname().machine])
    findings: list[str] = []
    for scanned in SCANNED:
        for directory, subdirectories, files in os.walk(image.root + scanned):
            links = [entry for entry in subdirectories if Path(directory, entry).is_symlink()]
            for name in (*files, *links):
                try:
                    _inspect(image, f"{directory.removeprefix(image.root)}/{name}")
                except RefusalError as refusal:
                    findings.append(str(refusal))
    for path, elf in sorted(dict(image.elves).items()):
        try:
            _verify(image, path, elf)
        except RefusalError as refusal:
            findings.append(str(refusal))
    return findings


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: shimpz_library_check.py ROOT")
    findings = check(sys.argv[1])
    if findings:
        raise SystemExit("unresolved or refused ELF files:\n" + "\n".join(findings))
    print("every ELF file resolves its shared libraries")


if __name__ == "__main__":
    main()
