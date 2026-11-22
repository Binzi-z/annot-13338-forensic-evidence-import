"""Windows path alias handling and physical file identity.

Two different *names* may denote the same file:

* case differences           ``C:\\Cases\\A.EVD`` == ``c:\\cases\\a.evd``
* separators                ``C:/Cases/A.EVD``  == ``C:\\Cases\\A.EVD``
* 8.3 short names           ``C:\\PROGRA~1``     == ``C:\\Program Files``
* trailing dots / spaces     ``A.EVD. ``         == ``A.EVD``   (Win32 strips these)
* hard links / junctions, symlinks, same file via different directory spellings.

``name_key`` produces a normalised textual key for quote-time alias grouping
(no filesystem access, deterministic on any platform). ``file_identity``
returns the OS-level identity (volume serial + file index) so that even a
hard link under a totally different name is recognised as the same bytes.
"""

from __future__ import annotations

import os
import re

_SEP_RE = re.compile(r"[\\/]+")
_DRIVE_RE = re.compile(r"^(?P<d>[a-zA-Z]):(?P<rest>.*)$")


def _strip_win32_name(part: str) -> str:
    # Win32 silently drops trailing dots and spaces from each component.
    return part.rstrip(" .")


def name_key(path: str) -> str:
    """Stable, case-folded, separator-normalised textual key for *path*.

    Purely lexical: never touches the filesystem, so it is reproducible in a
    minimal-repro bundle and on any host OS.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    p = path.strip()
    unc = p.startswith("\\\\") or p.startswith("//")
    p = _SEP_RE.sub(lambda _m: "\\", p)
    drive = ""
    m = _DRIVE_RE.match(p)
    if m:
        drive = m.group("d").lower() + ":"
        p = m.group("rest")
    if p.startswith("\\"):
        p = p[1:]
    parts = [x for x in p.split("\\") if x not in ("", ".")]
    resolved: list[str] = []
    for comp in parts:
        if comp == "..":
            if resolved:
                resolved.pop()
            continue
        comp = _strip_win32_name(comp)
        if comp:
            resolved.append(comp)
    body = "\\".join(resolved).casefold()
    if unc:
        return "\\\\" + body
    return drive + "\\" + body


def name_aliases(a: str, b: str) -> bool:
    """True when the two path spellings are lexically the same Windows path."""
    return name_key(a) == name_key(b)


def file_identity(path: str) -> tuple[int, int] | None:
    """OS identity ``(volume_serial, file_index)`` or ``None`` if absent.

    On Windows ``st_dev`` is the volume serial number and ``st_ino`` is the
    NTFS file index, both shared by every hard link / 8.3 alias of the file.
    We stat without following a final reparse point so that a symlink and its
    target are reported as distinct *names* while a hard link (same index) is
    recognised as the same file.
    """
    try:
        st = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError):
        return None
    if st.st_ino == 0:
        return None
    return (int(st.st_dev), int(st.st_ino))


def same_file(a: str, b: str) -> bool:
    """True if *a* and *b* denote the same physical file (alias or identity)."""
    if name_aliases(a, b):
        return True
    ia = file_identity(a)
    ib = file_identity(b)
    return ia is not None and ia == ib
