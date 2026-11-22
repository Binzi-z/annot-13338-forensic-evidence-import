"""Filesystem helpers: durable atomic writes, fsync, cross-process locking.

All durable-state mutations are: write temp -> fsync file -> ``os.replace`` ->
fsync parent directory. On Windows ``os.replace`` maps to ``MoveFileEx`` with
``MOVEFILE_REPLACE_EXISTING`` and is atomic on the same volume, which is the
guarantee the index-commit protocol relies on.
"""

from __future__ import annotations

import json
import os
import time

from .canonical import canonical_bytes
from .errors import LockTimeout

if os.name == "nt":  # pragma: no cover - exercised on Windows CI
    import msvcrt
else:  # pragma: no cover
    import fcntl


def _fsync_dir(path: str) -> None:
    if os.name == "nt":
        return  # directories cannot be fsync'd on Windows
    try:  # pragma: no cover
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:  # pragma: no cover
        pass


def fsync_file(path: str) -> None:
    fd = os.open(path, os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: str, data: bytes) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{time.time_ns()}"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(d)


def atomic_write_json(path: str, obj) -> None:
    atomic_write_bytes(path, canonical_bytes(obj) + b"\n")


def read_json(path: str):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


class FileLock:
    """Exclusive advisory lock via a lock file (works across processes).

    On Windows we lock the first byte of the lock file with ``msvcrt.locking``
    (mandatory, whole-system).  The file is opened unbuffered with ``os.open``
    and *seeded with one byte* when empty: locking a byte range that lies beyond
    EOF is not reliably exclusive on every Windows build, but locking an actual
    existing byte is.  On POSIX we use ``flock``.
    """

    def __init__(self, path: str, timeout: float = 30.0, poll: float = 0.02):
        self.path = path
        self.timeout = timeout
        self.poll = poll
        self._fd: int | None = None

    def acquire(self) -> "FileLock":
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
        except OSError:
            pass
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._lock(fd)
                self._fd = fd
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockTimeout(f"could not lock {self.path}")
                time.sleep(self.poll)

    def _lock(self, fd: int) -> None:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(self, fd: int) -> None:
        try:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:  # pragma: no cover
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass

    def release(self) -> None:
        if self._fd is not None:
            self._unlock(self._fd)
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()


def pid_alive(pid: int) -> bool:
    """Best-effort liveness probe for a writer pid (Windows + POSIX)."""
    if pid <= 0:
        return False
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        # Use OpenProcess via ctypes; avoids ctypes.wintypes import cost.
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return True
        finally:
            kernel32.CloseHandle(h)
    else:  # pragma: no cover
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
