"""No-follow file access and atomic output helpers."""

from __future__ import annotations

import errno
import os
import secrets
import stat
import tempfile
from pathlib import Path

from .errors import SecurityError, ValidationError


def _open_nofollow(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise SecurityError(f"symbolic links are forbidden: {path}") from exc
        raise
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise SecurityError(f"not a regular file: {path}")
    if not hasattr(os, "O_NOFOLLOW"):
        try:
            before = os.stat(path, follow_symlinks=False)
        except OSError:
            os.close(fd)
            raise
        if stat.S_ISLNK(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            raise SecurityError(f"unsafe file identity: {path}")
    return fd


def read_regular_file(path: str | Path, *, max_bytes: int) -> bytes:
    target = Path(path)
    fd = _open_nofollow(target)
    try:
        info = os.fstat(fd)
        if info.st_size > max_bytes:
            raise ValidationError(f"file exceeds {max_bytes} bytes: {target}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValidationError(f"file exceeds {max_bytes} bytes: {target}")
        return data
    finally:
        os.close(fd)


def read_secret_file(path: str | Path, *, max_bytes: int) -> bytes:
    target = Path(path)
    fd = _open_nofollow(target)
    try:
        info = os.fstat(fd)
        if os.name == "posix":
            if info.st_uid != os.geteuid():
                raise SecurityError(f"secret file must be owned by the current user: {target}")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise SecurityError(f"secret file must not be accessible by group or others: {target}")
        if info.st_size > max_bytes:
            raise ValidationError(f"secret file exceeds {max_bytes} bytes")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(65_536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise ValidationError(f"secret file exceeds {max_bytes} bytes")
        return bytes(data)
    finally:
        os.close(fd)


def atomic_write(path: str | Path, data: bytes, *, mode: int = 0o600) -> None:
    target = Path(path)
    if not isinstance(data, bytes):
        raise ValidationError("atomic_write data must be bytes")
    if not target.parent.exists():
        raise ValidationError("atomic output parent must already exist")
    if os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
        parent = target.parent.absolute()
        directory_fd = os.open(parent.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temp_name: str | None = None
        fd: int | None = None
        try:
            for part in parent.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            try:
                existing = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
                raise SecurityError(f"refusing non-regular or symlink output: {target}")
            for _ in range(16):
                candidate = f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}"
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory_fd)
                    temp_name = candidate
                    break
                except FileExistsError:
                    continue
            if fd is None or temp_name is None:
                raise SecurityError("could not reserve a private atomic output")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short atomic output write")
                view = view[written:]
            os.fsync(fd)
            os.close(fd); fd = None
            # Both names are resolved against the already-open directory, so an
            # ancestor rename cannot redirect the write to another tree.
            os.replace(temp_name, target.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temp_name = None
            os.fsync(directory_fd)
            return
        except OSError as exc:
            if isinstance(exc, SecurityError):
                raise
            raise SecurityError(f"atomic output path is unsafe or inaccessible: {target}") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            os.close(directory_fd)

    # Windows/Python 3.11 does not expose the full reparse-point-safe directory
    # handle API. The fallback still rejects a visible final symlink and uses an
    # atomic same-directory replace; hostile junction races are documented.
    if target.exists() and target.is_symlink():
        raise SecurityError(f"refusing symlink output: {target}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and target.is_symlink():
            raise SecurityError(f"refusing symlink output: {target}")
        os.replace(temp_name, target)
        if os.name == "posix":
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
