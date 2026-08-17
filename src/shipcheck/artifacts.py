"""Safe artifact hashing and bounded archive manifest inspection."""

from __future__ import annotations

import hashlib
import os
import stat
import tarfile
import tempfile
import struct
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from .errors import SecurityError, ValidationError
from .risk import normalize_repo_path

MAX_ARTIFACT_BYTES = 2_147_483_648
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_EXPANDED = 536_870_912
MAX_ARCHIVE_FILE_BYTES = 268_435_456
MAX_ZIP_CENTRAL_DIRECTORY = 33_554_432


def _zip_preflight(handle: BinaryIO, *, max_entries: int, size: int) -> None:
    tail_size = min(size, 65_557)
    handle.seek(size - tail_size)
    tail = handle.read(tail_size)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ValidationError("ZIP end-of-central-directory record is missing")
    _, disk, central_disk, disk_entries, total_entries, central_size, central_offset, comment_length = struct.unpack_from("<4s4H2LH", tail, offset)
    if disk or central_disk or disk_entries != total_entries:
        raise ValidationError("multi-disk ZIP archives are unsupported")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ValidationError("ZIP64 archives are unsupported by the bounded inspector")
    if total_entries > max_entries or central_size > MAX_ZIP_CENTRAL_DIRECTORY:
        raise ValidationError("ZIP metadata exceeds inspector bounds")
    if central_offset + central_size > size or offset + 22 + comment_length > len(tail):
        raise ValidationError("ZIP central directory offsets are invalid")
    handle.seek(0)


def _open_beneath(root: str | Path, relative_path: str) -> tuple[int, str]:
    root_path = Path(root)
    normalized = normalize_repo_path(relative_path)
    if not root_path.is_dir() or root_path.is_symlink():
        raise SecurityError("artifact root must be a real directory")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        target = root_path.joinpath(*normalized.split("/"))
        current = root_path
        for part in normalized.split("/"):
            current /= part
            try:
                if current.is_symlink():
                    raise SecurityError(f"symlink artifact path is forbidden: {relative_path}")
            except OSError as exc:
                raise SecurityError("artifact path cannot be inspected safely") from exc
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise SecurityError("artifact must be a regular file")
        return fd, normalized

    directory_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = normalized.split("/")
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(parts[-1], flags, dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise SecurityError("artifact must be a regular file")
        return fd, normalized
    except OSError as exc:
        raise SecurityError(f"artifact path is unsafe or inaccessible: {relative_path}") from exc
    finally:
        os.close(directory_fd)


def _digest_stream(handle: BinaryIO, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(65_536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValidationError(f"artifact exceeds {max_bytes} bytes")
        digest.update(chunk)
    return digest.hexdigest(), total


def hash_artifact(root: str | Path, relative_path: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict[str, Any]:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_ARTIFACT_BYTES:
        raise ValidationError("max_bytes is outside supported bounds")
    fd, normalized = _open_beneath(root, relative_path)
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            digest, size = _digest_stream(handle, max_bytes=max_bytes)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return {"name": Path(normalized).name, "path": normalized, "digest": digest, "size_bytes": size, "algorithm": "sha256"}


def inspect_archive(
    root: str | Path,
    relative_path: str,
    *,
    max_entries: int = MAX_ARCHIVE_ENTRIES,
    max_expanded_bytes: int = MAX_ARCHIVE_EXPANDED,
) -> dict[str, Any]:
    if type(max_entries) is not int or not 1 <= max_entries <= MAX_ARCHIVE_ENTRIES:
        raise ValidationError("max_entries is outside supported bounds")
    if type(max_expanded_bytes) is not int or not 1 <= max_expanded_bytes <= MAX_ARCHIVE_EXPANDED:
        raise ValidationError("max_expanded_bytes is outside supported bounds")
    fd, normalized = _open_beneath(root, relative_path)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    try:
        with os.fdopen(fd, "rb", closefd=True) as source, tempfile.TemporaryFile(mode="w+b") as handle:
            artifact_hasher = hashlib.sha256()
            artifact_size = 0
            while True:
                chunk = source.read(65_536)
                if not chunk:
                    break
                artifact_size += len(chunk)
                if artifact_size > MAX_ARCHIVE_FILE_BYTES:
                    raise ValidationError("archive artifact exceeds maximum size")
                artifact_hasher.update(chunk)
                handle.write(chunk)
            handle.flush()
            handle.seek(0)
            artifact = {"name": Path(normalized).name, "path": normalized, "digest": artifact_hasher.hexdigest(), "size_bytes": artifact_size, "algorithm": "sha256"}
            if zipfile.is_zipfile(handle):
                handle.seek(0)
                _zip_preflight(handle, max_entries=max_entries, size=artifact_size)
                try:
                    archive_context = zipfile.ZipFile(handle)
                except (zipfile.BadZipFile, OSError, NotImplementedError) as exc:
                    raise ValidationError("ZIP archive metadata is invalid or unsupported") from exc
                with archive_context as archive:
                    infos = archive.infolist()
                    if len(infos) > max_entries:
                        raise ValidationError("archive entry count exceeds policy")
                    for info in infos:
                        path = normalize_repo_path(info.filename)
                        mode = (info.external_attr >> 16) & 0xFFFF
                        file_type = stat.S_IFMT(mode)
                        if info.is_dir():
                            if file_type not in {0, stat.S_IFDIR}:
                                raise SecurityError(f"ambiguous ZIP directory entry is forbidden: {path}")
                            collision_key = path.casefold()
                            if collision_key in seen:
                                raise ValidationError(f"duplicate archive entry: {path}")
                            seen.add(collision_key)
                            continue
                        if file_type not in {0, stat.S_IFREG}:
                            raise SecurityError(f"non-regular ZIP entry is forbidden: {path}")
                        if info.flag_bits & 0x1:
                            raise SecurityError("encrypted archive entries are unsupported")
                        collision_key = path.casefold()
                        if collision_key in seen:
                            raise ValidationError(f"duplicate archive entry: {path}")
                        seen.add(collision_key)
                        total += info.file_size
                        if total > max_expanded_bytes:
                            raise ValidationError("archive expanded size exceeds policy")
                        if info.compress_size == 0 and info.file_size > 0 or info.compress_size and info.file_size / info.compress_size > 1_000:
                            raise ValidationError("archive compression ratio exceeds policy")
                        try:
                            with archive.open(info, "r") as item:
                                digest, actual = _digest_stream(item, max_bytes=min(info.file_size + 1, max_expanded_bytes))
                        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
                            raise ValidationError(f"ZIP entry is invalid or unsupported: {path}") from exc
                        if actual != info.file_size:
                            raise ValidationError(f"archive entry size mismatch: {path}")
                        entries.append({"path": path, "digest": digest, "size_bytes": actual, "type": "file"})
                archive_type = "zip"
            else:
                handle.seek(0)
                try:
                    archive = tarfile.open(fileobj=handle, mode="r|*")
                except tarfile.TarError as exc:
                    raise ValidationError("artifact is not a supported ZIP or TAR archive") from exc
                with archive:
                    member_count = 0
                    for member in archive:
                        member_count += 1
                        if member_count > max_entries:
                            raise ValidationError("archive entry count exceeds policy")
                        path = normalize_repo_path(member.name)
                        if member.isdir():
                            collision_key = path.casefold()
                            if collision_key in seen:
                                raise ValidationError(f"duplicate archive entry: {path}")
                            seen.add(collision_key)
                            continue
                        if not member.isfile():
                            raise SecurityError(f"non-regular TAR entry is forbidden: {path}")
                        collision_key = path.casefold()
                        if collision_key in seen:
                            raise ValidationError(f"duplicate archive entry: {path}")
                        seen.add(collision_key)
                        total += member.size
                        if total > max_expanded_bytes:
                            raise ValidationError("archive expanded size exceeds policy")
                        item = archive.extractfile(member)
                        if item is None:
                            raise ValidationError(f"archive entry cannot be read: {path}")
                        with item:
                            digest, actual = _digest_stream(item, max_bytes=min(member.size + 1, max_expanded_bytes))
                        if actual != member.size:
                            raise ValidationError(f"archive entry size mismatch: {path}")
                        entries.append({"path": path, "digest": digest, "size_bytes": actual, "type": "file"})
                archive_type = "tar"
    except (tarfile.TarError, EOFError) as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ValidationError("TAR archive is truncated, invalid, or unsupported") from exc
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return {"schema_version": "shipcheck/archive-v1", "artifact": artifact, "archive_type": archive_type, "entry_count": len(entries), "expanded_size_bytes": total, "files": sorted(entries, key=lambda item: item["path"])}
