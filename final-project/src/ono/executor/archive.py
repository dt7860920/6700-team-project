"""Workspace archives: how an ingested snapshot travels into (and is restored inside) a jail.

The Executor and the ONO app are separate containers that share no filesystem, so a
workspace is shipped as a **gzipped tar** (``pack_workspace``), validated on the
trusted side (``validate_archive``), and extracted *inside* the jail by ``tar``
running as the sandbox user.

On the Executor the archive never lives in RAM: the upload is spooled straight to a
file, validated by streaming that file, and the same file is kept - as a
:class:`Snapshot` - for ``reset()`` to stream back into a fresh jail. A ``Snapshot``
can only be produced by :meth:`Snapshot.validate`, so holding one *is* the proof that
``validate_archive`` accepted the bytes (the invariant the in-jail ``tar`` relies on).
"""

from __future__ import annotations

import contextlib
import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Self

SANDBOX_UID = 10001
"""Uid/gid the untrusted code runs as (and that owns the workspace tmpfs)."""

_SKIP_DIRS = frozenset({".git"})
SPOOL_CHUNK_BYTES = 64 * 1024
"""Granularity at which archives are copied between a socket, a file and a jail."""


class ArchiveError(ValueError):
    """The archive is not a usable workspace snapshot (too big, not a tar, bad members)."""


def pack_workspace(root: Path, *, max_bytes: int) -> bytes:
    """Tar+gzip a local directory for shipping into a sandbox.

    Regular files and directories only (symlinks, sockets, devices are skipped - ingest
    already copies snapshots without symlinks); ``.git`` is never included; ownership is
    rewritten to the sandbox uid so the files are writable inside the jail. Raises
    :class:`ArchiveError` when the uncompressed tree exceeds ``max_bytes``.
    """
    root = root.resolve()
    if not root.is_dir():
        raise ArchiveError(f"workspace {root} is not a directory")
    buf = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            here = Path(dirpath)
            if here != root:
                tar.addfile(_dir_info(here.relative_to(root).as_posix()))
            for name in sorted(filenames):
                path = here / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if path.is_symlink() or not path.is_file():  # skip links & specials
                    continue
                total += st.st_size
                if total > max_bytes:
                    raise ArchiveError(f"workspace exceeds {max_bytes} bytes; refusing to pack it")
                info = tarfile.TarInfo(path.relative_to(root).as_posix())
                info.size = st.st_size
                info.mtime = int(st.st_mtime)
                info.mode = 0o755 if st.st_mode & 0o100 else 0o644
                info.uid = info.gid = SANDBOX_UID
                with path.open("rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def _dir_info(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = SANDBOX_UID
    return info


def validate_archive(
    source: bytes | Path | IO[bytes], *, max_bytes: int, max_members: int = 200_000
) -> int:
    """Check an archive before it goes anywhere near a container.

    ``source`` is the archive as bytes, a path to it, or an open (seekable) binary file.
    Returns the uncompressed size. Rejects: non-gzip-tar input, absolute / ``..`` member
    names, symlinks and special files, more than ``max_members`` members, and
    uncompressed content above ``max_bytes`` (decompression bombs are stopped early
    because sizes are summed from headers while streaming - member *data* is never
    loaded, so validating a file costs a few KB of RAM however large the archive is).
    """
    with contextlib.ExitStack() as stack:
        if isinstance(source, bytes):
            fileobj: IO[bytes] = io.BytesIO(source)
        elif isinstance(source, Path):
            try:
                fileobj = stack.enter_context(source.open("rb"))
            except OSError as exc:
                raise ArchiveError(f"cannot read archive: {exc}") from exc
        else:
            fileobj = source
        return _validate_stream(fileobj, max_bytes=max_bytes, max_members=max_members)


def _validate_stream(fileobj: IO[bytes], *, max_bytes: int, max_members: int) -> int:
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=fileobj, mode="r:gz") as tar:
            for member in tar:
                count += 1
                if count > max_members:
                    raise ArchiveError(f"archive has more than {max_members} members")
                name = member.name
                if name.startswith("/") or "\\" in name or ".." in name.split("/"):
                    raise ArchiveError(f"archive member has an unsafe name: {name!r}")
                if not (member.isfile() or member.isdir()):
                    raise ArchiveError(
                        f"archive member {name!r} is not a regular file or directory"
                    )
                total += member.size
                if total > max_bytes:
                    raise ArchiveError(f"archive expands to more than {max_bytes} bytes")
    except ArchiveError:
        raise
    except tarfile.TarError as exc:
        raise ArchiveError(f"not a valid gzipped tar archive: {exc}") from exc
    except (EOFError, OSError, ValueError) as exc:  # truncated / corrupt gzip streams
        raise ArchiveError(f"not a valid gzipped tar archive: {exc}") from exc
    return total


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A validated workspace archive kept **on disk** for ``reset()``.

    Never construct one directly: :meth:`validate` is the single constructor and it
    always runs :func:`validate_archive` first. The Executor therefore never streams an
    archive into a jail's ``tar`` that did not pass validation - that is the invariant
    the in-container extraction depends on (``tar`` itself would honour ``..`` names).
    """

    path: Path
    size_bytes: int
    """Compressed size as stored - the bytes this snapshot retains on disk."""
    expanded_bytes: int
    """Uncompressed size, summed from the tar headers during validation."""

    @classmethod
    def validate(cls, path: Path, *, max_bytes: int, max_members: int = 200_000) -> Self:
        """Validate the archive at ``path`` and wrap it. Raises :class:`ArchiveError`."""
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ArchiveError(f"cannot read archive: {exc}") from exc
        if size == 0:
            raise ArchiveError("archive is empty")
        if size > max_bytes:
            raise ArchiveError(f"archive is larger than {max_bytes} bytes")
        expanded = validate_archive(path, max_bytes=max_bytes, max_members=max_members)
        return cls(path=path, size_bytes=size, expanded_bytes=expanded)

    def open(self) -> IO[bytes]:
        """The archive bytes as a stream (for ``tar -x`` over exec stdin)."""
        return self.path.open("rb")

    def remove(self) -> None:
        """Delete the on-disk copy. Idempotent, never raises."""
        with contextlib.suppress(OSError):
            self.path.unlink()
