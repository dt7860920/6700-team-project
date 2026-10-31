"""Workspace archives: how an ingested snapshot travels into (and is restored inside) a jail.

The Executor and the ONO app are separate containers that share no filesystem, so a
workspace is shipped as a **gzipped tar** (``pack_workspace``), validated on the
trusted side (``validate_archive``), and extracted *inside* the jail by ``tar``
running as the sandbox user. The same bytes are kept as the clean snapshot that
``reset()`` restores from.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

SANDBOX_UID = 10001
"""Uid/gid the untrusted code runs as (and that owns the workspace tmpfs)."""

_SKIP_DIRS = frozenset({".git"})


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


def validate_archive(data: bytes, *, max_bytes: int, max_members: int = 200_000) -> int:
    """Check an uploaded archive before it goes anywhere near a container.

    Returns the uncompressed size. Rejects: non-gzip-tar input, absolute / ``..`` member
    names, symlinks and special files, more than ``max_members`` members, and
    uncompressed content above ``max_bytes`` (decompression bombs are stopped early
    because sizes are summed from headers while streaming).
    """
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
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
