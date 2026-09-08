import os
import shutil
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from .container_spec import STORAGE_BYTES, STORAGE_MB, _container_uid_gid


MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_FILE_BYTES = 150 * 1024 * 1024

# Longest base64 "content" string that could still decode to a file write_bytes
# would accept: base64 expands by 4/3, so anything longer is already over the
# limit and can be refused before b64decode builds a third copy of the body.
# The slack covers the padding characters. Derived, not written out again, so
# this and the upload ceiling cannot drift apart.
MAX_UPLOAD_BASE64_CHARS = ((MAX_UPLOAD_FILE_BYTES + 2) // 3) * 4 + 1024

# One listing is rendered as a single JSON response in the panel file manager. A
# bot that drops a million files into one folder would otherwise build a body
# large enough to exhaust the agent before Flask finished serialising it.
MAX_DIRECTORY_ENTRIES = 5000


def directory_size(root):
    """Bytes used under `root`, tolerating entries that vanish mid-walk.

    st_size is read without following symlinks, so a link is charged as its own
    small entry instead of the size of its target, and a link whose target has
    been deleted no longer raises OSError out of the walk.
    """
    total = 0
    stack = [Path(root)]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                else:
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def resolve_server_path(root, relative_path):
    root = Path(root).resolve()
    candidate_text = str(relative_path or "").strip().replace("\\", "/")
    if PureWindowsPath(candidate_text).is_absolute() or candidate_text.startswith("/"):
        raise ValueError("absolute paths are not allowed")
    candidate = (root / candidate_text).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes the server directory") from exc
    return candidate


class ServerStorage:
    def __init__(self, root, *, create=False):
        self.root = Path(root).resolve()
        if create:
            self.root.mkdir(parents=True, exist_ok=True)

    def list_directory(self, path=""):
        directory = resolve_server_path(self.root, path)
        if not directory.exists():
            raise FileNotFoundError("directory does not exist")
        if not directory.is_dir():
            raise ValueError("path is not a directory")
        entries = []
        for item in sorted(directory.iterdir(), key=lambda entry: (not entry.is_dir(), entry.name.lower())):
            try:
                stat = item.stat(follow_symlinks=False)
            except OSError:
                # The bot deleted it between iterdir() and here, or it is a
                # symlink whose target is gone. Skip it rather than failing the
                # whole listing with a 500.
                continue
            is_directory = item.is_dir()
            entries.append(
                {
                    "name": item.name,
                    "path": item.relative_to(self.root).as_posix(),
                    "is_directory": is_directory,
                    "size": 0 if is_directory else stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                }
            )
            if len(entries) >= MAX_DIRECTORY_ENTRIES:
                break
        return entries

    def usage_bytes(self):
        return directory_size(self.root)

    def _check_quota(self, file_path, new_size):
        if new_size > STORAGE_BYTES:
            raise ValueError(f"file is larger than the {STORAGE_MB} MB server disk quota")
        try:
            existing = file_path.stat(follow_symlinks=False).st_size
        except OSError:
            existing = 0
        # One walk, reused for the message. directory_size recurses the whole
        # server tree, so calling it again to work out the free figure walked up
        # to 600 MB of small files a second time on the path that is already
        # failing — and against a tree the container is writing to, the two walks
        # could disagree and report a free figure inconsistent with the refusal.
        used = directory_size(self.root)
        projected = used - existing + new_size
        if projected > STORAGE_BYTES:
            free = max(0, STORAGE_BYTES - (used - existing))
            raise ValueError(
                f"server disk quota exceeded — {STORAGE_MB} MB total, "
                f"{free // (1024 * 1024)} MB free for this file"
            )

    def read_text(self, path):
        file_path = resolve_server_path(self.root, path)
        if not file_path.is_file():
            raise FileNotFoundError("file does not exist")
        if file_path.stat().st_size > MAX_TEXT_FILE_BYTES:
            raise ValueError(f"file is too large for the browser editor (max {MAX_TEXT_FILE_BYTES // (1024 * 1024)} MB)")
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("file is not UTF-8 text") from exc

    def _hand_over(self, path):
        """Chown a just-written path, and the parents created with it, to the container uid.

        The agent writes uploads as its own user, but the bot container runs as
        CONTAINER_USER, so anything written here was left unwritable by the bot
        until the next install: an upload that created its own folder gave the
        container a directory it could not add to, and `npm install` inside that
        folder died with EACCES on mkdir node_modules. ensure_owner() covers the
        whole tree, but only runs at create and install time, which is too late
        for files uploaded afterwards. Best-effort for the same reason
        ensure_owner is: the agent is not always root, and a chown failure must
        not fail the upload that triggered it. Windows has no chown at all, which
        is what the missing-attribute guard covers.
        """
        chown = getattr(os, "lchown", None) or getattr(os, "chown", None)
        if chown is None:
            return
        uid, gid = _container_uid_gid()
        if uid is None or gid is None:
            return
        target = Path(path)
        while True:
            try:
                chown(str(target), uid, gid)
            except OSError:
                pass
            if target == self.root or target.parent == target:
                return
            target = target.parent

    def _refuse_if_path_escaped(self, path):
        resolve_server_path(self.root, path)

    def write_text(self, path, content):
        if not isinstance(content, str):
            raise ValueError("content must be text")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_TEXT_FILE_BYTES:
            raise ValueError(f"file is too large for the browser editor (max {MAX_TEXT_FILE_BYTES // (1024 * 1024)} MB)")
        file_path = resolve_server_path(self.root, path)
        if file_path == self.root:
            raise ValueError("a file name is required")
        self._check_quota(file_path, len(encoded))
        self._refuse_if_path_escaped(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(encoded)
        self._hand_over(file_path)

    def write_bytes(self, path, content):
        if not isinstance(content, bytes):
            raise ValueError("content must be bytes")
        if len(content) > MAX_UPLOAD_FILE_BYTES:
            raise ValueError(f"uploaded file is larger than {MAX_UPLOAD_FILE_BYTES // (1024 * 1024)} MB")
        file_path = resolve_server_path(self.root, path)
        if file_path == self.root:
            raise ValueError("a file name is required")
        self._check_quota(file_path, len(content))
        self._refuse_if_path_escaped(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(content)
        self._hand_over(file_path)

    def create_directory(self, path):
        directory = resolve_server_path(self.root, path)
        if directory == self.root:
            raise ValueError("a directory name is required")
        directory.mkdir(parents=True, exist_ok=False)
        self._hand_over(directory)

    def delete(self, path):
        target = resolve_server_path(self.root, path)
        if target == self.root:
            raise ValueError("cannot delete the server root")
        if not target.exists():
            raise FileNotFoundError("path does not exist")
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    def remove_root(self):
        if self.root.exists():
            shutil.rmtree(self.root)

    def ensure_owner(self, uid=None, gid=None):
        """Hand the server tree to the uid its container runs as.

        Containers are started as a non-root user, so anything a root process
        left behind — files an older container wrote, or files the agent itself
        wrote while seeding — has to be handed over or the bot cannot rewrite
        its own directory. Best-effort: the agent is not always root, and a
        failure here must not fail the request that triggered it. os.walk does
        not follow symlinks and lchown does not follow the link, so a link
        pointing outside the tree cannot redirect the chown.
        """
        if os.name != "posix":
            return False
        default_uid, default_gid = _container_uid_gid()
        uid = default_uid if uid is None else uid
        gid = default_gid if gid is None else gid
        if uid is None or gid is None:
            return False
        chown = getattr(os, "lchown", os.chown)
        complete = True
        try:
            chown(str(self.root), uid, gid)
        except OSError:
            complete = False
        for directory, subdirectories, files in os.walk(self.root, followlinks=False):
            for name in list(subdirectories) + list(files):
                try:
                    chown(os.path.join(directory, name), uid, gid)
                except OSError:
                    complete = False
        return complete
