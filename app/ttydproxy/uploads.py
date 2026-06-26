"""Save images pasted/dropped into the web terminal to disk."""
import os
import pwd
import secrets
import time

# Magic-byte signatures drive both validation and the saved extension; the
# client-supplied Content-Type and filename are never trusted. SVG is
# deliberately excluded (script-bearing format).
_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
)

# How many times to regenerate the random filename on an O_EXCL collision before
# giving up. The name is a per-second timestamp plus 32 bits of randomness, so a
# collision needs the same second AND the same nonce — astronomically unlikely;
# a handful of attempts is plenty (B5).
_MAX_NAME_ATTEMPTS = 5


def detect_image_extension(data):
    """Return the file extension for known image magic bytes, else None."""
    for signature, extension in _SIGNATURES:
        if data.startswith(signature):
            return extension
    if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"
    return None


def _lookup_owner_ids(username):
    """Return (uid, gid) for username, or None if it can't be resolved.

    The proxy may run unprivileged in dev/test, where the owner doesn't exist;
    callers treat None as "skip chown".
    """
    try:
        record = pwd.getpwnam(username)
    except KeyError:
        return None
    return record.pw_uid, record.pw_gid


def _fchown_best_effort(fd, ids):
    """chown an open fd to ids=(uid, gid); ignore errors (unprivileged dev/test)."""
    if ids is None:
        return
    try:
        os.fchown(fd, ids[0], ids[1])
    except OSError:
        pass


def _open_upload_dir_nofollow(upload_dir, ids):
    """Open upload_dir as a directory fd without following symlinks anywhere.

    upload_dir must already be absolute (save_upload normalizes it).
    Returns an fd for upload_dir, creating missing levels as needed. The walk
    starts from the deepest already-existing ancestor (which the proxy did not
    create — e.g. /home/hapi) and descends one component at a time. Both the
    anchor open and each descent step use O_NOFOLLOW, so a symlink planted in
    the anchor (TOCTOU swap) or ANY component below it raises OSError instead
    of letting the privileged process escape the tree. Newly created levels are
    chowned to ids; pre-existing ancestors are left untouched. Caller must
    os.close the result.
    """
    path = upload_dir
    # Split into the deepest existing prefix + the components we must descend
    # (and create). The islink() check keeps a symlinked component in `missing`
    # even when isdir() would follow it, so O_NOFOLLOW still rejects it below.
    missing = []
    while not os.path.isdir(path) or os.path.islink(path):
        parent, comp = os.path.split(path)
        if not comp or parent == path:
            # Reached the filesystem root without an existing directory; let the
            # normal open below surface the error.
            break
        missing.append(comp)
        path = parent
    missing.reverse()

    # O_NOFOLLOW on the anchor too: the deepest existing ancestor was a real
    # directory when the walk computed it, but an attacker can swap it for a
    # symlink before this open (TOCTOU). It only constrains the final path
    # component, so legitimate symlinked prefixes (e.g. /var -> /private/var)
    # are unaffected — the anchor itself must be a real directory.
    parent_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        for comp in missing:
            try:
                child_fd = os.open(
                    comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd
                )
            except FileNotFoundError:
                # No atomic create-or-open for directories; mkdir then re-open
                # relative to parent_fd. The parent fd is pinned to an inode we
                # already opened with O_NOFOLLOW, so a symlink can't be swapped
                # in underneath us between mkdir and open.
                created = True
                try:
                    os.mkdir(comp, dir_fd=parent_fd)
                except FileExistsError:
                    # A concurrent upload created it first (5 parallel uploads
                    # per gesture race here on a fresh/just-cleaned dir). The
                    # O_NOFOLLOW re-open below still rejects a planted symlink,
                    # so just adopt the existing directory without chowning it.
                    created = False
                child_fd = os.open(
                    comp, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd
                )
                if created:
                    _fchown_best_effort(child_fd, ids)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def save_upload(data, upload_dir, owner):
    """Write image bytes to a generated path under upload_dir; return the path.

    The proxy may run as root while upload_dir lives under the terminal user's
    home, so the path is attacker-controlled: the user can replace upload_dir,
    or any parent component of it, with a symlink between calls. To keep the
    privileged chown/write from following such a link, the directory is reached
    via a component-by-component O_NOFOLLOW descent (see
    _open_upload_dir_nofollow) and every privileged operation is bound to a
    directory/file fd (an inode), never re-resolved from the string path. A
    symlink anywhere in the path raises OSError instead of escaping the tree.
    All of this hardening matters only in root mode; if root mode is ever
    dropped, it can collapse to os.makedirs + an O_EXCL open.
    """
    extension = detect_image_extension(data)
    if extension is None:
        raise ValueError("Unsupported image type")
    upload_dir = os.path.abspath(upload_dir)
    # chown matters only in root mode; an unprivileged proxy creates entries
    # with the right owner already, so skip the per-request passwd lookup.
    ids = _lookup_owner_ids(owner) if os.geteuid() == 0 else None
    # The cleanup dashboard can delete the whole directory at any time, so
    # recreate it (and any missing parents) on every save.
    dir_fd = _open_upload_dir_nofollow(upload_dir, ids)
    try:
        # Bounded retry: a generated-name collision (O_EXCL FileExistsError —
        # a token_hex collision in the same second, or a pre-created
        # predictable-prefix name) regenerates a fresh suffix rather than
        # failing the upload (B5). The O_EXCL/O_NOFOLLOW atomicity is preserved.
        for _ in range(_MAX_NAME_ATTEMPTS):
            name = f"img-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.{extension}"
            # Resolve `name` relative to the open directory inode (dir_fd), not
            # by walking upload_dir again; O_EXCL keeps the "xb" semantics and
            # O_NOFOLLOW rejects a symlink someone planted under that name.
            try:
                file_fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=dir_fd,
                )
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError(
                f"could not allocate a unique upload filename after {_MAX_NAME_ATTEMPTS} attempts"
            )
        try:
            _fchown_best_effort(file_fd, ids)
            with open(file_fd, "wb", closefd=False) as upload_file:
                upload_file.write(data)
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)
    return os.path.join(upload_dir, name)
