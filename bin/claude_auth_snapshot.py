"""Build and compare redacted Claude Code authentication snapshots.

The shell entrypoint owns CLI argument handling and snapshot-path orchestration;
this stdlib-only module owns the importable JSON and diff behavior.
"""

from __future__ import annotations

import datetime
import grp
import hashlib
import json
import os
import pwd
import shutil
import socket
import ssl
import stat
import subprocess
from pathlib import Path


DEFAULT_CLAUDE_CONFIG_DIR = "/home/hapi/.claude"
DEFAULT_SNAPSHOT_DIR = "/home/hapi/.hapi/auth-snapshots"


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def iso_z(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def name_for_uid(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def name_for_gid(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def hapi_identity():
    try:
        user = pwd.getpwnam("hapi")
    except KeyError:
        return None
    gids = {user.pw_gid}
    for group in grp.getgrall():
        if "hapi" in group.gr_mem:
            gids.add(group.gr_gid)
    return {"uid": user.pw_uid, "gids": gids}


def writable_by_hapi(path, mode, st):
    ident = hapi_identity()
    if ident is None:
        return None
    if st.st_uid == ident["uid"]:
        return bool(mode & stat.S_IWUSR)
    if st.st_gid in ident["gids"]:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def path_meta(path):
    path = Path(path)
    exists = path.exists()
    if not os.path.lexists(path):
        return {
            "path": str(path),
            "exists": False,
            "owner": None,
            "mode": None,
            "mtime": None,
            "is_symlink": False,
            "writable_by_hapi": None,
        }
    try:
        st = path.stat()
    except OSError as exc:
        return {
            "path": str(path),
            "exists": exists,
            "owner": None,
            "mode": None,
            "mtime": None,
            "is_symlink": path.is_symlink(),
            "writable_by_hapi": None,
            "error": exc.__class__.__name__,
        }
    mode = stat.S_IMODE(st.st_mode)
    return {
        "path": str(path),
        "exists": True,
        "owner": f"{name_for_uid(st.st_uid)}:{name_for_gid(st.st_gid)}",
        "mode": f"{mode:o}",
        "mtime": int(st.st_mtime),
        "is_symlink": path.is_symlink(),
        "writable_by_hapi": writable_by_hapi(path, mode, st),
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_credentials(credentials_path, now_ms):
    meta = {
        "path": str(credentials_path),
        "has_credentials": credentials_path.is_file(),
        "sha256": None,
        "mtime": None,
        "oauth": {
            "expiresAt": None,
            "expires_in_minutes": None,
            "is_expired": None,
            "scopes": [],
            "subscriptionType": None,
        },
    }
    if not credentials_path.is_file():
        return meta

    try:
        st = credentials_path.stat()
        meta["sha256"] = file_sha256(credentials_path)
        meta["mtime"] = int(st.st_mtime)
    except OSError as exc:
        meta["read_error"] = exc.__class__.__name__
        return meta

    try:
        raw = json.loads(credentials_path.read_text())
    except Exception as exc:  # noqa: BLE001 - diagnostic should not fail hard
        meta["parse_error"] = exc.__class__.__name__
        return meta

    oauth = raw.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        meta["oauth_error"] = "claudeAiOauth missing or not an object"
        return meta

    expires_at = oauth.get("expiresAt")
    # Only explicitly shaped scalars can enter a snapshot. In particular, do
    # not copy nested values that could conceal tokens after a schema change.
    raw_scopes = oauth.get("scopes")
    scopes = (
        [scope for scope in raw_scopes if isinstance(scope, str)]
        if isinstance(raw_scopes, list)
        else []
    )
    raw_subscription = oauth.get("subscriptionType")
    subscription_type = (
        raw_subscription
        if isinstance(raw_subscription, (str, type(None)))
        else None
    )
    meta["oauth"] = {
        "expiresAt": expires_at if isinstance(expires_at, int) else None,
        "expires_in_minutes": (
            int((expires_at - now_ms) / 60000)
            if isinstance(expires_at, int)
            else None
        ),
        "is_expired": expires_at <= now_ms if isinstance(expires_at, int) else None,
        "scopes": scopes,
        "subscriptionType": subscription_type,
    }
    return meta


def uptime_seconds():
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except Exception:  # noqa: BLE001
        try:
            result = subprocess.run(
                ["uptime"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            return result.stdout.strip() or None
        except Exception:  # noqa: BLE001
            return None


def anthropic_check():
    result = {
        "url": "https://api.anthropic.com/",
        "ok": False,
        "http_code": None,
        "method": None,
        "error": None,
    }
    curl = shutil.which("curl")
    if curl:
        try:
            proc = subprocess.run(
                [
                    curl,
                    "-sS",
                    "-m",
                    "5",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "https://api.anthropic.com/",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=7,
            )
            code = proc.stdout.strip()
            result.update(
                {
                    "method": "curl",
                    "http_code": code or None,
                    "ok": proc.returncode == 0 and bool(code) and code != "000",
                }
            )
            if proc.returncode != 0:
                result["error"] = (proc.stderr or "").strip()[:200] or "curl failed"
            return result
        except Exception as exc:  # noqa: BLE001
            result.update({"method": "curl", "error": exc.__class__.__name__})
            return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection(("api.anthropic.com", 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="api.anthropic.com"):
                pass
        result.update({"method": "tcp_tls", "ok": True})
    except Exception as exc:  # noqa: BLE001
        result.update({"method": "tcp_tls", "error": exc.__class__.__name__})
    return result


def build_snapshot(*, now=None, environ=None):
    """Return the version-1 redacted snapshot using the supplied environment."""
    environ = os.environ if environ is None else environ
    now = utc_now() if now is None else now
    now_ms = int(now.timestamp() * 1000)
    claude_dir = Path(environ.get("CLAUDE_CONFIG_DIR", DEFAULT_CLAUDE_CONFIG_DIR))
    credentials_path = claude_dir / ".credentials.json"
    hapi_home = (
        claude_dir.parent
        if claude_dir.name == ".claude"
        else Path(environ.get("HOME", "/home/hapi"))
    )

    settings = claude_dir / "settings.json"
    settings_local = claude_dir / "settings.local.json"
    projects = claude_dir / "projects"
    statsig = claude_dir / "statsig"
    claude_json = hapi_home / ".claude.json"

    return {
        "schema_version": 1,
        "kind": "claude-auth-snapshot",
        "label": environ.get("CLAUDE_AUTH_SNAPSHOT_LABEL") or None,
        "created_at": iso_z(now),
        "now_ms": now_ms,
        "process": {
            "user": name_for_uid(os.getuid()),
            "uid": os.getuid(),
            "claude_config_dir": str(claude_dir),
            "snapshot_dir": environ.get(
                "CLAUDE_AUTH_SNAPSHOT_DIR", DEFAULT_SNAPSHOT_DIR
            ),
        },
        "credentials": read_credentials(credentials_path, now_ms),
        "permissions": {
            "claude_dir": path_meta(claude_dir),
            "credentials": path_meta(credentials_path),
            "settings_json": path_meta(settings),
            "settings_local_json": path_meta(settings_local),
        },
        "artifacts": {
            "settings_json": settings.exists(),
            "settings_local_json": settings_local.exists(),
            "projects": projects.exists(),
            "claude_json": claude_json.exists(),
            "statsig": statsig.exists(),
            "paths": {
                "settings_json": str(settings),
                "settings_local_json": str(settings_local),
                "projects": str(projects),
                "claude_json": str(claude_json),
                "statsig": str(statsig),
            },
        },
        "time": {"date_utc": iso_z(now), "uptime_seconds": uptime_seconds()},
        "network": {"anthropic": anthropic_check()},
    }


def write_snapshot(path, snapshot):
    """Exclusively write a snapshot as sorted, mode-0600 JSON."""
    payload = (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def load_snapshot(path):
    with open(path) as handle:
        data = json.load(handle)
    return data.get("container_snapshot", data)


def get(data, keys, default=None):
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def changed(old, new, keys):
    return get(old, keys) != get(new, keys)


def bool_word(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def permission_verdict(old, new):
    owner_changed = changed(old, new, ["permissions", "credentials", "owner"])
    mode_changed = changed(old, new, ["permissions", "credentials", "mode"])
    owner = get(new, ["permissions", "credentials", "owner"])
    writable = get(new, ["permissions", "credentials", "writable_by_hapi"])
    non_hapi_owner = isinstance(owner, str) and not owner.startswith("hapi:")
    lost_write = writable is False
    return (owner_changed or mode_changed) and (non_hapi_owner or lost_write)


def format_diff(old, new, path_a, path_b):
    """Return the existing human-readable delta and verdict contract."""
    old_has = get(old, ["credentials", "has_credentials"])
    new_has = get(new, ["credentials", "has_credentials"])
    file_changed = (
        changed(old, new, ["credentials", "sha256"])
        or changed(old, new, ["credentials", "mtime"])
        or changed(old, new, ["credentials", "oauth", "expiresAt"])
    )
    new_expired = get(new, ["credentials", "oauth", "is_expired"])
    old_net_ok = get(old, ["network", "anthropic", "ok"])
    new_net_ok = get(new, ["network", "anthropic", "ok"])

    lines = [
        "Claude auth snapshot diff",
        f"A: {path_a}",
        f"B: {path_b}",
        "",
        "Delta:",
        f"- credentials present: {bool_word(old_has)} -> {bool_word(new_has)}",
        f"- expiresAt: {get(old, ['credentials', 'oauth', 'expiresAt'])} -> {get(new, ['credentials', 'oauth', 'expiresAt'])}",
        f"- is_expired: {bool_word(get(old, ['credentials', 'oauth', 'is_expired']))} -> {bool_word(new_expired)}",
        f"- sha256 changed: {bool_word(changed(old, new, ['credentials', 'sha256']))}",
        f"- mtime changed: {bool_word(changed(old, new, ['credentials', 'mtime']))}",
        (
            "- credentials owner/mode: "
            f"{get(old, ['permissions', 'credentials', 'owner'])} "
            f"{get(old, ['permissions', 'credentials', 'mode'])} -> "
            f"{get(new, ['permissions', 'credentials', 'owner'])} "
            f"{get(new, ['permissions', 'credentials', 'mode'])}"
        ),
        f"- writable_by_hapi: {bool_word(get(old, ['permissions', 'credentials', 'writable_by_hapi']))} -> {bool_word(get(new, ['permissions', 'credentials', 'writable_by_hapi']))}",
        f"- network api.anthropic.com ok: {bool_word(old_net_ok)} -> {bool_word(new_net_ok)}",
        "",
        "Verdict:",
    ]

    verdicts = []
    if old_has is True and new_has is False:
        verdicts.append(
            "🔴 credentials-файл исчез (mount/persistence? проверь host-снэпшот RestartCount/Mounts)."
        )
    if permission_verdict(old, new):
        verdicts.append(
            "🔴 права мешают записи: refresh не может сохранить обновлённый токен."
        )
    if old_has is True and new_has is True and file_changed:
        verdicts.append("✅ refresh работает: токен обновляется.")
    if old_has is True and new_has is True and not file_changed and new_expired is True:
        verdicts.append(
            "🔴 refresh НЕ происходит: expiresAt в прошлом, файл не переписан — Claude Code не обновляет токен (сеть? падает молча?)."
        )
    if old_net_ok is True and new_net_ok is False:
        verdicts.append("⚠️ сетевой доступ к Anthropic пропал.")
    if not verdicts:
        verdicts.append("⚪ причина не определена по этим двум снэпшотам.")
    lines.extend(f"- {verdict}" for verdict in verdicts)
    return "\n".join(lines) + "\n"


def main():
    command = os.environ["CLAUDE_AUTH_SNAPSHOT_COMMAND"]
    if command == "snapshot":
        write_snapshot(
            os.environ["CLAUDE_AUTH_SNAPSHOT_OUTPUT"],
            build_snapshot(),
        )
    elif command == "diff":
        path_a = os.environ["CLAUDE_AUTH_SNAPSHOT_A"]
        path_b = os.environ["CLAUDE_AUTH_SNAPSHOT_B"]
        print(
            format_diff(
                load_snapshot(path_a), load_snapshot(path_b), path_a, path_b
            ),
            end="",
        )
    else:
        raise ValueError(f"unknown command: {command}")


if __name__ == "__main__":
    main()
