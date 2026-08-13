"""Golden contracts for the importable Claude auth snapshot helpers (#116)."""

import datetime
import json
import pathlib
import sys
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "bin"))

import claude_auth_snapshot as snapshot_lib  # noqa: E402


def test_build_snapshot_schema_golden(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / ".credentials.json").write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "never-copy-me",
                    "expiresAt": 1893456000000,
                    "scopes": ["user:inference"],
                    "subscriptionType": "pro",
                }
            }
        )
    )
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    environ = {
        "CLAUDE_CONFIG_DIR": str(claude_dir),
        "CLAUDE_AUTH_SNAPSHOT_DIR": str(tmp_path / "snapshots"),
        "CLAUDE_AUTH_SNAPSHOT_LABEL": "baseline",
    }

    with (
        mock.patch.object(snapshot_lib, "uptime_seconds", return_value=123.5),
        mock.patch.object(
            snapshot_lib,
            "anthropic_check",
            return_value={
                "url": "https://api.anthropic.com/",
                "ok": True,
                "http_code": "200",
                "method": "curl",
                "error": None,
            },
        ),
    ):
        snapshot = snapshot_lib.build_snapshot(now=now, environ=environ)

    assert set(snapshot) == {
        "schema_version",
        "kind",
        "label",
        "created_at",
        "now_ms",
        "process",
        "credentials",
        "permissions",
        "artifacts",
        "time",
        "network",
    }
    assert set(snapshot["process"]) == {
        "user",
        "uid",
        "claude_config_dir",
        "snapshot_dir",
    }
    assert set(snapshot["credentials"]) == {
        "path",
        "has_credentials",
        "sha256",
        "mtime",
        "oauth",
    }
    assert set(snapshot["credentials"]["oauth"]) == {
        "expiresAt",
        "expires_in_minutes",
        "is_expired",
        "scopes",
        "subscriptionType",
    }
    assert set(snapshot["permissions"]) == {
        "claude_dir",
        "credentials",
        "settings_json",
        "settings_local_json",
    }
    for metadata in snapshot["permissions"].values():
        assert set(metadata) == {
            "path",
            "exists",
            "owner",
            "mode",
            "mtime",
            "is_symlink",
            "writable_by_hapi",
        }
    assert set(snapshot["artifacts"]) == {
        "settings_json",
        "settings_local_json",
        "projects",
        "claude_json",
        "statsig",
        "paths",
    }
    assert set(snapshot["artifacts"]["paths"]) == {
        "settings_json",
        "settings_local_json",
        "projects",
        "claude_json",
        "statsig",
    }
    assert snapshot["time"] == {
        "date_utc": "2026-01-01T00:00:00Z",
        "uptime_seconds": 123.5,
    }
    assert snapshot["network"]["anthropic"]["ok"] is True
    assert snapshot["credentials"]["oauth"] == {
        "expiresAt": 1893456000000,
        "expires_in_minutes": 2103840,
        "is_expired": False,
        "scopes": ["user:inference"],
        "subscriptionType": "pro",
    }
    assert "never-copy-me" not in json.dumps(snapshot)


def test_format_diff_output_golden():
    old = {
        "credentials": {
            "has_credentials": True,
            "sha256": "old",
            "mtime": 100,
            "oauth": {"expiresAt": 1000, "is_expired": False},
        },
        "permissions": {
            "credentials": {
                "owner": "hapi:hapi",
                "mode": "600",
                "writable_by_hapi": True,
            }
        },
        "network": {"anthropic": {"ok": True}},
    }
    new = json.loads(json.dumps(old))
    new["credentials"].update({"sha256": "new", "mtime": 200})
    new["credentials"]["oauth"]["expiresAt"] = 2000

    assert snapshot_lib.format_diff(old, new, "a.json", "b.json") == (
        "Claude auth snapshot diff\n"
        "A: a.json\n"
        "B: b.json\n"
        "\n"
        "Delta:\n"
        "- credentials present: true -> true\n"
        "- expiresAt: 1000 -> 2000\n"
        "- is_expired: false -> false\n"
        "- sha256 changed: true\n"
        "- mtime changed: true\n"
        "- credentials owner/mode: hapi:hapi 600 -> hapi:hapi 600\n"
        "- writable_by_hapi: true -> true\n"
        "- network api.anthropic.com ok: true -> true\n"
        "\n"
        "Verdict:\n"
        "- ✅ refresh работает: токен обновляется.\n"
    )
