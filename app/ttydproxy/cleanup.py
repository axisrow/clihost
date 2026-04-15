"""Cleanup target discovery and safe deletion helpers."""
import os
import shutil
from pathlib import Path


PROTECTED_HAPI_NAMES = {
    "runner.state.json",
    "runner.state.json.lock",
    "server.log",
    "settings.json",
}

STATIC_TARGETS = (
    {
        "id": "hapi-home",
        "label": "~/.hapi",
        "relative_path": ".hapi",
        "description": "HAPI state, logs, and runtime files (preserves active config/state files)",
        "category": "state",
        "risk": "medium",
        "order": 10,
        "strategy": "prune-hapi-home",
    },
    {
        "id": "runtime",
        "label": "runtime/",
        "relative_path": "runtime",
        "description": "Runtime data and temporary files",
        "category": "runtime",
        "risk": "medium",
        "order": 20,
        "strategy": "remove-tree",
    },
    {
        "id": "cache-home",
        "label": "~/.cache",
        "relative_path": ".cache",
        "description": "Shared tool caches",
        "category": "cache",
        "risk": "low",
        "order": 30,
        "strategy": "remove-tree",
    },
    {
        "id": "npm-cache",
        "label": "~/.npm",
        "relative_path": ".npm",
        "description": "npm cache",
        "category": "cache",
        "risk": "low",
        "order": 40,
        "strategy": "remove-tree",
    },
    {
        "id": "local-share",
        "label": "~/.local/share",
        "relative_path": ".local/share",
        "description": "Shared local application data and caches",
        "category": "cache",
        "risk": "medium",
        "order": 50,
        "strategy": "remove-tree",
    },
)

PROJECT_CATEGORY_ORDER = 100
RESERVED_TOP_LEVEL_NAMES = {"runtime"}


def _format_size(size_bytes):
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            precision = 0 if value >= 10 else 1
            return f"{value:.{precision}f} {unit}"
        value /= 1024
    return "0 B"


def _resolve_within_root(path, root):
    try:
        resolved_root = root.resolve()
        resolved_path = path.resolve()
    except OSError:
        return None
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved_path


def _directory_size(path):
    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        total += _directory_size(entry.path)
                    else:
                        total += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def _build_target(path, root, target_id, label, description, category, risk, order, strategy):
    normalized = _resolve_within_root(path, root)
    if normalized is None or not normalized.exists() or not normalized.is_dir():
        return None

    size_bytes = _directory_size(normalized)
    return {
        "id": target_id,
        "label": label,
        "description": description,
        "category": category,
        "risk": risk,
        "size_bytes": size_bytes,
        "size_human": _format_size(size_bytes),
        "path": str(normalized.relative_to(root.resolve())),
        "order": order,
        "strategy": strategy,
    }


def list_cleanup_targets(cleanup_root, hapi_home):
    """Return cleanup candidates within the configured home directory."""
    root = Path(cleanup_root)
    hapi_path = Path(hapi_home)
    targets = []

    for spec in STATIC_TARGETS:
        path = hapi_path if spec["id"] == "hapi-home" else root / spec["relative_path"]
        target = _build_target(
            path,
            root,
            spec["id"],
            spec["label"],
            spec["description"],
            spec["category"],
            spec["risk"],
            spec["order"],
            spec["strategy"],
        )
        if target is not None:
            targets.append(target)

    try:
        entries = list(root.iterdir())
    except OSError:
        entries = []

    projects = []
    for entry in entries:
        if entry.name.startswith(".") or entry.name in RESERVED_TOP_LEVEL_NAMES:
            continue
        target = _build_target(
            entry,
            root,
            f"project:{entry.name}",
            f"{entry.name}/",
            "Project or work directory",
            "project",
            "high",
            PROJECT_CATEGORY_ORDER,
            "remove-tree",
        )
        if target is not None:
            projects.append(target)

    projects.sort(key=lambda item: (-item["size_bytes"], item["label"]))
    targets.extend(projects)
    targets.sort(key=lambda item: (item["order"], item["label"]))
    return targets


def summarize_cleanup_targets(targets):
    """Return aggregate counts and sizes for cleanup targets."""
    total_size = sum(target["size_bytes"] for target in targets)
    return {
        "count": len(targets),
        "total_size_bytes": total_size,
        "total_size_human": _format_size(total_size),
    }


def _remove_tree(path):
    if not path.exists():
        return False
    shutil.rmtree(path)
    return True


def _prune_hapi_home(path):
    if not path.exists() or not path.is_dir():
        return False

    removed_anything = False
    for child in path.iterdir():
        if child.name in PROTECTED_HAPI_NAMES:
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child)
        removed_anything = True
    return removed_anything


def delete_cleanup_targets(target_ids, cleanup_root, hapi_home):
    """Delete selected cleanup targets by server-issued IDs."""
    targets = {target["id"]: target for target in list_cleanup_targets(cleanup_root, hapi_home)}
    unique_ids = list(dict.fromkeys(target_ids))
    deleted = []
    skipped = []
    errors = []
    root = Path(cleanup_root)

    for target_id in unique_ids:
        target = targets.get(target_id)
        if target is None:
            skipped.append({"id": target_id, "reason": "unknown target"})
            continue

        path = root / target["path"]
        try:
            if target["strategy"] == "prune-hapi-home":
                _prune_hapi_home(path)
            else:
                _remove_tree(path)
            deleted.append({"id": target_id, "label": target["label"]})
        except OSError as exc:
            errors.append({"id": target_id, "label": target["label"], "error": str(exc)})

    return {
        "deleted": deleted,
        "skipped": skipped,
        "errors": errors,
    }
