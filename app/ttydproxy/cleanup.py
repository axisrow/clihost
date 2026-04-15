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
MAX_SIZE_WALK_ENTRIES = 5000


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


def _relative_path_within_root(path, root):
    try:
        return str(path.absolute().relative_to(root.absolute()))
    except ValueError:
        return None


def _directory_size(path, budget):
    total = 0
    truncated = False
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if budget["remaining"] <= 0:
                    return total, True
                budget["remaining"] -= 1
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        child_total, child_truncated = _directory_size(entry.path, budget)
                        total += child_total
                        truncated = truncated or child_truncated
                    else:
                        total += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    except OSError:
        return 0, truncated
    return total, truncated


def _measure_directory_size(path, max_entries=MAX_SIZE_WALK_ENTRIES):
    budget = {"remaining": max_entries}
    return _directory_size(path, budget)


def _is_listable_directory(path, resolved_path):
    if path.is_symlink():
        return resolved_path.is_dir()
    return path.exists() and path.is_dir()


def _build_target(
    path,
    root,
    target_id,
    label,
    description,
    category,
    risk,
    order,
    strategy,
    include_missing=False,
    max_size_entries=MAX_SIZE_WALK_ENTRIES,
):
    normalized = _resolve_within_root(path, root)
    relative_path = _relative_path_within_root(path, root)
    if normalized is None or relative_path is None:
        return None
    if not include_missing and not _is_listable_directory(path, normalized):
        return None

    if path.exists() or path.is_symlink():
        size_bytes, size_approximate = _measure_directory_size(normalized, max_entries=max_size_entries)
    else:
        size_bytes = 0
        size_approximate = False
    size_human = _format_size(size_bytes)
    if size_approximate:
        size_human = f"~{size_human}"
    return {
        "id": target_id,
        "label": label,
        "description": description,
        "category": category,
        "risk": risk,
        "size_bytes": size_bytes,
        "size_human": size_human,
        "size_approximate": size_approximate,
        "path": relative_path,
        "order": order,
        "strategy": strategy,
    }


def _project_target_name(target_id):
    prefix = "project:"
    if not target_id.startswith(prefix):
        return None
    name = target_id[len(prefix):]
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return None
    if name.startswith(".") or name in RESERVED_TOP_LEVEL_NAMES:
        return None
    return name


def resolve_cleanup_target(target_id, cleanup_root, hapi_home, include_missing=False):
    """Resolve a cleanup target by ID using server-side allowlisted rules."""
    root = Path(cleanup_root)
    hapi_path = Path(hapi_home)

    for spec in STATIC_TARGETS:
        if spec["id"] != target_id:
            continue
        path = hapi_path if spec["id"] == "hapi-home" else root / spec["relative_path"]
        return _build_target(
            path,
            root,
            spec["id"],
            spec["label"],
            spec["description"],
            spec["category"],
            spec["risk"],
            spec["order"],
            spec["strategy"],
            include_missing=include_missing,
        )

    project_name = _project_target_name(target_id)
    if project_name is None:
        return None

    return _build_target(
        root / project_name,
        root,
        target_id,
        f"{project_name}/",
        "Project or work directory",
        "project",
        "high",
        PROJECT_CATEGORY_ORDER,
        "remove-tree",
        include_missing=include_missing,
    )


def list_cleanup_targets(cleanup_root, hapi_home):
    """Return cleanup candidates within the configured home directory."""
    root = Path(cleanup_root)
    targets = []

    for spec in STATIC_TARGETS:
        target = resolve_cleanup_target(spec["id"], cleanup_root, hapi_home)
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
        target = resolve_cleanup_target(f"project:{entry.name}", cleanup_root, hapi_home)
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


def _remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
        return True
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
    unique_ids = list(dict.fromkeys(target_ids))
    deleted = []
    skipped = []
    errors = []
    root = Path(cleanup_root)

    for target_id in unique_ids:
        target = resolve_cleanup_target(target_id, cleanup_root, hapi_home, include_missing=True)
        if target is None:
            skipped.append({"id": target_id, "reason": "unknown target"})
            continue

        path = root / target["path"]
        if not path.exists() and not path.is_symlink():
            skipped.append({"id": target_id, "label": target["label"], "reason": "already removed"})
            continue
        try:
            if target["strategy"] == "prune-hapi-home":
                removed = _prune_hapi_home(path)
            else:
                removed = _remove_path(path)
            if removed:
                deleted.append({"id": target_id, "label": target["label"]})
            else:
                skipped.append({"id": target_id, "label": target["label"], "reason": "already removed"})
        except OSError as exc:
            errors.append({"id": target_id, "label": target["label"], "error": str(exc)})

    return {
        "deleted": deleted,
        "skipped": skipped,
        "errors": errors,
    }
