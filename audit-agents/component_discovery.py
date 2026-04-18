from __future__ import annotations

import re
from pathlib import Path


def _count_locs(path: Path) -> int:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    lines = 0
    for ln in src.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        lines += 1
    return lines


_EXCLUDE_PATTERNS = (
    "test/", "lib/", "node_modules/", "mock/", "Mock",
    "script/", "interface/", "interfaces/",
)


def _scan_repo(repo: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in ("src/**/*.sol", "contracts/**/*.sol"):
        out.extend(repo.glob(pattern))
    filtered: list[Path] = []
    for f in out:
        try:
            rel = str(f.relative_to(repo))
        except ValueError:
            rel = str(f)
        if any(ex in rel for ex in _EXCLUDE_PATTERNS):
            continue
        stem = f.stem
        if stem.startswith("I") and len(stem) > 1 and stem[1].isupper():
            continue
        filtered.append(f)
    return filtered


def generate_component_map(
    *,
    repo_path: str,
    extra_repos: list[str] | None = None,
    components_done: list[str] | None = None,
    components_remaining: list[str] | None = None,
) -> list[dict]:
    repo = Path(repo_path)
    if not repo.exists():
        return []

    files = _scan_repo(repo)

    for extra in extra_repos or []:
        extra_repo = Path(extra)
        if extra_repo.exists():
            files.extend(_scan_repo(extra_repo))

    done = set(components_done or [])
    pending = set(components_remaining or [])

    stems = {f.stem for f in files}
    component_map: list[dict] = []
    seen_names: set[str] = set()

    for f in sorted(files, key=lambda x: x.stat().st_size, reverse=True):
        name = f.stem
        if name in seen_names:
            continue
        seen_names.add(name)

        loc = _count_locs(f)
        if loc == 0:
            continue

        if name in done:
            status = "done"
        elif name in pending:
            status = "pending"
        else:
            status = "unmapped"

        try:
            rel_path = str(f.relative_to(repo))
        except ValueError:
            rel_path = str(f)

        depends_on: list[str] = []
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
            imports = re.findall(r'import\s+.*?["\'].*?/(\w+)\.sol["\']', src)
            depends_on = list({imp for imp in imports if imp in stems} - {name})[:5]
        except OSError:
            pass

        component_map.append({
            "name": name,
            "files": [rel_path],
            "loc": loc,
            "status": status,
            "depends_on": depends_on,
        })

    component_map.sort(key=lambda c: c["loc"], reverse=True)
    for i, comp in enumerate(component_map):
        comp["priority"] = i + 1
    return component_map
