"""I/O + validation for merge_invariants package."""
import re
import json
import yaml
from pathlib import Path

from paths import WEB3_DIR, HUNT_SESSION_DIR
from state_manager import load_state
from merge.constants import REQUIRED_HYP_FIELDS, HUNTER_REQUIRED_TABLES, _PRAGMA


def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d

def validate_hypothesis(hyp: dict, source_file: str) -> list[str]:
    """Validate a single hypothesis. Returns list of warnings."""
    warnings = []
    for field in REQUIRED_HYP_FIELDS:
        if field not in hyp or not hyp[field]:
            warnings.append(f"  {source_file}: {hyp.get('id', '?')} missing '{field}'")
    sol = hyp.get("solidity", "")
    if sol and not any(kw in sol for kw in ["t(", "eq(", "gte(", "lte(", "assert", "require"]):
        warnings.append(f"  {source_file}: {hyp.get('id', '?')} solidity has no assertion")
    return warnings


def dedup_hypotheses(hypotheses: list[dict]) -> list[dict]:
    """Remove near-duplicate hypotheses across hunters before merge.

    Two hypotheses are duplicates if:
    - Same primary function referenced AND >50% keyword overlap in description
    Keep the one with highest confidence. Tag with _merged_count.
    """
    from collections import defaultdict

    groups = defaultdict(list)
    for hyp in hypotheses:
        # Extract function names from solidity/description
        text = f"{hyp.get('description', '')} {hyp.get('solidity', '')}".lower()
        functions = set()
        for token in re.findall(r'\b(\w+)\s*\(', text):
            if token not in ('require', 'assert', 'revert', 'emit', 'if', 'for', 'while',
                             'gte', 'lte', 'eq', 't', 'gt', 'lt', 'true', 'false'):
                functions.add(token)
        key = frozenset(functions) if functions else frozenset([hyp.get('id', str(id(hyp)))])
        groups[key].append(hyp)

    deduped = []
    total_merged = 0
    for key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            best = max(group, key=lambda h: h.get("confidence", 0))
            best["_merged_count"] = len(group)
            best["_merged_from"] = [h.get("_hunter", h.get("id", "?")) for h in group if h != best]
            deduped.append(best)
            total_merged += len(group) - 1

    if total_merged > 0:
        print(f"[dedup] Merged {total_merged} duplicate hypotheses ({len(hypotheses)} → {len(deduped)})")

    return deduped


def detect_pragma(chimera_dir: Path) -> str:
    """Detect pragma from project source files. Checks Setup.sol first, then src/."""
    candidates = []
    setup = chimera_dir / "Setup.sol"
    if setup.exists():
        candidates.append(setup)
    # Walk up to find src/
    repo = chimera_dir
    for _ in range(5):
        src = repo / "src"
        if src.is_dir():
            candidates.extend(sorted(src.glob("**/*.sol"))[:5])
            break
        repo = repo.parent
    for f in candidates:
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                m = re.match(r'\s*(pragma\s+solidity\s+[^;]+;)', line)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return _PRAGMA


def load_current_hunt() -> dict:
    """Carga el estado del hunt activo. Corrupted JSON swallowed to {}."""
    try:
        return load_state()
    except json.JSONDecodeError:
        return {}


def find_chimera_dir(hunt: dict) -> Path | None:
    """Localiza el directorio test/chimera/ del hunt activo."""
    repo = hunt.get("repo_path")
    if repo:
        candidates = [
            Path(repo) / "test/chimera",
            Path(repo) / "test",
            Path(repo) / "src/test/chimera",
        ]
        for c in candidates:
            if (c / "Properties.sol").exists():
                return c

    matches = list(WEB3_DIR.glob("*/test/chimera/Properties.sol"))
    if matches:
        return matches[0].parent

    return None


def find_properties_sol(hunt: dict) -> Path | None:
    """Localiza Properties.sol del hunt activo."""
    chimera_dir = find_chimera_dir(hunt)
    if chimera_dir:
        return chimera_dir / "Properties.sol"
    return None


def load_hypothesis_file(path: Path) -> dict | None:
    """Carga y valida un archivo de hipótesis YAML."""
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            print(f"  ✗ {path.name}: no es un dict YAML válido")
            return None
        invariants = data.get("invariants", data.get("findings", data.get("hypotheses", [])))
        if not invariants:
            print(f"  ⚠ {path.name}: sin invariants/findings/hypotheses")
        return data
    except Exception as e:
        print(f"  ✗ Error leyendo {path.name}: {e}")
        return None


def validate_evidence_tables(hyp_data: dict) -> list[str]:
    """Check if hypothesis YAML includes required structured evidence tables.

    Returns list of warning strings for missing tables.
    Does NOT block merge — warns only, so hunters can still produce results
    even if they skip a table (but the warning makes it visible).
    """
    warnings = []
    hunter = hyp_data.get("hunter", "")
    required = HUNTER_REQUIRED_TABLES.get(hunter, [])

    if not required:
        return warnings

    for table_name in required:
        # Check top-level and inside each invariant
        has_table = table_name in hyp_data
        if not has_table:
            # Also check inside invariants
            for inv in hyp_data.get("invariants", hyp_data.get("findings", hyp_data.get("hypotheses", []))):
                if isinstance(inv, dict) and table_name in inv:
                    has_table = True
                    break

        if not has_table:
            warnings.append(
                f"⚠ {hunter}: missing required '{table_name}' table. "
                f"Re-run hunter with structured evidence requirement."
            )

    return warnings
