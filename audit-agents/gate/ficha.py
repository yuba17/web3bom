"""Ficha file loading and lookup helpers."""

import yaml

from paths import HUNT_SESSION_DIR


def load_ficha(component: str, protocol: str = "") -> dict | None:
    """Try to load the ficha YAML for a component."""
    if protocol:
        ficha_path = HUNT_SESSION_DIR / "fichas" / protocol / f"{component}.yaml"
        if ficha_path.exists():
            return yaml.safe_load(ficha_path.read_text())
    # Search all protocol dirs
    fichas_dir = HUNT_SESSION_DIR / "fichas"
    if fichas_dir.exists():
        for proto_dir in fichas_dir.iterdir():
            if proto_dir.is_dir():
                fp = proto_dir / f"{component}.yaml"
                if fp.exists():
                    return yaml.safe_load(fp.read_text())
    return None


def update_ficha(component: str, updates: dict, protocol: str = ""):
    """Update specific fields in the ficha YAML."""
    fichas_dir = HUNT_SESSION_DIR / "fichas"
    ficha_path = None
    if protocol:
        ficha_path = fichas_dir / protocol / f"{component}.yaml"
    else:
        if fichas_dir.exists():
            for proto_dir in fichas_dir.iterdir():
                if proto_dir.is_dir():
                    fp = proto_dir / f"{component}.yaml"
                    if fp.exists():
                        ficha_path = fp
                        break
    if not ficha_path or not ficha_path.exists():
        return
    ficha = yaml.safe_load(ficha_path.read_text()) or {}
    # Deep merge updates into checklist
    if "checklist" in updates:
        if "checklist" not in ficha:
            ficha["checklist"] = {}
        ficha["checklist"].update(updates["checklist"])
        del updates["checklist"]
    ficha.update(updates)
    with open(ficha_path, "w") as f:
        yaml.dump(ficha, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
