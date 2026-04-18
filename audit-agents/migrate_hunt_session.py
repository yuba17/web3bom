#!/usr/bin/env python3
"""One-time migration: move flat hunt_session files into protocol subdirectories.

Detects protocol from component name in filename, then moves files to
hunt_session/hypotheses/{protocol}/. Same for context files.
Also splits gate_status.json into per-protocol files.
"""

import json
import shutil

from paths import WEB3_DIR
HUNT_SESSION = WEB3_DIR / "hunt_session"
HYP_DIR = HUNT_SESSION / "hypotheses"
CTX_DIR = HUNT_SESSION / "context"
GATE_FILE = HUNT_SESSION / "gate_status.json"
GATE_DIR = HUNT_SESSION / "gate_status"

# Map component name prefixes to protocols
COMPONENT_TO_PROTOCOL = {
    # Hyperlane
    "InterchainAccountRouter": "hyperlane",
    "AbstractInterchainAccountRouter": "hyperlane",
    "AbstractMultisigIsm": "hyperlane",
    "Mailbox": "hyperlane",
    "DomainRoutingIsm": "hyperlane",
    "MerkleTreeHook": "hyperlane",
    # Morpho
    "MetaMorpho": "morpho-metamorpho",
    "VaultV2": "morpho-vault-v2",
    "PreLiquidation": "morpho-pre-liquidation",
    "Bundler3": "morpho-bundler3",
    # Coinbase
    "CoinbaseSmartWallet": "smart-wallet",
    "MagicSpend": "smart-wallet",
    "Bridge": "base-bridge",
    "BridgeValidator": "base-bridge",
    "Transfers": "commerce-payments",
    "MessageStorageLib": "base-bridge",
    "RateLimit": "wrapped-tokens-os",
    # Chainlink / Variational
    "BaseAuction": "variational",
    "GPV2CompatibleAuction": "variational",
    "PriceManager": "variational",
    "AuctionBidder": "variational",
    "WorkflowRouter": "variational",
    # Flywheel
    "Flywheel": "flywheel",
    "AdConversion": "flywheel",
    "CashbackRewards": "flywheel",
    # PancakeSwap
    "BinPoolManager": "pancakeswap-infinity",
    "CLPoolManager": "pancakeswap-infinity",
    "Vault": "pancakeswap-infinity",
    "PoolManager": "pancakeswap-infinity",
    "VeCake": "pancakeswap-infinity",
}


def detect_protocol(filename: str) -> str:
    """Extract component from filename and map to protocol."""
    # Sort by length descending so longer matches win (e.g., "AbstractInterchainAccountRouter" before "Mailbox")
    for comp in sorted(COMPONENT_TO_PROTOCOL.keys(), key=len, reverse=True):
        if comp in filename:
            return COMPONENT_TO_PROTOCOL[comp]
    return "unknown"


def migrate_hypotheses():
    """Move flat hyp_*.yaml files into protocol subdirs."""
    if not HYP_DIR.exists():
        print("  No hypotheses directory found, skipping")
        return

    moved = 0
    skipped = 0
    for f in sorted(HYP_DIR.glob("hyp_*.yaml")):
        if f.parent != HYP_DIR:
            continue  # already in a subdir
        proto = detect_protocol(f.name)
        dest_dir = HYP_DIR / proto
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f.name
        if dest.exists():
            skipped += 1
            continue
        shutil.move(str(f), str(dest))
        moved += 1

    print(f"  Hypotheses: {moved} moved, {skipped} skipped (already exist)")


def migrate_context():
    """Move flat context files into protocol subdirs."""
    if not CTX_DIR.exists():
        print("  No context directory found, skipping")
        return

    moved = 0
    skipped = 0
    for f in sorted(CTX_DIR.iterdir()):
        if f.is_dir() or f.parent != CTX_DIR:
            continue
        proto = detect_protocol(f.name)
        dest_dir = CTX_DIR / proto
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f.name
        if dest.exists():
            skipped += 1
            continue
        shutil.move(str(f), str(dest))
        moved += 1

    print(f"  Context: {moved} moved, {skipped} skipped (already exist)")


def migrate_gate_status():
    """Split flat gate_status.json into per-protocol files."""
    if not GATE_FILE.exists():
        print("  No gate_status.json found, skipping")
        return

    data = json.loads(GATE_FILE.read_text())
    GATE_DIR.mkdir(parents=True, exist_ok=True)

    by_protocol: dict[str, dict] = {}

    for key, value in data.items():
        if key == "findings":
            for fid, fdata in value.items():
                comp = fdata.get("component", "")
                proto = detect_protocol(comp)
                by_protocol.setdefault(proto, {}).setdefault("findings", {})
                by_protocol[proto]["findings"][fid] = fdata
        else:
            proto = detect_protocol(key)
            by_protocol.setdefault(proto, {})
            by_protocol[proto][key] = value

    for proto, pdata in sorted(by_protocol.items()):
        out_file = GATE_DIR / f"{proto}.json"
        out_file.write_text(json.dumps(pdata, indent=2))
        n_comp = len([k for k in pdata if k != "findings"])
        n_find = len(pdata.get("findings", {}))
        print(f"  gate_status/{proto}.json: {n_comp} components, {n_find} findings")

    backup = GATE_FILE.with_suffix(".json.bak")
    shutil.move(str(GATE_FILE), str(backup))
    print(f"  Backed up original to gate_status.json.bak")


def main():
    print("=== Hunt Session Migration: Flat -> Protocol Namespaced ===\n")

    print("--- Hypotheses ---")
    migrate_hypotheses()

    print("\n--- Context ---")
    migrate_context()

    print("\n--- Gate Status ---")
    migrate_gate_status()

    print("\n=== Migration complete ===")


if __name__ == "__main__":
    main()
