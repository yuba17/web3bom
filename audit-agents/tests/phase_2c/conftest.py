from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make audit_agents_path importable from within this package
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Synthetic Solidity repo: 3 core contracts + excluded files (test/lib/mock/interface)."""
    src = tmp_path / "src"
    (src / "interfaces").mkdir(parents=True)
    (src / "mock").mkdir(parents=True)
    (tmp_path / "test").mkdir()
    (tmp_path / "lib" / "openzeppelin").mkdir(parents=True)

    vault_code = "\n".join(
        ['pragma solidity ^0.8.0;', 'import "./interfaces/IStrategy.sol";']
        + [f'// line {i}' for i in range(28)]
    )
    strategy_code = "\n".join(
        ['pragma solidity ^0.8.0;', 'import "./interfaces/IVault.sol";']
        + [f'// line {i}' for i in range(23)]
    )
    oracle_code = "\n".join(
        ['pragma solidity ^0.8.0;']
        + [f'// line {i}' for i in range(19)]
    )

    (src / "Vault.sol").write_text(vault_code)
    (src / "Strategy.sol").write_text(strategy_code)
    (src / "Oracle.sol").write_text(oracle_code)
    (src / "interfaces" / "IStrategy.sol").write_text('// interface')
    (src / "interfaces" / "IVault.sol").write_text('// interface')
    (src / "mock" / "MockERC20.sol").write_text('// mock')
    (tmp_path / "test" / "TestVault.sol").write_text('// test')
    (tmp_path / "lib" / "openzeppelin" / "Ownable.sol").write_text('// lib')
    return tmp_path


@pytest.fixture
def tmp_component_map() -> list[dict]:
    """Matches tmp_repo adjacency; adds isolated Router for exclusion tests."""
    return [
        {"name": "Vault", "files": ["src/Vault.sol"], "loc": 100,
         "status": "done", "priority": 1, "depends_on": ["Strategy"]},
        {"name": "Strategy", "files": ["src/Strategy.sol"], "loc": 80,
         "status": "done", "priority": 2, "depends_on": ["Oracle"]},
        {"name": "Oracle", "files": ["src/Oracle.sol"], "loc": 60,
         "status": "done", "priority": 3, "depends_on": []},
        {"name": "Router", "files": ["src/Router.sol"], "loc": 40,
         "status": "done", "priority": 4, "depends_on": []},
    ]
