# hunt-dashboard/test_serve.py
"""Tests for serve.py data consolidation logic."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add parent to path so we can import serve
sys.path.insert(0, os.path.dirname(__file__))
import serve


class TestLoadHuntState(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        result = serve.load_hunt_state("/nonexistent/path.json")
        self.assertEqual(result, {})

    def test_valid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"protocol": "test", "findings": []}, f)
            f.flush()
            result = serve.load_hunt_state(f.name)
            self.assertEqual(result["protocol"], "test")
            os.unlink(f.name)

    def test_malformed_json_returns_error(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{bad json")
            f.flush()
            result = serve.load_hunt_state(f.name)
            self.assertIn("error", result)
            os.unlink(f.name)


class TestLoadFichas(unittest.TestCase):
    def test_no_fichas_dir(self):
        result = serve.load_fichas("/nonexistent", "test-proto")
        self.assertEqual(result, {})

    def test_loads_yaml_excludes_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fichas_dir = Path(tmpdir) / "fichas"
            fichas_dir.mkdir()
            proto_dir = fichas_dir / "test-proto"
            proto_dir.mkdir()
            # Write a ficha
            (proto_dir / "Vault.yaml").write_text(
                "component: Vault\nstatus: complete\n"
                "hunters_completed:\n  MathHunter: true\n"
                "checklist:\n  full_code_read: true\n"
            )
            # Write template (should be excluded)
            (fichas_dir / "ficha_template.yaml").write_text("template: true\n")
            result = serve.load_fichas(tmpdir, "test-proto")
            self.assertIn("Vault", result)
            self.assertEqual(result["Vault"]["status"], "complete")


class TestLoadHypotheses(unittest.TestCase):
    def test_no_dir(self):
        result = serve.load_hypotheses("/nonexistent")
        self.assertEqual(result, {})

    def test_parses_component_hunter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hyp_file = Path(tmpdir) / "hyp_Vault_MathHunter.yaml"
            hyp_file.write_text(
                "component: Vault\nhunter: MathHunter\n"
                "invariants:\n"
                "  - id: MATH-01\n"
                "    description: 'test invariant for withdraw()'\n"
                "    confidence: 75\n"
                "    solidity: 'function check_withdraw() public {}'\n"
            )
            # Template should be excluded
            (Path(tmpdir) / "hyp_template.yaml").write_text("template: true\n")
            result = serve.load_hypotheses(tmpdir)
            self.assertIn("Vault", result)
            self.assertIn("MathHunter", result["Vault"])
            self.assertEqual(result["Vault"]["MathHunter"]["count"], 1)


class TestComputeConvergence(unittest.TestCase):
    def test_two_hunters_same_function(self):
        hypotheses = {
            "Vault": {
                "MathHunter": {
                    "count": 1, "tier1": 0,
                    "items": [{"id": "M1", "description": "rounding in withdraw()", "confidence": 50}],
                    "functions_mentioned": ["withdraw"]
                },
                "FlowHunter": {
                    "count": 1, "tier1": 0,
                    "items": [{"id": "F1", "description": "reentrancy in withdraw()", "confidence": 60}],
                    "functions_mentioned": ["withdraw"]
                }
            }
        }
        result = serve.compute_convergence(hypotheses)
        self.assertIn("Vault", result)
        self.assertEqual(len(result["Vault"]), 1)
        self.assertEqual(result["Vault"][0]["function"], "withdraw")
        self.assertEqual(result["Vault"][0]["count"], 2)


class TestBuildActivityLog(unittest.TestCase):
    def test_empty_dir(self):
        result = serve.build_activity_log("/nonexistent", {})
        self.assertEqual(result, [])


class TestDeriveConfirmedCount(unittest.TestCase):
    def test_counts_non_parked(self):
        findings = [
            {"status": "PARKED"}, {"status": "CONFIRMED"}, {"status": "REPORTED"}
        ]
        self.assertEqual(serve.derive_confirmed_count(findings), 2)

    def test_all_parked(self):
        findings = [{"status": "PARKED"}, {"status": "PARKED"}]
        self.assertEqual(serve.derive_confirmed_count(findings), 0)


class TestBuildDashboardIntegration(unittest.TestCase):
    """Integration test with real hunt data (if available)."""

    def test_real_data_if_available(self):
        state_path = str(Path.home() / ".claude/MEMORY/STATE/current_hunt.json")
        hunt_dir = str(Path.home() / "Documents/Web3/hunt_session")
        if not Path(state_path).exists():
            self.skipTest("No real hunt data available")

        data = serve.build_dashboard(state_path, hunt_dir)

        # Should not error
        self.assertNotIn("error", data)
        # Should have protocol
        self.assertIsNotNone(data.get("protocol"))
        # Should have checklist_labels (always present)
        self.assertEqual(len(data["checklist_labels"]), 12)
        # Should have hunter_domains (always present)
        self.assertGreaterEqual(len(data["hunter_domains"]), 6)
        # JSON serializable
        json.dumps(data, ensure_ascii=False)

    def test_server_startup(self):
        """Verify serve.py has valid syntax and can be imported."""
        import serve
        self.assertTrue(hasattr(serve, 'main'))
        self.assertTrue(hasattr(serve, 'build_dashboard'))
        self.assertTrue(hasattr(serve, 'DashboardHandler'))


if __name__ == "__main__":
    unittest.main()
