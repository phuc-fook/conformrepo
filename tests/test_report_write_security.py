from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

from conformrepo import run_audit


def write_config(root: Path, destination: str, exclusions: list[str]) -> Path:
    raw = {
        "configuration_version": "0.1",
        "repository": {
            "root": "repo",
            "include_roots": ["specs", "reports", "generated"],
            "exclude_roots": exclusions,
            "suffixes": [".md", ".json"],
            "case_policy": "lexical-sensitive",
            "symlink_policy": "do-not-follow",
        },
        "report": {"destination": destination, "format": "json"},
        "exit_policy": {"fail_on": ["error"]},
    }
    config = root / "config.yaml"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return config


class ReportWriteContainmentTests(unittest.TestCase):
    def test_symlinked_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo/specs").mkdir(parents=True)
            (root / "external").mkdir()
            (root / "repo/specs/overview.md").write_text("# Device\n", encoding="utf-8")
            try:
                (root / "repo/reports").symlink_to(root / "external", target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"SYMLINK_SECURITY_ENVIRONMENT_TEST_UNAVAILABLE: {os.name}: {exc}")
            result = run_audit(write_config(root, "reports/audit.json", ["reports"]), write_report=True)
            self.assertEqual(2, result.exit_code)
            self.assertFalse(result.scan_started)
            self.assertEqual("UNSAFE_REPORT_DESTINATION", result.findings[0].code)
            self.assertFalse((root / "external/audit.json").exists())

    def test_normal_excluded_output_directory_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo/specs").mkdir(parents=True)
            (root / "repo/reports").mkdir()
            (root / "repo/specs/overview.md").write_text("# Device\n", encoding="utf-8")
            result = run_audit(write_config(root, "reports/audit.json", ["reports"]), write_report=True)
            self.assertEqual(0, result.exit_code)
            self.assertTrue((root / "repo/reports/audit.json").is_file())

    def test_nested_symlink_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo/specs").mkdir(parents=True)
            (root / "repo/generated").mkdir()
            (root / "external").mkdir()
            (root / "repo/specs/overview.md").write_text("# Device\n", encoding="utf-8")
            try:
                (root / "repo/generated/cache").symlink_to(root / "external", target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"SYMLINK_SECURITY_ENVIRONMENT_TEST_UNAVAILABLE: {os.name}: {exc}")
            result = run_audit(write_config(root, "generated/cache/audit.json", ["generated/cache"]), write_report=True)
            self.assertEqual(2, result.exit_code)
            self.assertFalse(result.scan_started)
            self.assertEqual("UNSAFE_REPORT_DESTINATION", result.findings[0].code)
            self.assertFalse((root / "external/audit.json").exists())
