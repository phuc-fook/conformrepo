from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from corpus_support import FIXTURES_ROOT, determinism_replays
from conformrepo import run_audit
from conformrepo.intake import discover
from conformrepo.model import RepositoryContext


class IntegrationTests(unittest.TestCase):
    def test_f12_and_representative_determinism_replay(self) -> None:
        results = determinism_replays()
        self.assertTrue(all(value == "BYTE_EQUIVALENT_COMPARISON_CRITICAL_OUTPUT" for value in results.values()))

    def test_safe_file_report_write(self) -> None:
        fixture = next(FIXTURES_ROOT.glob("F18_*"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo/specs").mkdir(parents=True)
            (root / "repo/specs/overview.md").write_text("# Device\n", encoding="utf-8")
            config = (fixture / "config.yaml").read_text(encoding="utf-8")
            (root / "config.yaml").write_text(config, encoding="utf-8")
            result = run_audit(root / "config.yaml", write_report=True)
            output = root / "repo/out/audit.json"
            self.assertEqual("PASS", result.outcome)
            self.assertTrue(output.is_file())
            self.assertEqual("PASS", json.loads(output.read_text(encoding="utf-8"))["outcome"])

    def test_unsafe_output_does_not_write_or_scan(self) -> None:
        fixture = next(FIXTURES_ROOT.glob("F20_*"))
        result = run_audit(fixture / "config.yaml", write_report=True)
        self.assertEqual(2, result.exit_code)
        self.assertFalse(result.scan_started)
        self.assertFalse((fixture / "repo/specs/audit.json").exists())

    def test_real_symlink_do_not_follow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            (repo / "specs").mkdir(parents=True)
            (root / "outside").mkdir()
            (repo / "specs/overview.md").write_text("# Device\n", encoding="utf-8")
            (root / "outside/leak.md").write_text("# Outside\n", encoding="utf-8")
            try:
                (repo / "specs/link").symlink_to(root / "outside", target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"SYMLINK_ENVIRONMENT_TEST_UNAVAILABLE: {os.name}: {exc}")
            context = RepositoryContext(repo, ("specs",), (), (".md",))
            self.assertEqual(["specs/overview.md"], [a.discovered_path for a in discover(context)])
