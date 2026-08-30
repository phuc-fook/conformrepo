from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import yaml

from conformrepo import run_audit
from conformrepo.cli import main


def write_case(
    root: Path,
    *,
    destination: str = "stdout",
    include_roots: list[str] | None = None,
    exclude_roots: list[str] | None = None,
) -> Path:
    repo = root / "repo"
    (repo / "specs").mkdir(parents=True)
    (repo / "specs/overview.md").write_text("# Device\n", encoding="utf-8")
    raw = {
        "configuration_version": "0.1",
        "repository": {
            "root": "repo",
            "include_roots": include_roots or ["specs"],
            "exclude_roots": exclude_roots or [],
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


class UnsafeDestinationCliTests(unittest.TestCase):
    def assert_cli_rejection(self, config: Path, output: Path) -> None:
        stderr = io.StringIO()
        with patch("conformrepo.audit.repository_entries") as entries, redirect_stderr(stderr):
            exit_code = main(["check", "--config", str(config)])
        self.assertEqual(2, exit_code)
        self.assertIn("UNSAFE_REPORT_DESTINATION", stderr.getvalue())
        self.assertTrue(stderr.getvalue().strip())
        self.assertFalse(output.exists())
        entries.assert_not_called()

    def test_destination_inside_scan_set_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, destination="specs/audit.json")
            self.assert_cli_rejection(config, root / "repo/specs/audit.json")

    def test_lexical_root_escape_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, destination="../audit.json")
            self.assert_cli_rejection(config, root / "audit.json")

    def test_symlink_ancestor_rejection_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(
                root,
                destination="reports/audit.json",
                include_roots=["specs", "reports"],
                exclude_roots=["reports"],
            )
            symlink_ancestor = root / "repo/reports"
            with patch.object(Path, "is_symlink", autospec=True, side_effect=lambda path: path == symlink_ancestor):
                self.assert_cli_rejection(config, root / "repo/reports/audit.json")


class ReportWriteFailureCliTests(unittest.TestCase):
    def test_accepted_destination_write_failure_is_exit_three(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, destination="out/audit.json")
            stderr = io.StringIO()
            with patch.object(Path, "write_text", side_effect=OSError("simulated report write failure")), redirect_stderr(stderr):
                exit_code = main(["check", "--config", str(config)])
            self.assertEqual(3, exit_code)
            self.assertIn("tool/write failure", stderr.getvalue())
            self.assertIn("could not write report", stderr.getvalue())
            self.assertFalse((root / "repo/out/audit.json").exists())


class MarkdownFragmentTests(unittest.TestCase):
    def test_local_file_targets_strip_query_and_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root)
            overview = root / "repo/specs/overview.md"
            overview.write_text(
                "[same](#section)\n"
                "[existing](other.md#section)\n"
                "[missing](missing.md#section)\n"
                "[query](other.md?query=value#section)\n"
                "[web](https://example.com/other.md#section)\n",
                encoding="utf-8",
            )
            (root / "repo/specs/other.md").write_text("# Section\n", encoding="utf-8")
            raw = yaml.safe_load(config.read_text(encoding="utf-8"))
            raw["reference_bindings"] = [{
                "id": "markdown-links",
                "select": "**/*.md",
                "extractor": "markdown-link",
                "relative_mode": "document-relative",
            }]
            config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

            result = run_audit(config)

            self.assertEqual(1, result.exit_code)
            self.assertEqual(1, len(result.findings))
            finding = result.findings[0]
            self.assertEqual("REFERENCE_TARGET_MISSING", finding.code)
            self.assertEqual("missing.md#section", finding.details["raw_target"])
            self.assertEqual("specs/missing.md", finding.details["normalized_target"])


if __name__ == "__main__":
    unittest.main()
