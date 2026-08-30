from __future__ import annotations

import importlib.metadata
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import conformrepo
from conformrepo import run_audit
from conformrepo.config import load_configuration
from conformrepo.intake import discover
from conformrepo.model import RepositoryContext
from conformrepo.paths import is_same_or_below


def write_case(root: Path, overrides: dict | None = None) -> Path:
    repo = root / "repo"
    (repo / "specs").mkdir(parents=True)
    (repo / "specs/overview.md").write_text("# Device\n", encoding="utf-8")
    raw = {
        "configuration_version": "0.1",
        "repository": {
            "root": "repo", "include_roots": ["specs"], "exclude_roots": [],
            "suffixes": [".md"], "case_policy": "lexical-sensitive", "symlink_policy": "do-not-follow",
        },
        "report": {"destination": "stdout", "format": "json"},
        "exit_policy": {"fail_on": ["error"]},
    }
    for key, value in (overrides or {}).items():
        raw[key] = value
    path = root / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


class RootRelationshipTests(unittest.TestCase):
    def test_path_under_root_marker(self) -> None:
        self.assertTrue(is_same_or_below("specs/item.md", ""))

    def test_root_marker_itself(self) -> None:
        self.assertTrue(is_same_or_below("", ""))

    def test_ordinary_nested_include(self) -> None:
        self.assertTrue(is_same_or_below("specs/nested/item.md", "specs"))

    def test_ordinary_exclusion_relationship(self) -> None:
        self.assertFalse(is_same_or_below("specs/item.md", "archive"))

    def test_repository_root_exclusion_prunes_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "specs").mkdir()
            (repo / "root.md").write_text("# Root\n", encoding="utf-8")
            (repo / "specs/item.md").write_text("# Item\n", encoding="utf-8")
            context = RepositoryContext(repo, ("",), ("",), (".md",))
            self.assertEqual([], discover(context))


class ReportOutputHardeningTests(unittest.TestCase):
    def test_whole_root_include_rejects_root_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, {
                "repository": {"root": "repo", "include_roots": ["."], "exclude_roots": [], "suffixes": [".md", ".json"]},
                "report": {"destination": "audit.json", "format": "json"},
            })
            result = run_audit(config, write_report=True)
            self.assertEqual("UNSAFE_REPORT_DESTINATION", result.findings[0].code)
            self.assertFalse(result.scan_started)
            self.assertEqual(2, result.exit_code)
            self.assertFalse((root / "repo/audit.json").exists())

    def test_whole_root_include_allows_explicit_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, {
                "repository": {"root": "repo", "include_roots": ["."], "exclude_roots": ["reports"], "suffixes": [".md", ".json"]},
                "report": {"destination": "reports/audit.json", "format": "json"},
            })
            result = run_audit(config)
            self.assertTrue(result.scan_started)
            self.assertEqual("PASS", result.outcome)

    def test_report_destination_root_escape_pre_scan_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_case(root, {"report": {"destination": "../audit.json", "format": "json"}})
            result = run_audit(config, write_report=True)
            self.assertEqual("UNSAFE_REPORT_DESTINATION", result.findings[0].code)
            self.assertFalse(result.scan_started)
            self.assertEqual(2, result.exit_code)
            self.assertFalse((root / "audit.json").exists())

    def test_whole_root_error_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = write_case(Path(tmp), {
                "repository": {"root": "repo", "include_roots": ["."], "exclude_roots": [], "suffixes": [".json"]},
                "report": {"destination": "audit.json", "format": "json"},
            })
            self.assertEqual(run_audit(config).comparison_dict(), run_audit(config).comparison_dict())


class ConfigurationEnumTests(unittest.TestCase):
    def assert_invalid(self, overrides: dict) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = write_case(Path(tmp), overrides)
            with self.assertRaises(ValueError):
                load_configuration(config)

    def test_rejects_unknown_case_policy(self) -> None:
        self.assert_invalid({"repository": {"root": "repo", "include_roots": ["specs"], "exclude_roots": [], "suffixes": [".md"], "case_policy": "host-default"}})

    def test_rejects_unknown_symlink_policy(self) -> None:
        self.assert_invalid({"repository": {"root": "repo", "include_roots": ["specs"], "exclude_roots": [], "suffixes": [".md"], "symlink_policy": "follow"}})

    def test_rejects_unknown_report_format(self) -> None:
        self.assert_invalid({"report": {"destination": "stdout", "format": "xml"}})

    def test_rejects_unknown_reference_extractor(self) -> None:
        self.assert_invalid({"reference_bindings": [{"id": "links", "select": "**/*.md", "extractor": "script", "relative_mode": "document-relative"}]})

    def test_rejects_unknown_reference_mode(self) -> None:
        self.assert_invalid({"reference_bindings": [{"id": "links", "select": "**/*.md", "extractor": "markdown-link", "relative_mode": "host-relative"}]})

    def test_rejects_unknown_severity(self) -> None:
        self.assert_invalid({"severity_mapping": {"REQUIRED_PATH_MISSING": "fatal"}})

    def test_rejects_unknown_exit_policy_severity(self) -> None:
        self.assert_invalid({"exit_policy": {"fail_on": ["fatal"]}})


class BindingShapeTests(unittest.TestCase):
    def assert_invalid_binding(self, field: str, binding: dict) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = write_case(Path(tmp), {field: [binding]})
            with self.assertRaises(ValueError):
                load_configuration(config)

    def test_schema_binding_requires_id(self) -> None:
        self.assert_invalid_binding("schema_bindings", {"select": "specs/a.json", "schema": "schema.json"})

    def test_schema_binding_requires_select(self) -> None:
        self.assert_invalid_binding("schema_bindings", {"id": "a", "schema": "schema.json"})

    def test_schema_binding_requires_schema(self) -> None:
        self.assert_invalid_binding("schema_bindings", {"id": "a", "select": "specs/a.json"})

    def test_reference_binding_requires_id(self) -> None:
        self.assert_invalid_binding("reference_bindings", {"select": "**/*.md", "extractor": "markdown-link", "relative_mode": "document-relative"})

    def test_reference_binding_requires_extractor(self) -> None:
        self.assert_invalid_binding("reference_bindings", {"id": "a", "select": "**/*.md", "relative_mode": "document-relative"})

    def test_reference_binding_requires_mode(self) -> None:
        self.assert_invalid_binding("reference_bindings", {"id": "a", "select": "**/*.md", "extractor": "markdown-link"})


class SchemaIsolationTests(unittest.TestCase):
    def make_schema_case(self, schema: dict) -> tuple[tempfile.TemporaryDirectory, Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        config = write_case(root, {
            "repository": {"root": "repo", "include_roots": ["specs"], "exclude_roots": [], "suffixes": [".json"]},
            "schema_bindings": [{"id": "data", "select": "specs/data.json", "schema": "schema.json"}],
        })
        (root / "repo/specs/data.json").write_text("{}\n", encoding="utf-8")
        (root / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
        return temp, config

    def test_rejects_http_schema_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = write_case(Path(tmp), {"schema_bindings": [{"id": "data", "select": "specs/data.json", "schema": "https://example.invalid/schema.json"}]})
            with self.assertRaises(ValueError):
                load_configuration(config)

    def test_rejects_http_ref_before_scan(self) -> None:
        temp, config = self.make_schema_case({"$ref": "https://example.invalid/schema.json"})
        with temp, patch("conformrepo.audit.repository_entries") as entries:
            with self.assertRaises(ValueError):
                run_audit(config)
            entries.assert_not_called()

    def test_rejects_ftp_ref_before_scan(self) -> None:
        temp, config = self.make_schema_case({"$ref": "ftp://example.invalid/schema.json"})
        with temp, patch("conformrepo.audit.repository_entries") as entries:
            with self.assertRaises(ValueError):
                run_audit(config)
            entries.assert_not_called()

    def test_rejects_relative_file_ref_before_scan(self) -> None:
        temp, config = self.make_schema_case({"$ref": "other.json"})
        with temp, patch("conformrepo.audit.repository_entries") as entries:
            with self.assertRaises(ValueError):
                run_audit(config)
            entries.assert_not_called()

    def test_allows_fragment_only_internal_ref(self) -> None:
        schema = {"$ref": "#/$defs/item", "$defs": {"item": {"type": "object"}}}
        temp, config = self.make_schema_case(schema)
        with temp:
            self.assertEqual("PASS", run_audit(config).outcome)


class CleanInstallContractTests(unittest.TestCase):
    def test_clean_install_import(self) -> None:
        self.assertEqual("0.1.0", conformrepo.__version__)
        self.assertEqual("0.1.0", importlib.metadata.version("conformrepo"))

    def test_cli_entry_point_resolves(self) -> None:
        entries = [entry for entry in importlib.metadata.entry_points(group="console_scripts") if entry.name == "conformrepo"]
        self.assertEqual(1, len(entries))
        self.assertEqual("conformrepo.cli:main", entries[0].value)
