from __future__ import annotations

import json
import unittest

from conformrepo.model import AuditResult, DiscoveredArtifact, Finding
from conformrepo.paths import PathEscapesRoot, normalize_repository_path, resolve_reference, selector_matches
from conformrepo.references import extract_markdown_links
from conformrepo.reporting import finding_sort_key, render_json, render_text


class PathTests(unittest.TestCase):
    def test_slash_normalization(self) -> None:
        self.assertEqual("specs/sensor.yaml", normalize_repository_path(r"specs\sensor.yaml"))

    def test_dot_normalization(self) -> None:
        self.assertEqual("specs/sensor.yaml", normalize_repository_path("./sensor.yaml", "specs"))

    def test_contained_parent(self) -> None:
        self.assertEqual("specs/sensor.yaml", normalize_repository_path("nested/../sensor.yaml", "specs"))

    def test_root_escape(self) -> None:
        with self.assertRaises(PathEscapesRoot):
            normalize_repository_path("../../../outside.txt", "specs")

    def test_case_is_preserved(self) -> None:
        self.assertNotEqual(normalize_repository_path("specs/Sensor.yaml"), normalize_repository_path("specs/sensor.yaml"))

    def test_document_relative(self) -> None:
        self.assertEqual("specs/sensor.yaml", resolve_reference("specs/overview.md", "./sensor.yaml", "document-relative"))

    def test_root_relative(self) -> None:
        self.assertEqual("references/glossary.md", resolve_reference("specs/overview.md", "/references/glossary.md", "repository-root-relative"))


class SelectorAndReferenceTests(unittest.TestCase):
    def test_markdown_glob(self) -> None:
        self.assertTrue(selector_matches("specs/overview.md", "**/*.md"))

    def test_frontmatter_selector(self) -> None:
        self.assertTrue(selector_matches("docs/item.md", "**/*.md#frontmatter"))

    def test_exact_selector_is_case_sensitive(self) -> None:
        self.assertFalse(selector_matches("specs/Sensor.yaml", "specs/sensor.yaml"))

    def test_markdown_extraction_ignores_http(self) -> None:
        artifact = DiscoveredArtifact("specs/a.md", None, ".md", "[local](b.md) [web](https://example.com)")  # type: ignore[arg-type]
        targets = extract_markdown_links(artifact, "document-relative")
        self.assertEqual(["b.md"], [target.raw_target for target in targets])


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = Finding("error", "Z", "check", "specs/a.md", message="Message", details={"b": 2, "a": 1})
        self.result = AuditResult(("specs/a.md",), (self.finding,), "CONFORMANCE_FAIL", 1)

    def test_json_is_stable(self) -> None:
        self.assertEqual(render_json(self.result), render_json(self.result))
        self.assertNotIn("timestamp", render_json(self.result))

    def test_text_rendering_stability(self) -> None:
        first = render_text(self.result)
        self.assertEqual(first, render_text(self.result))
        self.assertIn("error Z specs/a.md Message", first)
        self.assertNotIn(":\\", first)

    def test_sort_contract(self) -> None:
        other = Finding("error", "A", "check", "specs/b.md", message="Message")
        self.assertLess(finding_sort_key(self.finding), finding_sort_key(other))

    def test_json_detail_keys_are_canonical(self) -> None:
        parsed = json.loads(render_json(self.result))
        self.assertEqual({"a": 1, "b": 2}, parsed["findings"][0]["details"])
