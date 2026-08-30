from __future__ import annotations

import unittest

from corpus_support import run_fixture


class CorpusConformanceTests(unittest.TestCase):
    pass


def _make_test(fixture_id: str):
    def test(self: CorpusConformanceTests) -> None:
        evidence = run_fixture(fixture_id)
        self.assertEqual("PASS", evidence["final"])

    test.__name__ = f"test_{fixture_id.lower()}"
    return test


for number in range(1, 21):
    fixture = f"F{number:02d}"
    setattr(CorpusConformanceTests, f"test_{fixture.lower()}", _make_test(fixture))
