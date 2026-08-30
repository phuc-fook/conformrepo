from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

from conformrepo import run_audit
from conformrepo.model import AuditResult
from conformrepo.reporting import render_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = PROJECT_ROOT / "tests" / "fixtures"
FIXTURES_ROOT = CORPUS_ROOT / "fixtures"


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and _contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(_contains(a, e) for a, e in zip(actual, expected))
    return actual == expected


def _assert_result(result: AuditResult, expected: dict[str, Any]) -> None:
    assert list(result.discovered_paths) == expected.get("expected_discovered_paths", []), (result.discovered_paths, expected)
    actual_findings = [finding.comparison_dict() for finding in result.findings]
    expected_findings = expected.get("expected_findings", [])
    assert len(actual_findings) == len(expected_findings), (actual_findings, expected_findings)
    for actual, wanted in zip(actual_findings, expected_findings):
        assert _contains(actual, wanted), (actual, wanted)
    assert result.outcome == expected["expected_outcome"], (result.outcome, expected["expected_outcome"])
    forbidden_codes = set(expected.get("forbidden_finding_codes", []))
    assert not forbidden_codes.intersection(f.code for f in result.findings)
    for forbidden in expected.get("forbidden_findings", []):
        if not isinstance(forbidden, dict) or "code" not in forbidden:
            continue
        assert not any(_contains(f.comparison_dict(), forbidden) for f in result.findings)


def run_fixture(fixture_id: str) -> dict[str, Any]:
    directory = next(FIXTURES_ROOT.glob(f"{fixture_id}_*"))
    expected = yaml.safe_load((directory / "expected.yaml").read_text(encoding="utf-8"))
    runs: list[tuple[str, AuditResult]] = []
    extra: dict[str, Any] = {}
    if fixture_id == "F13":
        identity = expected["finding_identity_except_severity"]
        for variant in expected["variants"]:
            result = run_audit(directory / variant["config"])
            wanted = {
                "expected_discovered_paths": expected["expected_discovered_paths"],
                "expected_findings": [{**identity, "severity": variant["severity"]}],
                "expected_outcome": variant["expected_outcome"],
            }
            _assert_result(result, wanted)
            runs.append((variant["config"], result))
        a = runs[0][1].findings[0].comparison_dict()
        b = runs[1][1].findings[0].comparison_dict()
        assert {k: v for k, v in a.items() if k != "severity"} == {k: v for k, v in b.items() if k != "severity"}
    elif fixture_id == "F14":
        before = directory / "state-before" / "docs/a/item.md"
        after = directory / "state-after" / "docs/b/item.md"
        assert before.read_bytes() == after.read_bytes()
        extra["byte_sha256"] = hashlib.sha256(before.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / "synthetic_corpus"
            shutil.copytree(CORPUS_ROOT, staged)
            staged_fixture = next((staged / "fixtures").glob("F14_*"))
            for state in expected["states"]:
                target = staged_fixture / "state"
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(staged_fixture / state["root"], target)
                result = run_audit(staged_fixture / "config.yaml")
                wanted = {
                    "expected_discovered_paths": state["expected_discovered_paths"],
                    "expected_findings": state["expected_findings"],
                    "expected_outcome": state["expected_outcome"],
                }
                _assert_result(result, wanted)
                runs.append((state["root"], result))
    else:
        result = run_audit(directory / "config.yaml")
        _assert_result(result, expected)
        if fixture_id == "F20":
            assert not result.scan_started
            assert not (directory / "repo/specs/audit.json").exists()
        runs.append(("default", result))
    return {
        "fixture_id": fixture_id,
        "run_status": "PASS",
        "discovered_path_match": True,
        "finding_match": True,
        "outcome_match": True,
        "forbidden_finding_check": "PASS",
        "final": "PASS",
        "runs": [{"variant": name, "comparison": result.comparison_dict()} for name, result in runs],
        **extra,
    }


def run_all() -> list[dict[str, Any]]:
    return [run_fixture(f"F{i:02d}") for i in range(1, 21)]


def determinism_replays() -> dict[str, Any]:
    ids = ["F01", "F08", "F13", "F16", "F20"]
    results: dict[str, Any] = {}
    for fixture_id in ids:
        first = run_fixture(fixture_id)
        second = run_fixture(fixture_id)
        assert first["runs"] == second["runs"]
        results[fixture_id] = "BYTE_EQUIVALENT_COMPARISON_CRITICAL_OUTPUT"
    f12 = next(FIXTURES_ROOT.glob("F12_*"))
    forward = run_audit(f12 / "config.yaml", reverse_discovery=False)
    reverse = run_audit(f12 / "config.yaml", reverse_discovery=True)
    assert render_json(forward) == render_json(reverse)
    results["F12_FORWARD_REVERSE"] = "BYTE_EQUIVALENT_COMPARISON_CRITICAL_OUTPUT"
    return results


if __name__ == "__main__":
    print(json.dumps({"fixtures": run_all(), "determinism": determinism_replays()}, indent=2, sort_keys=True))
