from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditConfiguration:
    source: Path
    raw: dict[str, Any]
    repository: dict[str, Any]
    required_paths: tuple[str, ...]
    schema_bindings: tuple[dict[str, Any], ...]
    reference_bindings: tuple[dict[str, Any], ...]
    severity_mapping: dict[str, str]
    report: dict[str, Any]
    fail_on: frozenset[str]


@dataclass(frozen=True)
class RepositoryContext:
    root: Path
    include_roots: tuple[str, ...]
    exclude_roots: tuple[str, ...]
    suffixes: tuple[str, ...]
    case_policy: str = "lexical-sensitive"
    symlink_policy: str = "do-not-follow"


@dataclass(frozen=True)
class DiscoveredArtifact:
    discovered_path: str
    host_path: Path
    suffix: str
    text: str


@dataclass(frozen=True)
class ParsedDocument:
    artifact: DiscoveredArtifact
    representation: str
    value: Any | None
    parse_ok: bool


@dataclass(frozen=True)
class MarkdownLinkTarget:
    source: DiscoveredArtifact
    raw_target: str
    resolution_mode: str
    normalized_target: str | None


class ReportWriteError(Exception):
    """Raised when an accepted report destination cannot be written."""


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    check_id: str
    discovered_path: str | None = None
    line: int | None = None
    column: int | None = None
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def comparison_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "check_id": self.check_id,
            "code": self.code,
            "severity": self.severity,
        }
        if self.discovered_path is not None:
            result["discovered_path"] = self.discovered_path
        if self.line is not None:
            result["line"] = self.line
        if self.column is not None:
            result["column"] = self.column
        result["message"] = self.message
        if self.details:
            result["details"] = self.details
        return result


@dataclass(frozen=True)
class AuditResult:
    discovered_paths: tuple[str, ...]
    findings: tuple[Finding, ...]
    outcome: str
    exit_code: int
    scan_started: bool = True

    def comparison_dict(self) -> dict[str, Any]:
        return {
            "result_format_version": "0.1",
            "discovered_paths": list(self.discovered_paths),
            "findings": [finding.comparison_dict() for finding in self.findings],
            "outcome": self.outcome,
            "exit_code": self.exit_code,
        }
