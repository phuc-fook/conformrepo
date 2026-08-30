from __future__ import annotations

import json
from typing import Any

from .model import AuditResult, Finding


def canonical_details(details: dict[str, Any]) -> str:
    return json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def finding_sort_key(finding: Finding) -> tuple[Any, ...]:
    return (
        finding.discovered_path or "",
        finding.check_id,
        finding.code,
        finding.line if finding.line is not None else -1,
        finding.column if finding.column is not None else -1,
        finding.message,
        canonical_details(finding.details),
    )


def render_json(result: AuditResult) -> str:
    return json.dumps(result.comparison_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_text(result: AuditResult) -> str:
    lines = [f"outcome={result.outcome} exit_code={result.exit_code}"]
    for finding in result.findings:
        path = finding.discovered_path or "-"
        lines.append(f"{finding.severity} {finding.code} {path} {finding.message}")
    return "\n".join(lines) + "\n"
