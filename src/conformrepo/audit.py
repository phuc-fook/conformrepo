from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml

from .config import load_configuration, load_local_schema
from .intake import discover, repository_entries
from .model import AuditResult, DiscoveredArtifact, Finding, ParsedDocument, ReportWriteError
from .paths import PathEscapesRoot, is_same_or_below, normalize_repository_path, selector_matches
from .references import extract_markdown_links
from .reporting import finding_sort_key, render_json, render_text


def _severity(config: Any, code: str) -> str:
    return config.severity_mapping.get(code, "error")


def _unsafe_report_finding(config: Any, context: Any) -> Finding | None:
    destination = str(config.report.get("destination", "stdout"))
    if destination == "stdout":
        return None
    try:
        normalized = normalize_repository_path(destination)
    except PathEscapesRoot:
        return Finding(
            severity="error",
            code="UNSAFE_REPORT_DESTINATION",
            check_id="configuration",
            message="Report destination escapes repository root.",
            details={"destination": destination.replace("\\", "/")},
        )
    in_include = any(is_same_or_below(normalized, include) for include in context.include_roots)
    in_exclusion = any(is_same_or_below(normalized, excluded) for excluded in context.exclude_roots)
    if in_include and not in_exclusion:
        return Finding(
            severity="error",
            code="UNSAFE_REPORT_DESTINATION",
            check_id="configuration",
            message="Report destination is inside the effective scan set.",
            details={"destination": normalized},
        )
    current = context.root
    for part in PurePosixPath(normalized).parts:
        current = current / part
        if current.is_symlink():
            return Finding(
                severity="error",
                code="UNSAFE_REPORT_DESTINATION",
                check_id="configuration",
                message="Report destination traverses a filesystem symlink.",
                details={"destination": normalized},
            )
        if not current.exists():
            break
    return None


def _parse_for_binding(artifact: DiscoveredArtifact, frontmatter: bool) -> ParsedDocument:
    try:
        if frontmatter:
            if not artifact.text.startswith("---"):
                raise yaml.YAMLError("frontmatter opening delimiter is absent")
            lines = artifact.text.splitlines()
            try:
                closing = lines.index("---", 1)
            except ValueError as exc:
                raise yaml.YAMLError("frontmatter closing delimiter is absent") from exc
            value = yaml.safe_load("\n".join(lines[1:closing]))
            if not isinstance(value, dict):
                raise yaml.YAMLError("frontmatter is not a mapping")
            return ParsedDocument(artifact, "frontmatter", value, True)
        if artifact.suffix in (".yaml", ".yml"):
            return ParsedDocument(artifact, "yaml", yaml.safe_load(artifact.text), True)
        if artifact.suffix == ".json":
            return ParsedDocument(artifact, "json", json.loads(artifact.text), True)
        return ParsedDocument(artifact, "text", artifact.text, True)
    except (yaml.YAMLError, json.JSONDecodeError):
        return ParsedDocument(artifact, "frontmatter" if frontmatter else artifact.suffix.lstrip("."), None, False)


def _parse_message(parsed: ParsedDocument) -> str:
    if parsed.representation == "frontmatter":
        return "Could not parse Markdown frontmatter."
    if parsed.representation in ("yaml", "yml"):
        return "Could not parse YAML input."
    return "Could not parse JSON input."


def _schema_findings(config: Any, artifacts: list[DiscoveredArtifact]) -> list[Finding]:
    findings: list[Finding] = []
    for binding in config.schema_bindings:
        selector = str(binding["select"])
        frontmatter = selector.endswith("#frontmatter")
        schema = load_local_schema(config, binding)
        validator = jsonschema.validators.validator_for(schema)(schema)
        for artifact in artifacts:
            if not selector_matches(artifact.discovered_path, selector):
                continue
            parsed = _parse_for_binding(artifact, frontmatter)
            if not parsed.parse_ok:
                findings.append(Finding(
                    severity=_severity(config, "INPUT_PARSE_ERROR"),
                    code="INPUT_PARSE_ERROR",
                    check_id="schema",
                    discovered_path=artifact.discovered_path,
                    message=_parse_message(parsed),
                ))
                continue
            errors = sorted(validator.iter_errors(parsed.value), key=lambda e: (list(e.absolute_path), e.message))
            for error in errors:
                details: dict[str, Any] = {"schema_id": str(binding["id"]), "keyword": str(error.validator)}
                if error.validator == "required":
                    missing = [name for name in error.validator_value if name not in error.instance]
                    if missing:
                        details["missing_property"] = missing[0]
                findings.append(Finding(
                    severity=_severity(config, "SCHEMA_VALIDATION_FAILED"),
                    code="SCHEMA_VALIDATION_FAILED",
                    check_id="schema",
                    discovered_path=artifact.discovered_path,
                    message=f"Document does not satisfy schema: {binding['id']}",
                    details=details,
                ))
    return findings


def _reference_findings(config: Any, artifacts: list[DiscoveredArtifact]) -> list[Finding]:
    findings: list[Finding] = []
    effective_paths = {artifact.discovered_path for artifact in artifacts}
    for binding in config.reference_bindings:
        if binding.get("extractor") != "markdown-link":
            continue
        mode = str(binding.get("relative_mode", "document-relative"))
        for artifact in artifacts:
            if not selector_matches(artifact.discovered_path, str(binding["select"])):
                continue
            for target in extract_markdown_links(artifact, mode):
                actual_mode = "repository-root-relative" if target.raw_target.startswith("/") and mode in ("by-syntax", "by-leading-slash") else "document-relative" if mode in ("by-syntax", "by-leading-slash") else mode
                if target.normalized_target is None:
                    findings.append(Finding(
                        severity=_severity(config, "REFERENCE_ESCAPES_ROOT"),
                        code="REFERENCE_ESCAPES_ROOT",
                        check_id="reference",
                        discovered_path=artifact.discovered_path,
                        message="Reference target escapes repository root.",
                        details={"raw_target": target.raw_target, "resolution_mode": actual_mode},
                    ))
                elif target.normalized_target not in effective_paths:
                    findings.append(Finding(
                        severity=_severity(config, "REFERENCE_TARGET_MISSING"),
                        code="REFERENCE_TARGET_MISSING",
                        check_id="reference",
                        discovered_path=artifact.discovered_path,
                        message=f"Reference target does not exist: {target.normalized_target}",
                        details={"raw_target": target.raw_target, "normalized_target": target.normalized_target, "resolution_mode": actual_mode},
                    ))
    return findings


def _write_report_file(output: Path, rendered: str) -> None:
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ReportWriteError(f"could not write report: {exc}") from exc


def run_audit(config_path: str | Path, *, write_report: bool = False, reverse_discovery: bool = False) -> AuditResult:
    config, context = load_configuration(config_path)
    unsafe = _unsafe_report_finding(config, context)
    if unsafe is not None:
        return AuditResult((), (unsafe,), "CONFIGURATION_ERROR_OR_UNSAFE_OUTPUT_DESTINATION", 2, scan_started=False)

    # Configuration resources are preflighted before any repository enumeration.
    for binding in config.schema_bindings:
        load_local_schema(config, binding)

    entries = repository_entries(context)
    findings: list[Finding] = []
    for raw in config.required_paths:
        normalized = normalize_repository_path(raw)
        if normalized not in entries:
            code = "REQUIRED_PATH_MISSING"
            findings.append(Finding(
                severity=_severity(config, code), code=code, check_id="required-path",
                message=f"Required path does not exist: {normalized}", details={"required_path": normalized},
            ))

    artifacts = discover(context, reverse=reverse_discovery)
    unique = {artifact.discovered_path: artifact for artifact in artifacts}
    artifacts = [unique[path] for path in sorted(unique)]
    findings.extend(_schema_findings(config, artifacts))
    findings.extend(_reference_findings(config, artifacts))
    ordered = tuple(sorted(findings, key=finding_sort_key))
    failing = any(finding.severity in config.fail_on for finding in ordered)
    outcome = "CONFORMANCE_FAIL" if failing else "PASS"
    result = AuditResult(tuple(artifact.discovered_path for artifact in artifacts), ordered, outcome, 1 if failing else 0)

    destination = str(config.report.get("destination", "stdout"))
    if write_report and destination != "stdout":
        output = context.root.joinpath(*normalize_repository_path(destination).split("/"))
        renderer = render_text if config.report.get("format") == "text" else render_json
        _write_report_file(output, renderer(result))
    return result
