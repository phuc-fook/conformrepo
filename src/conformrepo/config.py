from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .model import AuditConfiguration, RepositoryContext
from .paths import normalize_repository_path


SUPPORTED_SEVERITIES = frozenset({"error", "warning", "information"})
SUPPORTED_REFERENCE_MODES = frozenset({"document-relative", "by-leading-slash", "by-syntax", "repository-root-relative"})


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return value


def _binding_list(raw: dict[str, Any], field: str, required: tuple[str, ...]) -> list[dict[str, Any]]:
    value = raw.get(field, [])
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    for index, binding in enumerate(value):
        if not isinstance(binding, dict):
            raise ValueError(f"{field}[{index}] must be a mapping")
        missing = [name for name in required if not isinstance(binding.get(name), str) or not binding[name]]
        if missing:
            raise ValueError(f"{field}[{index}] missing required string field(s): {', '.join(missing)}")
    return value


def _validate_shape_and_enums(raw: dict[str, Any]) -> None:
    repository = raw.get("repository")
    if not isinstance(repository, dict):
        raise ValueError("repository must be a mapping")
    if not isinstance(repository.get("root", "."), str):
        raise ValueError("repository.root must be a string")
    _string_list(repository.get("include_roots", ["."]), "repository.include_roots")
    _string_list(repository.get("exclude_roots", []), "repository.exclude_roots")
    _string_list(repository.get("suffixes", []), "repository.suffixes")
    if repository.get("case_policy", "lexical-sensitive") != "lexical-sensitive":
        raise ValueError("Unsupported repository.case_policy")
    if repository.get("symlink_policy", "do-not-follow") != "do-not-follow":
        raise ValueError("Unsupported repository.symlink_policy")

    _string_list(raw.get("required_paths", []), "required_paths")
    schema_bindings = _binding_list(raw, "schema_bindings", ("id", "select", "schema"))
    reference_bindings = _binding_list(raw, "reference_bindings", ("id", "select", "extractor", "relative_mode"))
    for binding in schema_bindings:
        resource = binding["schema"]
        parsed = urlsplit(resource)
        if parsed.scheme or resource.startswith("//"):
            raise ValueError("Schema resources must be explicit local paths")
    for binding in reference_bindings:
        if binding["extractor"] != "markdown-link":
            raise ValueError("Unsupported reference extractor")
        if binding["relative_mode"] not in SUPPORTED_REFERENCE_MODES:
            raise ValueError("Unsupported reference resolution mode")

    severity_mapping = raw.get("severity_mapping", {})
    if not isinstance(severity_mapping, dict) or not all(isinstance(key, str) and value in SUPPORTED_SEVERITIES for key, value in severity_mapping.items()):
        raise ValueError("severity_mapping values must be supported severities")
    exit_policy = raw.get("exit_policy", {"fail_on": ["error"]})
    if not isinstance(exit_policy, dict):
        raise ValueError("exit_policy must be a mapping")
    fail_on = _string_list(exit_policy.get("fail_on", ["error"]), "exit_policy.fail_on")
    if not set(fail_on).issubset(SUPPORTED_SEVERITIES):
        raise ValueError("exit_policy.fail_on contains an unsupported severity")
    report = raw.get("report", {"destination": "stdout", "format": "json"})
    if not isinstance(report, dict):
        raise ValueError("report must be a mapping")
    if not isinstance(report.get("destination", "stdout"), str):
        raise ValueError("report.destination must be a string")
    if report.get("format", "json") not in {"json", "text"}:
        raise ValueError("Unsupported report.format")


def load_configuration(source: str | Path) -> tuple[AuditConfiguration, RepositoryContext]:
    config_path = Path(source).resolve()
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError("Configuration YAML cannot be parsed") from exc
    if not isinstance(raw, dict) or str(raw.get("configuration_version")) != "0.1":
        raise ValueError("Unsupported or missing configuration_version")
    _validate_shape_and_enums(raw)
    repo = raw.get("repository") or {}
    root = (config_path.parent / str(repo.get("root", "."))).resolve()
    includes = tuple(normalize_repository_path(str(p)) for p in repo.get("include_roots", ["."]))
    excludes = tuple(normalize_repository_path(str(p)) for p in repo.get("exclude_roots", []))
    config = AuditConfiguration(
        source=config_path,
        raw=raw,
        repository=repo,
        required_paths=tuple(raw.get("required_paths", [])),
        schema_bindings=tuple(raw.get("schema_bindings", [])),
        reference_bindings=tuple(raw.get("reference_bindings", [])),
        severity_mapping={str(k): str(v) for k, v in (raw.get("severity_mapping") or {}).items()},
        report=raw.get("report") or {"destination": "stdout", "format": "json"},
        fail_on=frozenset((raw.get("exit_policy") or {}).get("fail_on", ["error"])),
    )
    context = RepositoryContext(
        root=root,
        include_roots=includes,
        exclude_roots=excludes,
        suffixes=tuple(str(s) for s in repo.get("suffixes", [])),
        case_policy=str(repo.get("case_policy", "lexical-sensitive")),
        symlink_policy=str(repo.get("symlink_policy", "do-not-follow")),
    )
    return config, context


def load_local_schema(config: AuditConfiguration, binding: dict[str, Any]) -> dict[str, Any]:
    resource = str(binding["schema"])
    parsed_resource = urlsplit(resource)
    if parsed_resource.scheme or resource.startswith("//"):
        raise ValueError("Remote schema retrieval is not supported")
    schema_path = (config.source.parent / resource).resolve()
    import json

    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    def reject_remote_refs(value: Any) -> None:
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                raise ValueError("Only fragment-only internal schema references are supported")
            for child in value.values():
                reject_remote_refs(child)
        elif isinstance(value, list):
            for child in value:
                reject_remote_refs(child)

    reject_remote_refs(schema)
    return schema
