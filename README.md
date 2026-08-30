# ConformRepo
[![test](https://github.com/phuc-fook/conformrepo/actions/workflows/test.yml/badge.svg?branch=main&event=push)](https://github.com/phuc-fook/conformrepo/actions/workflows/test.yml)
ConformRepo validates configured repository structure, structured metadata and schemas, and file/reference integrity through a deterministic read-only workflow. It is an alpha, pre-1.0 command-line project for specification-heavy and AI-assisted repositories.

## The problem

Structured repositories often mix Markdown, YAML, and JSON. As schemas evolve and files move, required content disappears, references become stale, and high-volume human or AI-assisted edits make inconsistencies harder to review. CI needs the same findings in the same order on every run.

## What the tool does

ConformRepo scans explicitly included files without following symlinks, checks required paths, validates selected YAML/JSON/Markdown frontmatter against local JSON Schemas, and verifies local file targets extracted from configured inline Markdown links. It emits one deterministic finding model and applies a configurable severity/exit policy.

## Non-goals

- No auto-fix or repository mutation.
- No semantic inference from content.
- No arbitrary plugin or repository-content execution.
- No remote schema fetching or external-file schema references.
- No hidden path-derived identity: a file's current location comes from the scan.
- Not a cross-system domain-contract reconciler or architecture dependency analyzer.
- Not an AI semantic evaluator or LLM-output validator.
- Not a general static-analysis framework or policy engine.

## Quickstart

Python 3.11 or newer is required. From a cloned source repository:

```console
python -m pip install -e .
conformrepo check --config examples/device-spec/conformrepo.yaml
```

The example is clean and exits `0`. To see a reference finding, change `./sensor.yaml` in `examples/device-spec/specs/overview.md` to `./missing.yaml` and rerun the command.

## Minimal configuration

```yaml
configuration_version: "0.1"
repository:
  root: .
  include_roots: [specs]
  exclude_roots: [reports]
  suffixes: [.md, .yaml, .json]
  case_policy: lexical-sensitive
  symlink_policy: do-not-follow
required_paths: [specs/overview.md]
reference_bindings:
  - id: markdown-links
    select: "**/*.md"
    extractor: markdown-link
    relative_mode: by-syntax
report:
  destination: stdout
  format: json
exit_policy:
  fail_on: [error]
```

See [the configuration reference](docs/configuration.md) for the complete implemented surface.

## Outputs

`json` is deterministic and suitable for automation. `text` renders the same ordered findings as concise lines containing severity, code, path, and message. Stable output omits timestamps, usernames, temporary paths, and absolute repository roots.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Pass: no finding has a severity listed in `exit_policy.fail_on`. |
| `1` | Conformance failure: repository/input findings meet the configured failure policy. |
| `2` | Configuration error: the run cannot be interpreted safely, including an unsafe report destination. |
| `3` | Unexpected tool, runtime, rendering, or write failure. |

## Key design behavior

- Current file location is derived from the filesystem scan. A stale `source_path`, `path`, or similar content field does not relocate the file or require repair.
- Cross-file references are extracted and checked independently from declared self-path metadata.
- Markdown link checks cover inline link syntax only. They validate the local file target after removing query and fragment components; they do not validate heading anchors.
- Repository paths use normalized `/` separators and exact lexical case.
- Findings and details have stable ordering for repeatable CI output.
- Reports default to stdout. File destinations are rejected if they could join the scan set, escape the repository lexically, or traverse an existing symlink.

## Development

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

The test corpus is neutral and lives entirely under `tests/fixtures/`. See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing new checks.

## Status

ConformRepo is alpha and pre-1.0. Interfaces may change while the initial public release and compatibility policy are established.
