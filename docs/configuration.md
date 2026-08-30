# Configuration reference

The CLI accepts one local YAML configuration with `conformrepo check --config <path>`. Configuration selects trusted local resources; repository content remains data and is never executed.

## Top-level fields

### `configuration_version`

Required string. The only supported value is `"0.1"`.

### `repository`

Required mapping:

- `root`: repository directory, resolved relative to the configuration file. Defaults to `.`.
- `include_roots`: list of repository-relative lexical roots. `.` means the entire repository.
- `exclude_roots`: list pruned from included roots. An exclusion may also isolate a report directory.
- `suffixes`: eligible file suffixes such as `.md`, `.yaml`, and `.json`.
- `case_policy`: only `lexical-sensitive`.
- `symlink_policy`: only `do-not-follow`.

Paths use `/` in stable output. `.` segments are removed, contained `..` segments are reduced, and paths that escape the repository are rejected. Filename Unicode normalization is not performed.

### `required_paths`

Optional list of repository-relative files or directories that must exist. This check does not require document parsing.

### `schema_bindings`

Optional list. Each binding requires:

- `id`: stable binding name used in findings;
- `select`: exact repository-relative path, `**/*.md`, `**/*.md#frontmatter`, or the simple path/suffix patterns exercised by the current implementation;
- `schema`: local JSON Schema path resolved relative to the configuration file.

YAML uses safe loading; JSON uses the standard parser. `#frontmatter` validates only the YAML mapping between Markdown `---` delimiters. A schema may use fragment-only internal references such as `#/$defs/item`. URI and external-file schema references are rejected; no network retrieval occurs.

### `reference_bindings`

Optional list. Each binding requires:

- `id`;
- `select`;
- `extractor`: only `markdown-link`;
- `relative_mode`: one of `document-relative`, `repository-root-relative`, `by-leading-slash`, or `by-syntax`.

The extractor supports inline Markdown link syntax only. It validates the local file target, not anchor correctness: fragment-only links refer to the same document, while query and fragment components are removed from cross-file targets before lookup. HTTP and HTTPS links are ignored. Repository references are compared against the normalized discovered-path set with exact lexical case.

### `severity_mapping`

Optional mapping from finding code to `error`, `warning`, or `information`. The implemented codes are:

- `REQUIRED_PATH_MISSING`
- `INPUT_PARSE_ERROR`
- `SCHEMA_VALIDATION_FAILED`
- `REFERENCE_TARGET_MISSING`
- `REFERENCE_ESCAPES_ROOT`
- `UNSAFE_REPORT_DESTINATION`

### `report`

- `destination`: `stdout` by default, or a repository-relative file path.
- `format`: `json` or `text`.

A file destination must be outside effective include roots or beneath an explicit exclusion. It must remain lexically inside the repository and must not traverse an existing symlink. Unsafe output is rejected before scanning and no file is written.

### `exit_policy`

`fail_on` is a list containing any of `error`, `warning`, and `information`. A matching finding yields exit `1`; unsafe or uninterpretable configuration yields exit `2`.
