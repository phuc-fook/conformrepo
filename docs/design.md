# Design notes

ConformRepo is a generic engine driven by user-supplied repository boundaries, local schemas, reference bindings, severity mappings, and exit policy. It does not embed project-specific rules.

Audits are read-only. Discovery observes current files without following symlinks, assigns normalized repository-relative lexical paths, and never takes location from document metadata. Moving unchanged bytes therefore changes the discovered path on the next scan without requiring a metadata rewrite. Cross-file reference freshness remains a separate check.

Lexical path comparison makes case behavior predictable across operating systems. Findings are sorted and serialized deterministically without comparison-critical timestamps or machine-specific paths.

Schema files are explicit trusted local configuration resources. Remote or external-file schema references are rejected. Repository content is parsed as data and is not executed.

Reports default to stdout. A file destination is validated against include/exclude boundaries and lexical containment. Existing output-path ancestors are also checked without following symlinks so a lexically safe path cannot redirect a write outside the repository. This physical write guard does not change the lexical identity model used during scanning.
