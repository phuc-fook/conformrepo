from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath


class PathEscapesRoot(ValueError):
    pass


def normalize_repository_path(raw: str, base: str = "") -> str:
    """Normalize a lexical repository path without consulting the host filesystem."""
    value = str(raw).replace("\\", "/")
    rooted = value.startswith("/")
    if rooted:
        value = value.lstrip("/")
        parts: list[str] = []
    else:
        parts = [part for part in base.replace("\\", "/").split("/") if part not in ("", ".")]
    if len(value) >= 2 and value[1] == ":":
        raise PathEscapesRoot(raw)
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise PathEscapesRoot(raw)
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def is_same_or_below(path: str, root: str) -> bool:
    # The empty lexical path is the normalized marker for the repository root.
    return root == "" or path == root or path.startswith(root + "/")


def selector_matches(path: str, selector: str) -> bool:
    selector = selector.removesuffix("#frontmatter").replace("\\", "/")
    if not any(char in selector for char in "*?["):
        return path == selector
    if selector.startswith("**/"):
        return fnmatch.fnmatchcase(path, selector) or fnmatch.fnmatchcase(path, selector[3:])
    return fnmatch.fnmatchcase(path, selector)


def resolve_reference(source_path: str, raw_target: str, mode: str) -> str:
    if mode == "repository-root-relative" or mode == "by-leading-slash" and raw_target.startswith("/"):
        return normalize_repository_path("/" + raw_target.lstrip("/"))
    base = str(PurePosixPath(source_path).parent)
    if base == ".":
        base = ""
    return normalize_repository_path(raw_target, base)
