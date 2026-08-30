from __future__ import annotations

import os
from pathlib import Path

from .model import DiscoveredArtifact, RepositoryContext
from .paths import is_same_or_below, normalize_repository_path


def repository_entries(context: RepositoryContext) -> set[str]:
    entries: set[str] = set()
    if not context.root.is_dir():
        return entries
    for current, dirs, files in os.walk(context.root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
        rel_dir = Path(current).relative_to(context.root).as_posix()
        if rel_dir != ".":
            entries.add(rel_dir)
        for name in sorted(files):
            path = Path(current) / name
            if not path.is_symlink():
                entries.add(path.relative_to(context.root).as_posix())
    return entries


def discover(context: RepositoryContext, reverse: bool = False) -> list[DiscoveredArtifact]:
    artifacts: list[DiscoveredArtifact] = []
    for include in context.include_roots:
        start = context.root / Path(include.replace("/", os.sep))
        if not start.is_dir() or start.is_symlink():
            continue
        for current, dirs, files in os.walk(start, followlinks=False):
            rel_current = Path(current).relative_to(context.root).as_posix()
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            dirs[:] = [d for d in dirs if not any(is_same_or_below(normalize_repository_path(f"{rel_current}/{d}"), ex) for ex in context.exclude_roots)]
            dirs.sort(reverse=reverse)
            for name in sorted(files, reverse=reverse):
                host_path = Path(current) / name
                if host_path.is_symlink() or host_path.suffix not in context.suffixes:
                    continue
                rel = host_path.relative_to(context.root).as_posix()
                if any(is_same_or_below(rel, ex) for ex in context.exclude_roots):
                    continue
                artifacts.append(DiscoveredArtifact(rel, host_path, host_path.suffix, host_path.read_text(encoding="utf-8")))
    return artifacts
