from __future__ import annotations

import re

from .model import DiscoveredArtifact, MarkdownLinkTarget
from .paths import PathEscapesRoot, resolve_reference


MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")


def extract_markdown_links(artifact: DiscoveredArtifact, mode: str) -> list[MarkdownLinkTarget]:
    targets: list[MarkdownLinkTarget] = []
    for match in MARKDOWN_LINK.finditer(artifact.text):
        raw = match.group(1)
        if raw.lower().startswith(("http://", "https://")):
            continue
        file_target = raw.split("#", 1)[0].split("?", 1)[0]
        if not file_target:
            continue
        try:
            normalized = resolve_reference(artifact.discovered_path, file_target, mode)
        except PathEscapesRoot:
            normalized = None
        targets.append(MarkdownLinkTarget(artifact, raw, mode, normalized))
    return targets
