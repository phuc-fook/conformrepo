"""Small read-only repository conformance engine."""

from .audit import run_audit
from .model import AuditResult, Finding

__all__ = ["AuditResult", "Finding", "run_audit"]
__version__ = "0.1.0"
