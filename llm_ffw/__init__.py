"""Deterministic scanning for text sent to and from language models."""

from .config import ScannerConfig
from .engine import Scanner
from .findings import Action, Finding, Severity, Span

__all__ = [
    "Action",
    "Finding",
    "Scanner",
    "ScannerConfig",
    "Severity",
    "Span",
]

__version__ = "0.1.0"
