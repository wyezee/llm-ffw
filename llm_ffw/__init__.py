"""Deterministic scanning for text sent to and from language models."""

from .capabilities import (
    BannedSubstringCatalogCapability,
    FirewallCapabilities,
    RuleCapability,
    SecretCatalogCapability,
)
from .banned_substring_catalog import (
    BannedSubstring,
    BannedSubstringCatalog,
    LiteralMatchMode,
)
from .config import ScannerConfig
from .engine import Scanner
from .findings import Action, Finding, Severity, Span
from .facade import ContentBlockedError, FirewallUnavailableError, LLMFirewall
from .inspection import (
    Inspection,
    InspectionFeature,
    InspectionFeatureUnavailableError,
    ScanScope,
)
from .manager import (
    FirewallManagerState,
    FirewallReloadError,
    LLMFirewallManager,
)
from .policy import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    Firewall,
    FirewallPolicy,
    FirewallResult,
    PolicyOverride,
)
from .process_pool import (
    ProcessPoolNotRunningError,
    ProcessPoolSaturatedError,
    ProcessPoolState,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
)
from .secret_catalog import (
    BUILTIN_SECRET_CATALOG,
    SecretCatalog,
    SecretSignature,
    SignatureStatus,
)
from .rules.invisible_characters import InvisibleCharactersRule
from .rules.banned_substrings import BannedSubstringsRule

__all__ = [
    "Action",
    "AUDIT_POLICY",
    "BALANCED_POLICY",
    "BannedSubstring",
    "BannedSubstringCatalog",
    "BannedSubstringCatalogCapability",
    "BannedSubstringsRule",
    "BUILTIN_SECRET_CATALOG",
    "ContentBlockedError",
    "Finding",
    "Firewall",
    "FirewallCapabilities",
    "FirewallManagerState",
    "FirewallReloadError",
    "FirewallUnavailableError",
    "FirewallPolicy",
    "FirewallResult",
    "Inspection",
    "InspectionFeature",
    "InspectionFeatureUnavailableError",
    "InvisibleCharactersRule",
    "LLMFirewall",
    "LLMFirewallManager",
    "LiteralMatchMode",
    "ProcessPoolNotRunningError",
    "ProcessPoolSaturatedError",
    "ProcessPoolState",
    "ProcessScannerPool",
    "ProcessScannerPoolConfig",
    "RuleCapability",
    "PolicyOverride",
    "Scanner",
    "ScannerConfig",
    "ScanScope",
    "SecretCatalog",
    "SecretCatalogCapability",
    "SecretSignature",
    "Severity",
    "SignatureStatus",
    "Span",
    "STRICT_POLICY",
]

__version__ = "0.1.0"
