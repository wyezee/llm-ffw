"""Deterministic scanning for text sent to and from language models."""

from .capabilities import (
    FirewallCapabilities,
    RuleCapability,
    SecretCatalogCapability,
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

__all__ = [
    "Action",
    "AUDIT_POLICY",
    "BALANCED_POLICY",
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
    "LLMFirewall",
    "LLMFirewallManager",
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
