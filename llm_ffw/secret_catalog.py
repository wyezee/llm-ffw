"""Immutable, versioned signatures for deterministic secret detection."""

from dataclasses import dataclass
from enum import Enum
import string

from .findings import Action, Severity


_IDENTIFIER_CHARS = frozenset(string.ascii_lowercase + string.digits + "._-")
_PREFIX_CHARS = frozenset(string.ascii_letters + string.digits + "._-")
_VERSION_CHARS = frozenset(string.ascii_letters + string.digits + ".+-_")
_MAX_SIGNATURES = 1_024
_MAX_PREFIXES_PER_SIGNATURE = 16
_MAX_TOTAL_PREFIXES = 4_096
_MAX_PREFIX_LENGTH = 64
_MAX_ALPHABET_LENGTH = 128


class SignatureStatus(str, Enum):
    """Lifecycle state of one provider token format."""

    ACTIVE = "active"
    LEGACY = "legacy"


def _validate_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > 128 or value[0] not in string.ascii_lowercase + string.digits:
        raise ValueError(f"{field_name} must be a lowercase ASCII identifier")
    if any(character not in _IDENTIFIER_CHARS for character in value):
        raise ValueError(f"{field_name} must be a lowercase ASCII identifier")
    return value


def _validate_character_set(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_ALPHABET_LENGTH:
        raise ValueError(f"{field_name} is too large")
    if not value.isascii() or any(not character.isprintable() for character in value):
        raise ValueError(f"{field_name} must contain printable ASCII characters")
    if len(set(value)) != len(value):
        raise ValueError(f"{field_name} must not contain duplicate characters")
    return value


@dataclass(frozen=True, slots=True)
class SecretSignature:
    """One constrained token shape with no executable or regex content."""

    signature_id: str
    provider: str
    secret_type: str
    prefixes: tuple[str, ...]
    suffix_chars: str
    min_suffix_chars: int
    max_suffix_chars: int | None
    boundary_chars: str
    source: str
    status: SignatureStatus = SignatureStatus.ACTIVE
    severity: Severity = Severity.HIGH
    action: Action = Action.REDACT
    suffix_ending: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.signature_id, "signature_id")
        _validate_identifier(self.provider, "provider")
        _validate_identifier(self.secret_type, "secret_type")

        if isinstance(self.prefixes, (str, bytes)):
            raise TypeError("prefixes must be an iterable of strings")
        try:
            prefixes = tuple(self.prefixes)
        except TypeError as exc:
            raise TypeError("prefixes must be an iterable of strings") from exc
        if not prefixes or len(prefixes) > _MAX_PREFIXES_PER_SIGNATURE:
            raise ValueError("prefixes must contain between 1 and 16 values")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("prefixes must not contain duplicates")
        for prefix in prefixes:
            if not isinstance(prefix, str) or not prefix:
                raise ValueError("each prefix must be a non-empty string")
            if len(prefix) > _MAX_PREFIX_LENGTH:
                raise ValueError("prefix is too long")
            if any(character not in _PREFIX_CHARS for character in prefix):
                raise ValueError("prefixes must use ASCII letters, digits, '.', '_', or '-'")
        object.__setattr__(self, "prefixes", tuple(sorted(prefixes)))

        _validate_character_set(self.suffix_chars, "suffix_chars")
        _validate_character_set(self.boundary_chars, "boundary_chars")
        if any(
            character not in self.boundary_chars
            for character in self.suffix_chars
        ):
            raise ValueError(
                "boundary_chars must contain every suffix character"
            )
        for prefix in prefixes:
            if any(character not in self.boundary_chars for character in prefix):
                raise ValueError("boundary_chars must contain every prefix character")
        if isinstance(self.min_suffix_chars, bool) or not isinstance(
            self.min_suffix_chars, int
        ):
            raise TypeError("min_suffix_chars must be an integer")
        if self.min_suffix_chars <= 0:
            raise ValueError("min_suffix_chars must be positive")
        if self.max_suffix_chars is not None:
            if isinstance(self.max_suffix_chars, bool) or not isinstance(
                self.max_suffix_chars, int
            ):
                raise TypeError("max_suffix_chars must be an integer or None")
            if self.max_suffix_chars < self.min_suffix_chars:
                raise ValueError("max_suffix_chars must not be less than the minimum")

        if not isinstance(self.source, str) or not self.source:
            raise ValueError("source must be a non-empty string")
        if (
            len(self.source) > 2_048
            or not self.source.isascii()
            or any(
                character.isspace() or not character.isprintable()
                for character in self.source
            )
        ):
            raise ValueError("source must be printable ASCII without whitespace")
        if not isinstance(self.status, SignatureStatus):
            raise TypeError("status must be a SignatureStatus")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")
        if not isinstance(self.suffix_ending, str):
            raise TypeError("suffix_ending must be a string")
        if (
            len(self.suffix_ending) > self.min_suffix_chars
            or not self.suffix_ending.isascii()
            or any(character not in self.suffix_chars for character in self.suffix_ending)
        ):
            raise ValueError("suffix_ending must fit within the permitted suffix")


@dataclass(frozen=True, slots=True)
class SecretCatalog:
    """A deterministic, deployment-pinned collection of secret signatures."""

    catalog_id: str
    version: str
    signatures: tuple[SecretSignature, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.catalog_id, "catalog_id")
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("version must be a non-empty string")
        if len(self.version) > 64 or any(
            character not in _VERSION_CHARS for character in self.version
        ):
            raise ValueError("version must use ASCII letters, digits, '.', '+', '-', or '_'")

        if isinstance(self.signatures, (str, bytes)):
            raise TypeError("signatures must be an iterable of SecretSignature values")
        try:
            signatures = tuple(self.signatures)
        except TypeError as exc:
            raise TypeError(
                "signatures must be an iterable of SecretSignature values"
            ) from exc
        if not signatures or len(signatures) > _MAX_SIGNATURES:
            raise ValueError("signatures must contain between 1 and 1024 values")
        if any(not isinstance(item, SecretSignature) for item in signatures):
            raise TypeError("signatures must contain SecretSignature values")
        signature_ids = [item.signature_id for item in signatures]
        if len(set(signature_ids)) != len(signature_ids):
            raise ValueError("signature_id values must be unique within a catalog")

        prefix_owners = tuple(
            (
                (prefix, signature.signature_id)
                for signature in signatures
                for prefix in signature.prefixes
            )
        )
        if len(prefix_owners) > _MAX_TOTAL_PREFIXES:
            raise ValueError("catalog contains too many prefixes")
        owners_by_prefix: dict[str, str] = {}
        for prefix, owner in prefix_owners:
            existing_owner = owners_by_prefix.get(prefix)
            if existing_owner is not None and existing_owner != owner:
                raise ValueError("prefixes must be unique across signatures")
            owners_by_prefix[prefix] = owner

        object.__setattr__(
            self,
            "signatures",
            tuple(sorted(signatures, key=lambda item: item.signature_id)),
        )


def _resolve_secret_catalog(
    additional_secret_catalog: SecretCatalog | None,
    replacement_secret_catalog: SecretCatalog | None,
) -> SecretCatalog:
    """Resolve the shared additive-or-replacement catalog contract."""

    for value, field_name in (
        (additional_secret_catalog, "additional_secret_catalog"),
        (replacement_secret_catalog, "replacement_secret_catalog"),
    ):
        if value is not None and not isinstance(value, SecretCatalog):
            raise TypeError(f"{field_name} must be a SecretCatalog or None")
    if (
        additional_secret_catalog is not None
        and replacement_secret_catalog is not None
    ):
        raise ValueError(
            "additional_secret_catalog and replacement_secret_catalog "
            "are mutually exclusive"
        )
    if replacement_secret_catalog is not None:
        return replacement_secret_catalog
    if additional_secret_catalog is None:
        return BUILTIN_SECRET_CATALOG
    builtin_prefixes = tuple(
        prefix
        for signature in BUILTIN_SECRET_CATALOG.signatures
        for prefix in signature.prefixes
    )
    additional_prefixes = tuple(
        prefix
        for signature in additional_secret_catalog.signatures
        for prefix in signature.prefixes
    )
    if any(
        builtin.startswith(additional) or additional.startswith(builtin)
        for builtin in builtin_prefixes
        for additional in additional_prefixes
    ):
        raise ValueError(
            "additional secret prefixes must not overlap built-in prefixes"
        )
    return SecretCatalog(
        catalog_id=additional_secret_catalog.catalog_id,
        version=additional_secret_catalog.version,
        signatures=(
            BUILTIN_SECRET_CATALOG.signatures
            + additional_secret_catalog.signatures
        ),
    )


_ALNUM = string.ascii_letters + string.digits
_TOKEN_CHARS = _ALNUM + "_-"
_WORD_CHARS = _ALNUM + "_"
_TOKEN_DOT_CHARS = _TOKEN_CHARS + "."
_ALNUM_DASH = _ALNUM + "-"
_HEX = string.hexdigits[:16] + string.ascii_uppercase[:6]
_LOWER_HEX = string.digits + "abcdef"
_LETTERS = string.ascii_letters
_GITLEAKS_SOURCE = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/"
    "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml"
)

BUILTIN_SECRET_CATALOG = SecretCatalog(
    catalog_id="llm_ffw.builtin.secrets",
    version="3.0.0",
    signatures=(
        SecretSignature(
            signature_id="openai.api_key.prefixed",
            provider="openai",
            secret_type="openai_api_key",
            prefixes=("sk-", "sk-proj-", "sk-svcacct-"),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=20,
            max_suffix_chars=None,
            boundary_chars=_TOKEN_CHARS,
            source="https://developers.openai.com/api/reference/overview#authentication",
        ),
        SecretSignature(
            signature_id="github.token.legacy_prefixed_alnum",
            provider="github",
            secret_type="github_token",
            prefixes=("ghp_", "gho_", "ghu_", "ghr_"),
            suffix_chars=_ALNUM,
            min_suffix_chars=36,
            max_suffix_chars=36,
            boundary_chars=_WORD_CHARS,
            source=(
                "https://docs.github.com/authentication/keeping-your-account-and-data-"
                "secure/about-authentication-to-github"
            ),
        ),
        SecretSignature(
            signature_id="github.token.installation",
            provider="github",
            secret_type="github_installation_token",
            prefixes=("ghs_",),
            suffix_chars=_TOKEN_DOT_CHARS,
            min_suffix_chars=36,
            max_suffix_chars=2_048,
            boundary_chars=_TOKEN_DOT_CHARS,
            source=(
                "https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-"
                "format-for-github-app-installation-tokens/"
            ),
        ),
        SecretSignature(
            signature_id="github.token.fine_grained_pat",
            provider="github",
            secret_type="github_fine_grained_pat",
            prefixes=("github_pat_",),
            suffix_chars=_WORD_CHARS,
            min_suffix_chars=82,
            max_suffix_chars=82,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="aws.access_key_id",
            provider="aws",
            secret_type="aws_access_key_id",
            prefixes=("AKIA", "ASIA"),
            suffix_chars=string.ascii_uppercase + string.digits,
            min_suffix_chars=16,
            max_suffix_chars=16,
            boundary_chars=_WORD_CHARS,
            source=(
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                "security-creds-programmatic-access.html"
            ),
        ),
        SecretSignature(
            signature_id="anthropic.api_key.api03",
            provider="anthropic",
            secret_type="anthropic_api_key",
            prefixes=("sk-ant-api03-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=95,
            max_suffix_chars=95,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
            suffix_ending="AA",
        ),
        SecretSignature(
            signature_id="anthropic.admin_key.admin01",
            provider="anthropic",
            secret_type="anthropic_admin_key",
            prefixes=("sk-ant-admin01-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=95,
            max_suffix_chars=95,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
            suffix_ending="AA",
        ),
        SecretSignature(
            signature_id="gitlab.token.common_20",
            provider="gitlab",
            secret_type="gitlab_token",
            prefixes=("gldt-", "glffct-", "glft-", "glpat-", "glrt-", "glsoat-"),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=20,
            max_suffix_chars=20,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="gitlab.token.official_opaque",
            provider="gitlab",
            secret_type="gitlab_token",
            prefixes=("glrtr-", "glwt-"),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=20,
            max_suffix_chars=255,
            boundary_chars=_TOKEN_CHARS,
            source="https://docs.gitlab.com/security/token_overview/",
        ),
        SecretSignature(
            signature_id="gitlab.token.incoming_mail",
            provider="gitlab",
            secret_type="gitlab_incoming_mail_token",
            prefixes=("glimt-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=25,
            max_suffix_chars=25,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="gitlab.token.agent",
            provider="gitlab",
            secret_type="gitlab_agent_token",
            prefixes=("glagent-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=50,
            max_suffix_chars=50,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="gitlab.token.oauth_application_secret",
            provider="gitlab",
            secret_type="gitlab_oauth_application_secret",
            prefixes=("gloas-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=64,
            max_suffix_chars=64,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="gitlab.token.pipeline_trigger",
            provider="gitlab",
            secret_type="gitlab_pipeline_trigger_token",
            prefixes=("glptt-",),
            suffix_chars=_LOWER_HEX,
            min_suffix_chars=40,
            max_suffix_chars=40,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="gitlab.token.job",
            provider="gitlab",
            secret_type="gitlab_job_token",
            prefixes=("glcbt-",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=22,
            max_suffix_chars=26,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="slack.token.bot",
            provider="slack",
            secret_type="slack_bot_token",
            prefixes=("xoxb-",),
            suffix_chars=_ALNUM_DASH,
            min_suffix_chars=27,
            max_suffix_chars=255,
            boundary_chars=_ALNUM_DASH,
            source="https://docs.slack.dev/authentication/tokens/",
        ),
        SecretSignature(
            signature_id="slack.token.user",
            provider="slack",
            secret_type="slack_user_token",
            prefixes=("xoxp-",),
            suffix_chars=_ALNUM_DASH,
            min_suffix_chars=60,
            max_suffix_chars=255,
            boundary_chars=_ALNUM_DASH,
            source="https://docs.slack.dev/authentication/tokens/",
        ),
        SecretSignature(
            signature_id="slack.token.app",
            provider="slack",
            secret_type="slack_app_token",
            prefixes=("xapp-",),
            suffix_chars=_ALNUM_DASH,
            min_suffix_chars=20,
            max_suffix_chars=255,
            boundary_chars=_ALNUM_DASH,
            source="https://docs.slack.dev/authentication/tokens/",
        ),
        SecretSignature(
            signature_id="slack.token.workflow",
            provider="slack",
            secret_type="slack_workflow_token",
            prefixes=("xwfp-",),
            suffix_chars=_ALNUM_DASH,
            min_suffix_chars=20,
            max_suffix_chars=255,
            boundary_chars=_ALNUM_DASH,
            source="https://docs.slack.dev/authentication/tokens/",
        ),
        SecretSignature(
            signature_id="stripe.key.server_side",
            provider="stripe",
            secret_type="stripe_server_key",
            prefixes=(
                "rk_live_",
                "rk_prod_",
                "rk_test_",
                "sk_live_",
                "sk_prod_",
                "sk_test_",
            ),
            suffix_chars=_ALNUM,
            min_suffix_chars=10,
            max_suffix_chars=99,
            boundary_chars=_WORD_CHARS,
            source="https://docs.stripe.com/keys",
        ),
        SecretSignature(
            signature_id="stripe.webhook.signing_secret",
            provider="stripe",
            secret_type="stripe_webhook_signing_secret",
            prefixes=("whsec_",),
            suffix_chars=_ALNUM,
            min_suffix_chars=20,
            max_suffix_chars=255,
            boundary_chars=_WORD_CHARS,
            source="https://docs.stripe.com/webhooks/signature",
        ),
        SecretSignature(
            signature_id="huggingface.token.user",
            provider="huggingface",
            secret_type="huggingface_token",
            prefixes=("hf_",),
            suffix_chars=_LETTERS,
            min_suffix_chars=34,
            max_suffix_chars=34,
            boundary_chars=_WORD_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="huggingface.token.jwt",
            provider="huggingface",
            secret_type="huggingface_jwt_token",
            prefixes=("hf_jwt_",),
            suffix_chars=_TOKEN_DOT_CHARS,
            min_suffix_chars=20,
            max_suffix_chars=2_048,
            boundary_chars=_TOKEN_DOT_CHARS,
            source="https://huggingface.co/docs/hub/en/trusted-publishers",
        ),
        SecretSignature(
            signature_id="huggingface.token.oauth",
            provider="huggingface",
            secret_type="huggingface_oauth_token",
            prefixes=("hf_oauth_",),
            suffix_chars=_TOKEN_DOT_CHARS,
            min_suffix_chars=20,
            max_suffix_chars=2_048,
            boundary_chars=_TOKEN_DOT_CHARS,
            source="https://huggingface.co/docs/hub/en/trusted-publishers",
        ),
        SecretSignature(
            signature_id="google.api_key.aiza",
            provider="google",
            secret_type="google_api_key",
            prefixes=("AIza",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=35,
            max_suffix_chars=35,
            boundary_chars=_TOKEN_CHARS,
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="npm.token.legacy",
            provider="npm",
            secret_type="npm_access_token",
            prefixes=("npm_",),
            suffix_chars=_ALNUM,
            min_suffix_chars=36,
            max_suffix_chars=36,
            boundary_chars=_WORD_CHARS,
            source=_GITLEAKS_SOURCE,
            status=SignatureStatus.LEGACY,
        ),
        SecretSignature(
            signature_id="pypi.api_token",
            provider="pypi",
            secret_type="pypi_api_token",
            prefixes=("pypi-AgEIcHlwaS5vcmc",),
            suffix_chars=_TOKEN_CHARS,
            min_suffix_chars=50,
            max_suffix_chars=1_000,
            boundary_chars=_TOKEN_CHARS,
            source="https://pypi.org/help/#apitoken",
        ),
        SecretSignature(
            signature_id="sendgrid.api_key",
            provider="sendgrid",
            secret_type="sendgrid_api_key",
            prefixes=("SG.",),
            suffix_chars=_TOKEN_DOT_CHARS + "=",
            min_suffix_chars=66,
            max_suffix_chars=66,
            boundary_chars=_TOKEN_DOT_CHARS + "=",
            source=_GITLEAKS_SOURCE,
        ),
        SecretSignature(
            signature_id="shopify.access_token",
            provider="shopify",
            secret_type="shopify_access_token",
            prefixes=("shpat_", "shpca_", "shppa_"),
            suffix_chars=_HEX,
            min_suffix_chars=32,
            max_suffix_chars=32,
            boundary_chars=_WORD_CHARS,
            source=(
                "https://shopify.dev/changelog/length-of-shopify-access-tokens-is-"
                "increasing"
            ),
        ),
    ),
)


__all__ = [
    "BUILTIN_SECRET_CATALOG",
    "SecretCatalog",
    "SecretSignature",
    "SignatureStatus",
]
