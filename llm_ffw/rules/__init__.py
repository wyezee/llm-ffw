"""Built-in deterministic scanning rules."""

from .base import Rule, RuleMatch
from .banned_substrings import BannedSubstringsRule
from .invisible_characters import InvisibleCharactersRule
from .unicode_tag_smuggling import UnicodeTagSmugglingRule
from .json_output import JSONOutputRule
from .ip_address import IPAddressRule
from .mac_address import MACAddressRule
from .email_address import EmailAddressRule
from .payment_card import PaymentCardRule
from .private_key import PrivateKeyRule
from .jwt_token import JWTTokenRule
from .secrets import SecretsRule
from .unsafe_url import UnsafeURLRule

__all__ = [
    "BannedSubstringsRule",
    "InvisibleCharactersRule",
    "UnicodeTagSmugglingRule",
    "JSONOutputRule",
    "IPAddressRule",
    "MACAddressRule",
    "EmailAddressRule",
    "PaymentCardRule",
    "PrivateKeyRule",
    "JWTTokenRule",
    "Rule",
    "RuleMatch",
    "SecretsRule",
    "UnsafeURLRule",
]
