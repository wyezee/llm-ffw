"""Deterministic structural detection of compact JSON Web Tokens."""

import base64
import binascii
import json

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..jwt_token import JWTTokenConfig
from .base import Rule, RuleMatch


_BASE64URL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_REGISTERED_CLAIMS = frozenset(
    ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
)
_MIN_HEADER_CHARS = 15
_JSON_LIMIT_EXCEEDED = object()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite JSON constant")


def _discard_number(_: str) -> None:
    return None


def _within_json_limits(value: str, config: JWTTokenConfig) -> bool:
    depth = 0
    structure_tokens = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            structure_tokens += 1
            if depth > config.max_json_depth:
                return False
        elif character in "]}":
            depth -= 1
        elif character in ",:":
            structure_tokens += 1
        if structure_tokens > config.max_json_structure_tokens:
            return False
    return True


def _decode_base64url(text: str, start: int, end: int) -> bytes | None:
    length = end - start
    if length == 0 or length % 4 == 1:
        return None
    try:
        encoded = text[start:end].encode("ascii")
        decoded = base64.b64decode(
            encoded + (b"=" * (-length % 4)),
            altchars=b"-_",
            validate=True,
        )
        if base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
            return None
    except (UnicodeError, ValueError, binascii.Error):
        return None
    return decoded


def _decode_object(
    text: str,
    start: int,
    end: int,
    config: JWTTokenConfig,
) -> dict[str, object] | object | None:
    decoded = _decode_base64url(text, start, end)
    if decoded is None:
        return None
    try:
        decoded_text = decoded.decode("utf-8")
        if not _within_json_limits(decoded_text, config):
            return _JSON_LIMIT_EXCEEDED
        value = json.loads(
            decoded_text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_discard_number,
            parse_int=_discard_number,
        )
    except (UnicodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _algorithm_family(value: str) -> str:
    upper = value.upper()
    if value.lower() == "none":
        return "none"
    if upper.startswith("HS"):
        return "hmac"
    if upper.startswith("RS"):
        return "rsa"
    if upper.startswith("PS"):
        return "rsa_pss"
    if upper.startswith("ES"):
        return "ecdsa"
    if upper == "EDDSA":
        return "eddsa"
    return "other"


def _failure(
    start: int,
    end: int,
    *,
    reason: str,
    config: JWTTokenConfig,
) -> RuleMatch:
    return RuleMatch(
        span=Span(start, end),
        severity=Severity.HIGH,
        action=Action.BLOCK,
        message="JWT candidate could not be safely inspected.",
        metadata={
            "reason": reason,
            "detector": "compact_jwt_structure",
            "max_candidates": str(config.max_candidates),
            "max_token_chars": str(config.max_token_chars),
            "max_json_depth": str(config.max_json_depth),
            "max_json_structure_tokens": str(
                config.max_json_structure_tokens
            ),
            "span_basis": "characters",
        },
    )


class JWTTokenRule(Rule):
    """Find bounded compact JWTs with validated JSON header and claims shape."""

    RULE_ID = "secrets.jwt_token"
    PURPOSE = "Detect structurally credible compact JSON Web Tokens."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: JWTTokenConfig | None = None) -> None:
        if config is not None and not isinstance(config, JWTTokenConfig):
            raise TypeError("config must be a JWTTokenConfig or None")
        self._config = config if config is not None else JWTTokenConfig()

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return frozenset(self._config.scopes)

    @property
    def config(self) -> JWTTokenConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if "." not in text:
            return ()

        matches: list[RuleMatch] = []
        candidate_count = 0
        cursor = 0
        text_length = len(text)
        while True:
            header_end = text.find(".", cursor)
            if header_end < 0:
                break
            start = header_end
            while start > 0 and text[start - 1] in _BASE64URL_CHARS:
                start -= 1
            cursor = header_end + 1
            if (
                header_end - start < _MIN_HEADER_CHARS
                or text[start] != "e"
                or (start > 0 and text[start - 1] in ".=")
            ):
                continue

            payload_start = cursor
            while cursor < text_length and text[cursor] in _BASE64URL_CHARS:
                cursor += 1
            payload_end = cursor
            if (
                payload_end == payload_start
                or cursor >= text_length
                or text[cursor] != "."
            ):
                cursor = header_end + 1
                continue
            signature_start = cursor + 1
            cursor = signature_start
            while cursor < text_length and text[cursor] in _BASE64URL_CHARS:
                cursor += 1
            end = cursor
            if cursor < text_length and text[cursor] in ".=":
                cursor += 1
                continue

            if candidate_count >= self._config.max_candidates:
                matches.append(
                    _failure(
                        start,
                        text_length,
                        reason="candidate_limit_exceeded",
                        config=self._config,
                    )
                )
                break
            candidate_count += 1
            if end - start > self._config.max_token_chars:
                matches.append(
                    _failure(
                        start,
                        text_length,
                        reason="token_size_exceeded",
                        config=self._config,
                    )
                )
                break

            header = _decode_object(text, start, header_end, self._config)
            if header is _JSON_LIMIT_EXCEEDED:
                matches.append(
                    _failure(
                        start,
                        text_length,
                        reason="json_limit_exceeded",
                        config=self._config,
                    )
                )
                break
            if not isinstance(header, dict):
                continue
            algorithm = header.get("alg")
            if not isinstance(algorithm, str) or not algorithm:
                continue
            if algorithm.lower() == "none":
                if end != signature_start:
                    continue
            elif end == signature_start:
                continue
            elif _decode_base64url(text, signature_start, end) is None:
                continue
            payload = _decode_object(
                text,
                payload_start,
                payload_end,
                self._config,
            )
            if payload is _JSON_LIMIT_EXCEEDED:
                matches.append(
                    _failure(
                        start,
                        text_length,
                        reason="json_limit_exceeded",
                        config=self._config,
                    )
                )
                break
            if not isinstance(payload, dict):
                continue
            has_jwt_type = (
                isinstance(header.get("typ"), str)
                and header["typ"].lower() == "jwt"
            )
            has_registered_claim = bool(_REGISTERED_CLAIMS.intersection(payload))
            if not has_jwt_type and not has_registered_claim:
                continue

            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Potential JSON Web Token detected.",
                    redacted_preview="[REDACTED:jwt_token]",
                    metadata={
                        "reason": (
                            "jwt_type_header"
                            if has_jwt_type
                            else "registered_claim"
                        ),
                        "detector": "compact_jwt_structure",
                        "algorithm_family": _algorithm_family(algorithm),
                        "token_chars": str(end - start),
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["JWTTokenRule"]
