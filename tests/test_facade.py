import unittest
import string
from dataclasses import FrozenInstanceError

from llm_ffw import (
    Action,
    AUDIT_POLICY,
    BUILTIN_SECRET_CATALOG,
    STRICT_POLICY,
    ContentBlockedError,
    FirewallUnavailableError,
    Firewall,
    ProcessPoolState,
    ProcessScannerPoolConfig,
    RuleScannerConfig,
    SanitizationResult,
    ScanScope,
    SecretCatalog,
    SecretSignature,
)


def _single_worker_config() -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=1,
        max_in_flight=1,
        max_tasks_per_child=10,
    )


def _custom_signature() -> SecretSignature:
    return SecretSignature(
        signature_id="acme.token.service",
        provider="acme",
        secret_type="acme_service_token",
        prefixes=("acme_live_",),
        suffix_chars=string.ascii_letters + string.digits,
        min_suffix_chars=12,
        max_suffix_chars=12,
        boundary_chars=string.ascii_letters + string.digits + "_",
        source="internal://security/acme-service-token",
    )


def _additional_catalog() -> SecretCatalog:
    return SecretCatalog(
        catalog_id="acme.production",
        version="3.0.0+acme.1",
        signatures=(_custom_signature(),),
    )


class LLMFirewallTests(unittest.TestCase):
    def test_builtin_capabilities_are_safe_and_available_before_start(self) -> None:
        firewall = Firewall(pool_config=_single_worker_config())

        capabilities = firewall.capabilities()

        self.assertIs(capabilities, firewall.capabilities())
        self.assertEqual(capabilities.rule_count, 6)
        self.assertEqual(
            tuple(rule.rule_id for rule in capabilities.rules),
            (
                "pii.payment_card",
                "secrets.detected",
                "secrets.jwt_token",
                "secrets.private_key",
                "unicode.invisible_characters",
                "unicode.tag_smuggling",
            ),
        )
        secrets = next(
            rule for rule in capabilities.rules if rule.rule_id == "secrets.detected"
        )
        self.assertEqual(tuple(scope.value for scope in secrets.scopes), ("input", "output"))
        self.assertEqual(capabilities.payment_card.max_candidates, 128)
        self.assertEqual(capabilities.private_key.max_candidates, 32)
        self.assertEqual(capabilities.jwt_token.max_candidates, 128)
        self.assertEqual(
            capabilities.secret_catalog.catalog_id,
            "llm_ffw.builtin.secrets",
        )
        self.assertEqual(capabilities.secret_catalog.version, "3.0.0")
        self.assertEqual(capabilities.secret_catalog.signature_count, 28)
        self.assertEqual(capabilities.secret_catalog.prefix_count, 47)
        self.assertEqual(len(capabilities.secret_catalog.providers), 13)
        self.assertNotIn("sk-", repr(capabilities))
        self.assertNotIn("https://", repr(capabilities))
        firewall.close()

    def test_custom_catalog_is_summarized_and_used_by_workers(self) -> None:
        catalog = _additional_catalog()
        value = "acme_live_" + "A" * 12
        firewall = Firewall(
            pool_config=ProcessScannerPoolConfig(
                max_workers=1,
                max_in_flight=1,
                max_tasks_per_child=1,
            ),
            additional_secret_catalog=catalog,
        )

        capabilities = firewall.capabilities()
        self.assertEqual(capabilities.secret_catalog.catalog_id, catalog.catalog_id)
        self.assertEqual(capabilities.secret_catalog.version, catalog.version)
        self.assertEqual(capabilities.secret_catalog.signature_count, 29)
        self.assertEqual(capabilities.secret_catalog.prefix_count, 48)
        self.assertIn("acme", capabilities.secret_catalog.providers)
        self.assertNotIn("acme_live_", repr(capabilities))
        self.assertNotIn("internal://", repr(capabilities))

        with firewall:
            self.assertEqual(firewall.sanitize_input(value), "[REDACTED]")
            self.assertEqual(firewall.sanitize_output(value), "[REDACTED]")
            # Each call uses a newly spawned worker, proving that the pinned
            # catalog survives the configured worker-recycling boundary.
            self.assertEqual(
                firewall.sanitize_input("sk-" + "A" * 20),
                "[REDACTED]",
            )

        self.assertIsNot(catalog, firewall._pool.secret_catalog)
        self.assertEqual(firewall._pool.secret_catalog.catalog_id, catalog.catalog_id)

    def test_replacement_catalog_explicitly_removes_builtins(self) -> None:
        catalog = _additional_catalog()
        value = "acme_live_" + "A" * 12
        builtin_value = "sk-" + "A" * 20
        firewall = Firewall(
            pool_config=_single_worker_config(),
            replacement_secret_catalog=catalog,
        )

        capabilities = firewall.capabilities()
        self.assertEqual(capabilities.secret_catalog.signature_count, 1)
        self.assertEqual(capabilities.secret_catalog.prefix_count, 1)
        self.assertEqual(capabilities.secret_catalog.providers, ("acme",))
        with firewall:
            self.assertEqual(firewall.sanitize_input(value), "[REDACTED]")
            self.assertEqual(firewall.sanitize_input(builtin_value), builtin_value)

    def test_rejects_non_catalog_configuration(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(additional_secret_catalog={})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            Firewall(replacement_secret_catalog={})  # type: ignore[arg-type]

    def test_rejects_ambiguous_catalog_configuration(self) -> None:
        catalog = _additional_catalog()
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            Firewall(
                additional_secret_catalog=catalog,
                replacement_secret_catalog=catalog,
            )

    def test_extension_rejects_builtin_signature_collisions(self) -> None:
        collision = SecretCatalog(
            catalog_id="acme.invalid",
            version="1",
            signatures=(BUILTIN_SECRET_CATALOG.signatures[0],),
        )
        with self.assertRaisesRegex(ValueError, "overlap built-in"):
            Firewall(additional_secret_catalog=collision)

    def test_extension_rejects_nested_builtin_prefixes(self) -> None:
        nested_signature = SecretSignature(
            signature_id="acme.token.openai_shaped",
            provider="acme",
            secret_type="service_token",
            prefixes=("sk-acme-",),
            suffix_chars=string.ascii_letters + string.digits,
            min_suffix_chars=12,
            max_suffix_chars=12,
            boundary_chars=string.ascii_letters + string.digits + "_-",
            source="internal://security/acme-openai-shaped-token",
        )
        nested = SecretCatalog(
            catalog_id="acme.invalid",
            version="1",
            signatures=(nested_signature,),
        )
        with self.assertRaisesRegex(ValueError, "overlap built-in"):
            Firewall(additional_secret_catalog=nested)

    def test_rejects_legacy_ambiguous_catalog_keyword(self) -> None:
        with self.assertRaises(TypeError):
            Firewall(  # type: ignore[call-arg]
                secret_catalog=_additional_catalog(),
            )

    def test_context_sanitizes_input_and_output_and_closes(self) -> None:
        input_value = "sk-" + "I" * 20
        output_value = "sk-" + "O" * 20
        firewall = Firewall(pool_config=_single_worker_config())

        with firewall:
            self.assertEqual(firewall.state, ProcessPoolState.RUNNING)
            self.assertEqual(
                firewall.sanitize_input(f"before {input_value} after"),
                "before [REDACTED] after",
            )
            self.assertEqual(
                firewall.sanitize_output(
                    f"before {output_value} after",
                    prompt_context="safe prompt",
                ),
                "before [REDACTED] after",
            )

        self.assertEqual(firewall.state, ProcessPoolState.CLOSED)

    def test_structured_results_are_forwardable_and_disclosure_safe(self) -> None:
        secret = "sk-" + "D" * 20
        firewall = Firewall(pool_config=_single_worker_config())

        with firewall:
            input_result = firewall.sanitize_input_result(
                f"before {secret} after"
            )
            output_result = firewall.sanitize_output_result(
                "ordinary output",
                prompt_context="ordinary prompt",
            )

        self.assertIsInstance(input_result, SanitizationResult)
        self.assertEqual(input_result.text, "before [REDACTED] after")
        self.assertEqual(input_result.scope, ScanScope.INPUT)
        self.assertIs(input_result.decision, Action.REDACT)
        self.assertEqual(len(input_result.findings), 1)
        self.assertEqual(input_result.findings[0].rule_id, "secrets.detected")
        self.assertNotIn(secret, repr(input_result))
        self.assertNotIn(input_result.text, repr(input_result))

        self.assertEqual(output_result.text, "ordinary output")
        self.assertEqual(output_result.scope, ScanScope.OUTPUT)
        self.assertIs(output_result.decision, Action.ALLOW)
        self.assertEqual(output_result.findings, ())
        with self.assertRaises(FrozenInstanceError):
            output_result.text = "changed"  # type: ignore[misc]

    def test_structured_result_rejects_blocked_or_invalid_state(self) -> None:
        fields = {
            "text": "safe",
            "policy_id": "test.policy",
            "policy_version": "1.0.0",
            "scope": ScanScope.INPUT,
            "decision": Action.ALLOW,
            "findings": (),
        }
        with self.assertRaises(ValueError):
            SanitizationResult(**(fields | {"decision": Action.BLOCK}))

    def test_audit_result_omits_unchanged_sensitive_text_from_repr(self) -> None:
        secret = "sk-" + "R" * 20
        firewall = Firewall(
            pool_config=_single_worker_config(),
            policy=AUDIT_POLICY,
        )

        with firewall:
            result = firewall.sanitize_input_result(secret)

        self.assertEqual(result.text, secret)
        self.assertIs(result.decision, Action.REVIEW)
        self.assertNotIn(secret, repr(result))

    def test_secure_baseline_defaults_and_explicit_opt_outs_reach_workers(self) -> None:
        invisible = "hello\u200bworld"
        card = "Card 4242424242424242"
        default = Firewall(pool_config=_single_worker_config())
        opted_out = Firewall(
            scanner_config=RuleScannerConfig(
                enable_invisible_characters=False,
                enable_unicode_tag_smuggling=False,
                enable_payment_cards=False,
                enable_private_keys=False,
                enable_jwt_tokens=False,
            ),
            pool_config=_single_worker_config(),
        )

        with default:
            self.assertEqual(default.sanitize_input(invisible), "helloworld")
            self.assertEqual(default.sanitize_output(card), "Card [REDACTED]")
        with opted_out:
            self.assertEqual(opted_out.sanitize_input(invisible), invisible)
            self.assertEqual(opted_out.sanitize_output(card), card)

    def test_explicit_lifecycle_is_idempotent_while_running(self) -> None:
        firewall = Firewall(pool_config=_single_worker_config())

        self.assertIs(firewall.start(), firewall)
        self.assertIs(firewall.start(), firewall)
        self.assertEqual(firewall.sanitize_input("safe"), "safe")
        firewall.close()
        firewall.close()

        self.assertEqual(firewall.state, ProcessPoolState.CLOSED)

    def test_strict_block_exposes_only_safe_metadata(self) -> None:
        value = "sk-" + "B" * 20
        firewall = Firewall(
            pool_config=_single_worker_config(),
            policy=STRICT_POLICY,
        )

        with firewall:
            with self.assertRaises(ContentBlockedError) as raised:
                firewall.sanitize_input_result(value)
            with self.assertRaises(ContentBlockedError):
                firewall.sanitize_input(value)
            self.assertEqual(firewall.sanitize_input("safe"), "safe")

        error = raised.exception
        self.assertEqual(str(error), "content blocked by firewall policy")
        self.assertNotIn(value, str(error))
        self.assertEqual(error.scope.value, "input")
        self.assertEqual(len(error.findings), 1)
        self.assertNotIn(value, error.findings[0].message)
        self.assertNotIn(value, tuple(error.findings[0].metadata.values()))

    def test_unavailable_error_suppresses_internal_exception_chain(self) -> None:
        firewall = Firewall(pool_config=_single_worker_config())

        with self.assertRaises(FirewallUnavailableError) as raised:
            firewall.sanitize_input("safe")
        firewall.close()

        error = raised.exception
        self.assertEqual(str(error), "content inspection unavailable")
        self.assertEqual(error.cause_type, "ProcessPoolNotRunningError")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)

    def test_unexpected_worker_error_does_not_escape_public_exception(self) -> None:
        value = "sk-" + "X" * 20
        firewall = Firewall(pool_config=_single_worker_config())

        def unsafe_failure(*args: object, **kwargs: object) -> object:
            raise RuntimeError(f"internal failure contained {value}")

        firewall._pool.process = unsafe_failure  # type: ignore[method-assign]
        with self.assertRaises(FirewallUnavailableError) as raised:
            firewall.sanitize_input(value)
        firewall.close()

        error = raised.exception
        self.assertEqual(error.cause_type, "InternalInspectionError")
        self.assertNotIn(value, str(error))
        self.assertNotIn(value, repr(error.__dict__))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)

    def test_validates_timeout_and_payloads_before_submission(self) -> None:
        invalid_timeouts = (None, True, -1, 0, float("inf"), "5")
        for timeout in invalid_timeouts:
            with self.subTest(timeout=timeout), self.assertRaises(
                (TypeError, ValueError)
            ):
                Firewall(request_timeout_seconds=timeout)  # type: ignore[arg-type]

        firewall = Firewall(
            scanner_config=RuleScannerConfig(max_input_chars=4),
            pool_config=_single_worker_config(),
        )
        with self.assertRaises(TypeError):
            firewall.sanitize_input(123)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "max_input_chars=4"):
            firewall.sanitize_input("12345")
        with self.assertRaisesRegex(ValueError, "prompt_context"):
            firewall.sanitize_output("safe", prompt_context="12345")
        firewall.close()


if __name__ == "__main__":
    unittest.main()
