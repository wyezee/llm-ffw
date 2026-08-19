from dataclasses import FrozenInstanceError
import unittest

from llm_ffw import (
    AUDIT_POLICY,
    BALANCED_POLICY,
    STRICT_POLICY,
    AsyncFirewall,
    AsyncFirewallManager,
    BannedSubstring,
    BannedSubstringCatalog,
    FirewallConfig,
    Firewall,
    FirewallManager,
    JWTTokenConfig,
    PaymentCardConfig,
    PrivateKeyConfig,
    ProcessScannerPoolConfig,
    RuleScannerConfig,
    ScanScope,
)


def _catalog() -> BannedSubstringCatalog:
    return BannedSubstringCatalog(
        "test.facade.preset",
        "1",
        (BannedSubstring("test.private.marker", "private-marker-value"),),
    )


class FirewallConfigTests(unittest.TestCase):
    def test_default_matches_direct_facade_capabilities(self) -> None:
        direct = Firewall(pool_config=ProcessScannerPoolConfig(max_workers=1))
        configured = Firewall.from_config(
            FirewallConfig(
                pool_config=ProcessScannerPoolConfig(max_workers=1)
            )
        )
        try:
            self.assertEqual(configured.capabilities(), direct.capabilities())
        finally:
            direct.close()
            configured.close()

    def test_presets_have_explicit_composable_scope(self) -> None:
        privacy = Firewall.from_config(FirewallConfig.privacy_input())
        json_api = Firewall.from_config(FirewallConfig.json_api())
        self_contained_config = FirewallConfig.all_text_rules()
        self_contained = Firewall.from_config(self_contained_config)
        all_rules_config = FirewallConfig.all_text_rules(
            banned_substring_catalog=_catalog(),
            policy=STRICT_POLICY,
        )
        all_rules = Firewall.from_config(all_rules_config)
        try:
            privacy_rule_ids = {
                item.rule_id for item in privacy.capabilities().rules
            }
            json_rule_ids = {
                item.rule_id for item in json_api.capabilities().rules
            }
            self.assertTrue(
                {
                    "pii.ip_address",
                    "pii.mac_address",
                    "pii.iban",
                    "pii.email_address",
                    "pii.phone_number",
                }.issubset(privacy_rule_ids)
            )
            self.assertTrue(
                {"output.json.validity", "url.unsafe"}.issubset(
                    json_rule_ids
                )
            )
            self.assertNotIn("output.external_resource", json_rule_ids)
            self.assertIn(
                "output.external_resource",
                {item.rule_id for item in all_rules.capabilities().rules},
            )
            self_contained_rule_ids = {
                item.rule_id for item in self_contained.capabilities().rules
            }
            self.assertNotIn(
                "content.banned_substrings",
                self_contained_rule_ids,
            )
            self.assertEqual(len(self_contained_rule_ids), 19)
            self.assertEqual(len(all_rules.capabilities().rules), 20)
            self_contained_capabilities = {
                item.rule_id: item
                for item in self_contained.capabilities().rules
            }
            for rule_id in (
                "pii.ip_address",
                "pii.mac_address",
                "pii.iban",
                "pii.email_address",
                "pii.phone_number",
            ):
                with self.subTest(rule_id=rule_id):
                    self.assertEqual(
                        self_contained_capabilities[rule_id].scopes,
                        (ScanScope.INPUT, ScanScope.OUTPUT),
                    )
            self.assertIs(self_contained_config.policy, BALANCED_POLICY)
            self.assertIs(all_rules_config.policy, STRICT_POLICY)
            self.assertEqual(
                all_rules.capabilities().policy_id,
                STRICT_POLICY.policy_id,
            )
            self.assertEqual(
                all_rules.capabilities().policy_version,
                STRICT_POLICY.version,
            )
            self.assertIs(
                FirewallConfig.all_text_rules(policy=AUDIT_POLICY).policy,
                AUDIT_POLICY,
            )
            self.assertEqual(all_rules_config.request_timeout_seconds, 30.0)
        finally:
            privacy.close()
            json_api.close()
            self_contained.close()
            all_rules.close()

    def test_all_text_rules_rejects_invalid_catalog_and_policy(self) -> None:
        with self.assertRaisesRegex(
            TypeError,
            "banned_substring_catalog must be a BannedSubstringCatalog or None",
        ):
            FirewallConfig.all_text_rules(  # type: ignore[arg-type]
                banned_substring_catalog=object()
            )
        with self.assertRaisesRegex(TypeError, "policy must be a FirewallPolicy"):
            FirewallConfig.all_text_rules(policy=object())  # type: ignore[arg-type]

    def test_configuration_is_immutable_validated_and_disclosure_safe(self) -> None:
        config = FirewallConfig(banned_substring_catalog=_catalog())
        self.assertNotIn("private-marker-value", repr(config))
        with self.assertRaises(FrozenInstanceError):
            config.request_timeout_seconds = 10  # type: ignore[misc]
        with self.assertRaises(TypeError):
            FirewallConfig(scanner_config=object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            FirewallConfig(request_timeout_seconds=True)
        with self.assertRaises(ValueError):
            FirewallConfig(request_timeout_seconds=float("inf"))
        with self.assertRaises(ValueError):
            FirewallConfig(request_timeout_seconds=0)
        self.assertEqual(FirewallConfig().request_timeout_seconds, 30.0)

    def test_all_facades_reject_non_configuration_values(self) -> None:
        factories = (
            Firewall.from_config,
            FirewallManager.from_config,
            AsyncFirewall.from_config,
            AsyncFirewallManager.from_config,
        )
        for factory in factories:
            with self.subTest(factory=factory.__qualname__):
                with self.assertRaises(TypeError):
                    factory(object())  # type: ignore[arg-type]

    def test_disabled_default_rules_reject_dedicated_configuration_early(self) -> None:
        cases = (
            (
                RuleScannerConfig(enable_payment_cards=False),
                {"payment_card_config": PaymentCardConfig()},
                "payment_card_config requires enable_payment_cards=True",
            ),
            (
                RuleScannerConfig(enable_private_keys=False),
                {"private_key_config": PrivateKeyConfig()},
                "private_key_config requires enable_private_keys=True",
            ),
            (
                RuleScannerConfig(enable_jwt_tokens=False),
                {"jwt_token_config": JWTTokenConfig()},
                "jwt_token_config requires enable_jwt_tokens=True",
            ),
        )
        for scanner_config, kwargs, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    FirewallConfig(scanner_config=scanner_config, **kwargs)


if __name__ == "__main__":
    unittest.main()
