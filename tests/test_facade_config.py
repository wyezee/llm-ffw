from dataclasses import FrozenInstanceError
import unittest

from llm_ffw import (
    AsyncLLMFirewall,
    AsyncLLMFirewallManager,
    BannedSubstring,
    BannedSubstringCatalog,
    FirewallConfig,
    LLMFirewall,
    LLMFirewallManager,
    ProcessScannerPoolConfig,
)


def _catalog() -> BannedSubstringCatalog:
    return BannedSubstringCatalog(
        "test.facade.preset",
        "1",
        (BannedSubstring("test.private.marker", "private-marker-value"),),
    )


class FirewallConfigTests(unittest.TestCase):
    def test_default_matches_direct_facade_capabilities(self) -> None:
        direct = LLMFirewall(pool_config=ProcessScannerPoolConfig(max_workers=1))
        configured = LLMFirewall.from_config(
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
        privacy = LLMFirewall.from_config(FirewallConfig.privacy_input())
        json_api = LLMFirewall.from_config(FirewallConfig.json_api())
        all_rules_config = FirewallConfig.all_text_rules(
            banned_substring_catalog=_catalog()
        )
        all_rules = LLMFirewall.from_config(all_rules_config)
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
                }.issubset(privacy_rule_ids)
            )
            self.assertTrue(
                {"output.json.validity", "url.unsafe"}.issubset(
                    json_rule_ids
                )
            )
            self.assertEqual(len(all_rules.capabilities().rules), 15)
            self.assertEqual(all_rules_config.request_timeout_seconds, 30.0)
        finally:
            privacy.close()
            json_api.close()
            all_rules.close()

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

    def test_all_facades_reject_non_configuration_values(self) -> None:
        factories = (
            LLMFirewall.from_config,
            LLMFirewallManager.from_config,
            AsyncLLMFirewall.from_config,
            AsyncLLMFirewallManager.from_config,
        )
        for factory in factories:
            with self.subTest(factory=factory.__qualname__):
                with self.assertRaises(TypeError):
                    factory(object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
