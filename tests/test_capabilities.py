from dataclasses import FrozenInstanceError
import unittest

from llm_ffw import (
    FirewallCapabilities,
    EmailAddressCapability,
    IPAddressCapability,
    MACAddressCapability,
    RuleCapability,
    ScanScope,
    SecretCatalogCapability,
)


class CapabilityValueTests(unittest.TestCase):
    def test_values_are_normalized_and_immutable(self) -> None:
        rule = RuleCapability(
            rule_id="secrets.detected",
            purpose="Detect secrets.",
            scopes=(ScanScope.OUTPUT, ScanScope.INPUT, ScanScope.INPUT),
        )
        catalog = SecretCatalogCapability(
            catalog_id="catalog",
            version="1.0.0",
            signature_count=2,
            prefix_count=3,
            providers=("zeta", "acme", "acme"),
        )
        capabilities = FirewallCapabilities(
            rules=(rule,),
            secret_catalog=catalog,
            policy_id="balanced",
            policy_version="1.0.0",
        )

        self.assertEqual(
            rule.scopes,
            (ScanScope.INPUT, ScanScope.OUTPUT),
        )
        self.assertEqual(catalog.providers, ("acme", "zeta"))
        self.assertEqual(capabilities.rule_count, 1)
        with self.assertRaises(FrozenInstanceError):
            capabilities.policy_id = "changed"  # type: ignore[misc]

    def test_rejects_invalid_capability_descriptions(self) -> None:
        with self.assertRaises(ValueError):
            RuleCapability("rule", "purpose", ())
        with self.assertRaises(ValueError):
            SecretCatalogCapability("catalog", "1", 0, 1, ("acme",))
        rule = RuleCapability(
            "secrets.detected",
            "Detect secrets.",
            (ScanScope.INPUT,),
        )
        catalog = SecretCatalogCapability(
            "catalog",
            "1",
            1,
            1,
            ("acme",),
        )
        with self.assertRaises(ValueError):
            FirewallCapabilities(
                rules=(rule, rule),
                secret_catalog=catalog,
                policy_id="balanced",
                policy_version="1",
            )

    def test_ip_address_capability_is_bounded_and_typed(self) -> None:
        capability = IPAddressCapability(
            max_candidates=128,
            include_ipv4=True,
            include_ipv6=False,
        )
        self.assertEqual(capability.max_candidates, 128)
        with self.assertRaises(ValueError):
            IPAddressCapability(0, True, True)
        with self.assertRaises(TypeError):
            IPAddressCapability(1, 1, True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            IPAddressCapability(1, False, False)

    def test_email_address_capability_is_bounded_and_typed(self) -> None:
        capability = EmailAddressCapability(max_candidates=128)
        self.assertEqual(capability.max_candidates, 128)
        with self.assertRaises(ValueError):
            EmailAddressCapability(0)
        with self.assertRaises(ValueError):
            EmailAddressCapability(True)

    def test_mac_address_capability_is_bounded_and_typed(self) -> None:
        capability = MACAddressCapability(max_candidates=128)
        self.assertEqual(capability.max_candidates, 128)
        with self.assertRaises(ValueError):
            MACAddressCapability(0)
        with self.assertRaises(ValueError):
            MACAddressCapability(True)


if __name__ == "__main__":
    unittest.main()
