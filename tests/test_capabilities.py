from dataclasses import FrozenInstanceError
import unittest

from llm_ffw import (
    FirewallCapabilities,
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


if __name__ == "__main__":
    unittest.main()
