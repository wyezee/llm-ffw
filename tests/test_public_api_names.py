from inspect import signature
import unittest

from llm_ffw import (
    AsyncFirewall,
    AsyncFirewallManager,
    AsyncLLMFirewall,
    AsyncLLMFirewallManager,
    Firewall,
    FirewallManager,
    LLMFirewall,
    LLMFirewallManager,
    RuleEngine,
    RuleScanner,
    RuleScannerConfig,
    Scanner,
    ScannerConfig,
)
from llm_ffw.policy import Firewall as ModulePolicyFirewall


class PublicAPINameTests(unittest.TestCase):
    def test_canonical_names_describe_each_abstraction_level(self) -> None:
        self.assertEqual(Firewall.__name__, "Firewall")
        self.assertEqual(Firewall.__module__, "llm_ffw.facade")
        self.assertEqual(RuleEngine.__name__, "RuleEngine")
        self.assertEqual(RuleEngine.__module__, "llm_ffw.policy")
        self.assertEqual(RuleScanner.__name__, "RuleScanner")
        self.assertEqual(RuleScanner.__module__, "llm_ffw.engine")
        self.assertNotIn("scanner", signature(Firewall).parameters)
        self.assertIn("scanner", signature(RuleEngine).parameters)

    def test_non_conflicting_legacy_names_are_identity_aliases(self) -> None:
        self.assertIs(LLMFirewall, Firewall)
        self.assertIs(AsyncLLMFirewall, AsyncFirewall)
        self.assertIs(LLMFirewallManager, FirewallManager)
        self.assertIs(AsyncLLMFirewallManager, AsyncFirewallManager)
        self.assertIs(Scanner, RuleScanner)
        self.assertIs(ScannerConfig, RuleScannerConfig)

    def test_low_level_module_compatibility_has_explicit_root_name(self) -> None:
        self.assertIs(ModulePolicyFirewall, RuleEngine)


if __name__ == "__main__":
    unittest.main()
