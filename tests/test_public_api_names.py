from inspect import signature
import unittest

import llm_ffw
import llm_ffw.async_facade as async_facade_module
import llm_ffw.config as config_module
import llm_ffw.engine as engine_module
import llm_ffw.facade as facade_module
import llm_ffw.manager as manager_module
import llm_ffw.policy as policy_module

from llm_ffw import (
    AsyncFirewall,
    AsyncFirewallManager,
    Firewall,
    FirewallManager,
    RuleEngine,
    RuleScanner,
    RuleScannerConfig,
)


class PublicAPINameTests(unittest.TestCase):
    def test_canonical_names_describe_each_abstraction_level(self) -> None:
        self.assertEqual(Firewall.__name__, "Firewall")
        self.assertEqual(Firewall.__module__, "llm_ffw.facade")
        self.assertEqual(RuleEngine.__name__, "RuleEngine")
        self.assertEqual(RuleEngine.__module__, "llm_ffw.policy")
        self.assertEqual(RuleScanner.__name__, "RuleScanner")
        self.assertEqual(RuleScanner.__module__, "llm_ffw.engine")
        self.assertEqual(AsyncFirewall.__module__, "llm_ffw.async_facade")
        self.assertEqual(
            AsyncFirewallManager.__module__,
            "llm_ffw.async_facade",
        )
        self.assertEqual(FirewallManager.__module__, "llm_ffw.manager")
        self.assertEqual(RuleScannerConfig.__module__, "llm_ffw.config")
        self.assertNotIn("scanner", signature(Firewall).parameters)
        self.assertIn("scanner", signature(RuleEngine).parameters)

    def test_pre_one_compatibility_aliases_are_removed(self) -> None:
        removed_by_module = (
            (llm_ffw, "LLMFirewall"),
            (llm_ffw, "AsyncLLMFirewall"),
            (llm_ffw, "LLMFirewallManager"),
            (llm_ffw, "AsyncLLMFirewallManager"),
            (llm_ffw, "Scanner"),
            (llm_ffw, "ScannerConfig"),
            (facade_module, "LLMFirewall"),
            (async_facade_module, "AsyncLLMFirewall"),
            (async_facade_module, "AsyncLLMFirewallManager"),
            (manager_module, "LLMFirewallManager"),
            (engine_module, "Scanner"),
            (config_module, "ScannerConfig"),
            (policy_module, "Firewall"),
        )
        for module, name in removed_by_module:
            with self.subTest(module=module.__name__, name=name):
                self.assertFalse(hasattr(module, name))
                self.assertNotIn(name, module.__all__)


if __name__ == "__main__":
    unittest.main()
