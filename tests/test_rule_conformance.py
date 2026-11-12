import json
import pathlib
import unittest

from hydrate_and_verify import evaluate_rules

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "rule_conformance.json"


def load_cases():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestRuleConformance(unittest.TestCase):
    """The rules must behave identically in every runtime. These fixtures are
    the shared contract: the Python engine runs them here, and the browser
    suite (tests/test_ui_clear_flow.py) runs the same file through the JS
    implementation. A case added here must pass in both."""

    def test_python_matches_the_conformance_fixture(self) -> None:
        for case in load_cases():
            with self.subTest(case=case["name"]):
                decision = evaluate_rules(case)
                failed = set(decision["failed_rules"])
                for rule in case.get("expect_failed", []):
                    self.assertIn(rule, failed, f"{case['name']}: expected {rule}")
                for rule in case.get("expect_failed_contains", []):
                    self.assertIn(rule, failed, f"{case['name']}: expected {rule}")


if __name__ == "__main__":
    unittest.main()