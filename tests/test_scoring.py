import unittest

from hydrate_and_verify import (
    compute_cli_risk_score,
    compute_termination_exposure_inr,
    run_smoke_test,
)


class TestScoring(unittest.TestCase):
    def test_compute_termination_exposure_inr(self):
        self.assertEqual(compute_termination_exposure_inr([0, 1, 60, 61]), 0.20)

    def test_compute_cli_risk_score(self):
        self.assertEqual(compute_cli_risk_score(0, 0, 0, 0), 0.0)
        self.assertEqual(compute_cli_risk_score(1, 2, 1, 3), 100.0)
        self.assertEqual(compute_cli_risk_score(0, 1, 0, 0), 25.0)

    def test_run_smoke_test(self):
        result = run_smoke_test(200, "/tmp/smoke_test_audit.jsonl")
        self.assertEqual(result["rows_evaluated"], 200)
        self.assertEqual(result["rule_precision"], 1.0)


if __name__ == "__main__":
    unittest.main()
