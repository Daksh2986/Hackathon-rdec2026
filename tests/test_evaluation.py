from __future__ import annotations

import unittest

from evaluation.run_evaluation import evaluate


class EvaluationTests(unittest.TestCase):
    def test_labeled_fixtures_report_expected_metrics(self) -> None:
        report = evaluate()
        self.assertEqual(report["fixtures"], 3)
        self.assertEqual(report["confusion_matrix"]["true_positive"], 2)
        self.assertEqual(report["confusion_matrix"]["true_negative"], 1)
        self.assertEqual(report["precision"], 1.0)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["source_to_sink_path_accuracy"], 1.0)
        self.assertEqual(report["parse_errors"], [])


if __name__ == "__main__":
    unittest.main()
