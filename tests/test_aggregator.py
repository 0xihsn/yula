"""
Tests for detection.aggregator — per-template OR rollup of TestResults.
"""

from __future__ import annotations

from datetime import datetime, timezone

from yula_ai_scanner.detection.aggregator import aggregate
from yula_ai_scanner.engine.executor import TestResult
from yula_ai_scanner.taxonomy.models import AttackPayload


def _result(template_id, status, confidence, intent="jailbreak"):
    payload = AttackPayload(
        prompt="x",
        intent_id=intent,
        intent_title=intent.title(),
        raw_example="x",
        template_id=template_id,
        template_name=template_id.replace("-", " ").title(),
    )
    return TestResult(
        payload=payload,
        response="ok",
        status=status,
        confidence=confidence,
        matched_signals=[],
        duration_ms=10.0,
        timestamp=datetime.now(timezone.utc),
        http_status=200,
    )


class TestAggregator:
    def test_any_vulnerable_marks_template_vulnerable(self):
        results = [
            _result("t1", "safe", 0.1),
            _result("t1", "safe", 0.2),
            _result("t1", "vulnerable", 0.85),
        ]
        verdicts = aggregate(results)
        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.status == "vulnerable"
        assert v.vulnerable_count == 1
        assert v.payload_count == 3
        assert v.best_confidence == 0.85
        assert v.proof_result_index == 2

    def test_all_safe_marks_template_safe(self):
        results = [_result("t1", "safe", 0.1), _result("t1", "safe", 0.05)]
        verdicts = aggregate(results)
        assert verdicts[0].status == "safe"
        assert verdicts[0].proof_result_index is None

    def test_all_errors_marks_template_error(self):
        results = [_result("t1", "error", 0.0), _result("t1", "timeout", 0.0)]
        verdicts = aggregate(results)
        assert verdicts[0].status == "error"

    def test_mixed_safe_and_error_marks_template_safe(self):
        results = [_result("t1", "safe", 0.1), _result("t1", "error", 0.0)]
        verdicts = aggregate(results)
        assert verdicts[0].status == "safe"

    def test_proof_points_to_strongest_vulnerable(self):
        results = [
            _result("t1", "vulnerable", 0.6),
            _result("t1", "safe", 0.2),
            _result("t1", "vulnerable", 0.95),
            _result("t1", "vulnerable", 0.8),
        ]
        verdicts = aggregate(results)
        assert verdicts[0].proof_result_index == 2
        assert verdicts[0].best_confidence == 0.95
        assert verdicts[0].vulnerable_count == 3

    def test_groups_by_template_id(self):
        results = [
            _result("t1", "vulnerable", 0.9),
            _result("t2", "safe", 0.1),
            _result("t1", "safe", 0.2),
        ]
        verdicts = aggregate(results)
        ids = {v.template_id for v in verdicts}
        assert ids == {"t1", "t2"}

    def test_results_without_template_id_are_skipped(self):
        no_template_payload = AttackPayload(
            prompt="x", intent_id="jailbreak", intent_title="Jailbreak",
            raw_example="x", template_id=None,
        )
        results = [
            TestResult(
                payload=no_template_payload, response="ok",
                status="vulnerable", confidence=0.9,
                duration_ms=1.0, timestamp=datetime.now(timezone.utc),
            ),
            _result("t1", "safe", 0.1),
        ]
        verdicts = aggregate(results)
        assert len(verdicts) == 1
        assert verdicts[0].template_id == "t1"

    def test_severity_passed_through(self):
        results = [_result("t1", "vulnerable", 0.9)]
        verdicts = aggregate(results, severities={"t1": "critical"})
        assert verdicts[0].severity == "critical"
