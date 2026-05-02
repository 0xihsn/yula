"""
Tests for yula_ai_scanner.reporting.report and yula_ai_scanner.reporting.severity.

Validates severity scoring, report building, and visibility gating in the
Jinja2 template output.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from yula_ai_scanner.config.scan_schema import VisibilityLevel
from yula_ai_scanner.engine.executor import TestResult
from yula_ai_scanner.reporting.report import ReportBuilder
from yula_ai_scanner.reporting.severity import (
    SeverityRating,
    compute_score,
    compute_severity,
)
from yula_ai_scanner.taxonomy.models import AttackPayload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    intent_id: str = "jailbreak",
    status: str = "vulnerable",
    confidence: float = 0.85,
    technique_id: str | None = None,
    evasion_id: str | None = None,
) -> TestResult:
    payload = AttackPayload(
        prompt="test prompt",
        intent_id=intent_id,
        intent_title=intent_id.replace("_", " ").title(),
        technique_id=technique_id,
        technique_title="Narrative Smuggling" if technique_id else None,
        evasion_id=evasion_id,
        evasion_title="Base64" if evasion_id else None,
        raw_example="test prompt",
    )
    return TestResult(
        payload=payload,
        response="Sure! Here are the steps." if status == "vulnerable" else "I cannot help.",
        raw_response=None,
        status=status,
        confidence=confidence,
        matched_signals=["jailbreak_compliance"] if status == "vulnerable" else [],
        duration_ms=150.0,
        timestamp=datetime.now(timezone.utc),
        http_status=200,
        error_message=None,
    )


# ---------------------------------------------------------------------------
# Severity scoring tests
# ---------------------------------------------------------------------------

class TestSeverityScoring:
    def test_compute_score_returns_float(self):
        result = _make_result()
        score = compute_score(result)
        assert isinstance(score, float)
        assert 0.0 <= score <= 10.0

    def test_technique_adds_bonus(self):
        without = compute_score(_make_result(technique_id=None))
        with_ = compute_score(_make_result(technique_id="narrative_smuggling"))
        assert with_ > without

    def test_evasion_adds_bonus(self):
        without = compute_score(_make_result(evasion_id=None))
        with_ = compute_score(_make_result(evasion_id="base64"))
        assert with_ > without

    def test_high_impact_intent_scores_higher(self):
        low = compute_score(_make_result(intent_id="test_bias", confidence=0.8))
        high = compute_score(_make_result(intent_id="jailbreak", confidence=0.8))
        assert high > low

    def test_compute_severity_returns_severity_rating(self):
        result = _make_result(confidence=0.95)
        sev = compute_severity(result)
        assert isinstance(sev, SeverityRating)

    def test_low_confidence_maps_to_low_or_info(self):
        result = _make_result(confidence=0.5)
        sev = compute_severity(result)
        assert sev in (SeverityRating.INFO, SeverityRating.LOW, SeverityRating.MEDIUM)

    def test_high_confidence_high_impact_maps_to_critical_or_high(self):
        result = _make_result(intent_id="system_prompt_leak", confidence=0.99)
        sev = compute_severity(result)
        assert sev in (SeverityRating.CRITICAL, SeverityRating.HIGH)


# ---------------------------------------------------------------------------
# ReportBuilder tests
# ---------------------------------------------------------------------------

class TestReportBuilder:
    def test_build_returns_string(self):
        builder = ReportBuilder()
        results = [_make_result(), _make_result(status="safe", confidence=0.1)]
        rendered = builder.build(
            results=results,
            target_url="http://localhost:8080",
            target_type="openai",
            auth_type="api_key",
            visibility=VisibilityLevel.CONFIDENTIAL,
            duration_seconds=12.5,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert isinstance(rendered, str)
        assert len(rendered) > 100

    def test_report_contains_target_url(self):
        builder = ReportBuilder()
        results = [_make_result()]
        rendered = builder.build(
            results=results,
            target_url="http://my-special-target.example",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.INTERNAL,
            duration_seconds=5.0,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert "my-special-target.example" in rendered

    def test_public_report_includes_vulnerable_payload(self):
        # Vulnerable findings always include input + output regardless of visibility.
        builder = ReportBuilder()
        results = [_make_result()]
        rendered = builder.build(
            results=results,
            target_url="http://localhost",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.PUBLIC,
            duration_seconds=5.0,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert "test prompt" in rendered
        assert "Sure! Here are the steps." in rendered

    def test_confidential_report_includes_payload(self):
        builder = ReportBuilder()
        results = [_make_result()]
        rendered = builder.build(
            results=results,
            target_url="http://localhost",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.CONFIDENTIAL,
            duration_seconds=5.0,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert "test prompt" in rendered

    def test_save_writes_file(self, tmp_path):
        builder = ReportBuilder()
        report_path = tmp_path / "report.md"
        builder.save("# Test Report\n\nContent here.", report_path)
        assert report_path.exists()
        assert report_path.read_text() == "# Test Report\n\nContent here."

    def test_no_findings_report_does_not_crash(self):
        builder = ReportBuilder()
        rendered = builder.build(
            results=[_make_result(status="safe", confidence=0.05)],
            target_url="http://localhost",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.INTERNAL,
            duration_seconds=1.0,
            intents=[],
            techniques=[],
            evasions=[],
        )
        assert isinstance(rendered, str)

    def test_build_json_returns_dict(self):
        builder = ReportBuilder()
        results = [_make_result(), _make_result(status="safe", confidence=0.1)]
        data = builder.build_json(
            results=results,
            target_url="http://localhost:8080",
            target_type="openai",
            auth_type="api_key",
            visibility=VisibilityLevel.CONFIDENTIAL,
            duration_seconds=12.5,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert isinstance(data, dict)
        assert "scan_id" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_build_json_timestamp_is_string(self):
        builder = ReportBuilder()
        data = builder.build_json(
            results=[_make_result()],
            target_url="http://localhost",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.INTERNAL,
            duration_seconds=1.0,
            intents=[],
            techniques=[],
            evasions=[],
        )
        assert isinstance(data["timestamp"], str)

    def test_save_json_writes_file(self, tmp_path):
        builder = ReportBuilder()
        json_path = tmp_path / "report.json"
        builder.save_json({"scan_id": "abc-123", "findings": []}, json_path)
        import json
        assert json_path.exists()
        parsed = json.loads(json_path.read_text())
        assert parsed["scan_id"] == "abc-123"
        assert parsed["findings"] == []

    def test_build_json_vulnerable_finding_in_findings(self):
        builder = ReportBuilder()
        data = builder.build_json(
            results=[_make_result(status="vulnerable", confidence=0.9)],
            target_url="http://localhost",
            target_type="openai",
            auth_type="none",
            visibility=VisibilityLevel.CONFIDENTIAL,
            duration_seconds=1.0,
            intents=["Jailbreak"],
            techniques=[],
            evasions=[],
        )
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["intent_id"] == "jailbreak"
        assert "severity" in finding
        assert "score" in finding
