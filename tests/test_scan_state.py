"""
Tests for the per-target scan state used by `scan --continue`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from yula_ai_scanner.engine.executor import TestResult
from yula_ai_scanner.state.scan_state import (
    ScanState,
    load_state,
    save_state,
    target_state_key,
)
from yula_ai_scanner.taxonomy.models import AttackPayload


def _result(template_id: str, status: str) -> TestResult:
    payload = AttackPayload(
        prompt="x", intent_id="jailbreak", intent_title="Jailbreak",
        raw_example="x", template_id=template_id,
    )
    return TestResult(
        payload=payload,
        response="ok",
        status=status,
        confidence=0.9 if status == "vulnerable" else 0.1,
        duration_ms=10.0,
        timestamp=datetime.now(timezone.utc),
    )


class TestStateKey:
    def test_key_is_deterministic_for_same_inputs(self):
        p = Path("config/targets/openai_target.yaml")
        a = target_state_key(p, "https://api.openai.com/v1/chat/completions")
        b = target_state_key(p, "https://api.openai.com/v1/chat/completions")
        assert a == b

    def test_key_differs_for_different_urls(self):
        p = Path("config/targets/openai_target.yaml")
        a = target_state_key(p, "https://a.example/v1")
        b = target_state_key(p, "https://b.example/v1")
        assert a != b

    def test_key_differs_for_different_target_files(self):
        url = "https://example.com"
        a = target_state_key(Path("config/targets/a.yaml"), url)
        b = target_state_key(Path("config/targets/b.yaml"), url)
        assert a != b


class TestScanState:
    def test_completed_includes_only_successful_results(self):
        state = ScanState(target_key="k", target_url="u")
        state.add_scan(
            scan_id="s1",
            results=[
                _result("t1", "vulnerable"),
                _result("t2", "safe"),
                _result("t3", "error"),
                _result("t4", "timeout"),
            ],
        )
        completed = state.completed_template_ids
        assert "t1" in completed
        assert "t2" in completed
        assert "t3" not in completed
        assert "t4" not in completed

    def test_errored_templates_can_be_retried(self):
        # If a template only produced error results, it should NOT be in
        # the completed set (so --continue retries it).
        state = ScanState(target_key="k", target_url="u")
        state.add_scan(
            scan_id="s1",
            results=[_result("t1", "error"), _result("t1", "timeout")],
        )
        assert "t1" not in state.completed_template_ids

    def test_partial_template_completion_counts_as_completed(self):
        # If at least one variant of a template completed cleanly, the
        # template counts as completed for --continue purposes.
        state = ScanState(target_key="k", target_url="u")
        state.add_scan(
            scan_id="s1",
            results=[_result("t1", "error"), _result("t1", "safe")],
        )
        assert "t1" in state.completed_template_ids

    def test_unions_across_multiple_scans(self):
        state = ScanState(target_key="k", target_url="u")
        state.add_scan(scan_id="s1", results=[_result("t1", "safe")])
        state.add_scan(scan_id="s2", results=[_result("t2", "vulnerable")])
        assert state.completed_template_ids == {"t1", "t2"}

    def test_save_and_load_roundtrip(self, tmp_path):
        state = ScanState(target_key="k", target_url="https://x")
        state.add_scan(
            scan_id="s1",
            results=[_result("t1", "safe"), _result("t2", "error")],
        )
        save_state(state, tmp_path)
        loaded = load_state(tmp_path, "k", "https://x")
        assert loaded.completed_template_ids == {"t1"}
        assert len(loaded.scans) == 1

    def test_load_returns_fresh_state_when_file_missing(self, tmp_path):
        loaded = load_state(tmp_path, "missing", "u")
        assert loaded.target_key == "missing"
        assert loaded.scans == []

    def test_load_recovers_from_corrupt_state_file(self, tmp_path):
        path = tmp_path / "k.state.json"
        path.write_text("not valid json", encoding="utf-8")
        loaded = load_state(tmp_path, "k", "u")
        assert loaded.scans == []
