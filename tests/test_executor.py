"""
Tests for yula_ai_scanner.engine.executor.

Uses mock adapters to test orchestration logic — concurrency control,
per-test error isolation, and TestResult construction — without hitting
any real network endpoint.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yula_ai_scanner.engine.adapters.base import AdapterResponse
from yula_ai_scanner.engine.executor import TestExecutor, TestResult
from yula_ai_scanner.taxonomy.models import AttackPayload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _payload(intent_id: str = "jailbreak", idx: int = 0) -> AttackPayload:
    return AttackPayload(
        prompt=f"test prompt {idx}",
        intent_id=intent_id,
        intent_title=intent_id.replace("_", " ").title(),
        technique_id=None,
        technique_title=None,
        evasion_id=None,
        evasion_title=None,
        raw_example=f"test prompt {idx}",
    )


def _mock_adapter(response_text: str = "I cannot help.", status: int = 200):
    adapter = MagicMock()
    adapter.setup = AsyncMock()
    adapter.teardown = AsyncMock()
    adapter.send = AsyncMock(
        return_value=AdapterResponse(
            text=response_text,
            http_status=status,
            raw_body=None,
            duration_ms=50.0,
        )
    )
    return adapter


# ---------------------------------------------------------------------------
# TestResult model
# ---------------------------------------------------------------------------

class TestTestResult:
    def test_test_result_construction(self, sample_payload, analyzer):
        result = TestResult(
            payload=sample_payload,
            response="I cannot help with that.",
            raw_response=None,
            status="safe",
            confidence=0.1,
            matched_signals=[],
            duration_ms=120.0,
            timestamp=datetime.now(timezone.utc),
            http_status=200,
            error_message=None,
        )
        assert result.status == "safe"
        assert result.confidence == 0.1

    def test_test_result_vulnerable(self, sample_payload):
        result = TestResult(
            payload=sample_payload,
            response="Absolutely! Here are the steps:",
            raw_response=None,
            status="vulnerable",
            confidence=0.85,
            matched_signals=["jailbreak_compliance"],
            duration_ms=200.0,
            timestamp=datetime.now(timezone.utc),
            http_status=200,
            error_message=None,
        )
        assert result.status == "vulnerable"
        assert "jailbreak_compliance" in result.matched_signals


# ---------------------------------------------------------------------------
# Executor orchestration tests
# ---------------------------------------------------------------------------

class TestTestExecutor:
    def _make_executor(self, scan_config, target_config, adapter):
        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(scan_config, target_config, MagicMock())
            executor._adapter = adapter
            return executor

    @pytest.mark.asyncio
    async def test_run_all_returns_results_for_each_payload(
        self, default_scan_config, openai_target_config
    ):
        payloads = [_payload(idx=i) for i in range(3)]
        adapter = _mock_adapter("I cannot help with that.")

        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(
                default_scan_config, openai_target_config, MagicMock()
            )
            executor._adapter = adapter
            progress = MagicMock()
            progress.update = MagicMock()

            results = await executor.run_all(payloads, progress)

        assert len(results) == 3
        assert progress.update.call_count == 3

    @pytest.mark.asyncio
    async def test_adapter_error_yields_error_status(
        self, default_scan_config, openai_target_config
    ):
        payloads = [_payload()]
        adapter = MagicMock()
        adapter.setup = AsyncMock()
        adapter.teardown = AsyncMock()
        adapter.send = AsyncMock(side_effect=RuntimeError("connection failed"))

        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(
                default_scan_config, openai_target_config, MagicMock()
            )
            executor._adapter = adapter
            progress = MagicMock()
            progress.update = MagicMock()

            results = await executor.run_all(payloads, progress)

        assert results[0].status == "error"
        assert results[0].error_message is not None

    @pytest.mark.asyncio
    async def test_empty_payload_list_returns_empty(
        self, default_scan_config, openai_target_config
    ):
        adapter = _mock_adapter()
        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(
                default_scan_config, openai_target_config, MagicMock()
            )
            executor._adapter = adapter
            results = await executor.run_all([], MagicMock())

        assert results == []
