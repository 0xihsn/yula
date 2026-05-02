"""
Verify that sequential AttackPayloads are routed through send_turns and that
single-turn payloads still go through send.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yula_ai_scanner.engine.adapters.base import AdapterResponse
from yula_ai_scanner.engine.executor import TestExecutor
from yula_ai_scanner.taxonomy.models import AttackPayload


def _payload(turns: list[str], template_id: str = "t1") -> AttackPayload:
    return AttackPayload(
        prompt=turns[0],
        intent_id="multi_chain_attacks",
        intent_title="Multi Chain Attacks",
        raw_example="\n".join(turns),
        template_id=template_id,
        followup_prompts=turns[1:],
    )


def _adapter(send_text="single", chain_text="chain"):
    adapter = MagicMock()
    adapter.setup = AsyncMock()
    adapter.teardown = AsyncMock()
    adapter.send = AsyncMock(return_value=AdapterResponse(
        text=send_text, http_status=200, raw_body=None, duration_ms=10.0
    ))
    adapter.send_turns = AsyncMock(return_value=AdapterResponse(
        text=chain_text, http_status=200, raw_body=None,
        duration_ms=20.0, turn_texts=[chain_text],
    ))
    return adapter


class TestSequentialRouting:
    @pytest.mark.asyncio
    async def test_sequential_payload_uses_send_turns(
        self, default_scan_config, openai_target_config
    ):
        adapter = _adapter()
        payload = _payload(["t1", "t2", "t3"])

        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(default_scan_config, openai_target_config, MagicMock())
            executor.analyzer = MagicMock()
            executor.analyzer.analyze = MagicMock(return_value=("safe", 0.1, []))
            progress = MagicMock()
            progress.update = MagicMock()
            await executor.run_all([payload], progress)

        adapter.send_turns.assert_awaited_once()
        assert adapter.send_turns.call_args.args[0] == ["t1", "t2", "t3"]
        adapter.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_single_turn_payload_uses_send(
        self, default_scan_config, openai_target_config
    ):
        adapter = _adapter()
        payload = _payload(["only"])  # only one turn → followup_prompts == []

        with patch("yula_ai_scanner.engine.executor.get_adapter", return_value=adapter):
            executor = TestExecutor(default_scan_config, openai_target_config, MagicMock())
            executor.analyzer = MagicMock()
            executor.analyzer.analyze = MagicMock(return_value=("safe", 0.1, []))
            progress = MagicMock()
            progress.update = MagicMock()
            await executor.run_all([payload], progress)

        adapter.send.assert_awaited_once_with("only")
        adapter.send_turns.assert_not_called()
