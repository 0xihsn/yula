"""
Tests for the new template `mode:` field and matrix-builder branching.
"""

from __future__ import annotations

import textwrap

import pytest

from yula_ai_scanner.taxonomy.matrix_builder import MatrixBuilder
from yula_ai_scanner.taxonomy.template_loader import TemplateLoader
from yula_ai_scanner.taxonomy.template_models import TemplateMode


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


class TestTemplateModeParsing:
    def test_default_mode_is_parallel(self, tmp_path):
        _write(tmp_path, "p.yaml", """\
            id: parallel-default
            info: {name: Parallel, severity: medium}
            attack: {intent: jailbreak}
            payloads: ["a", "b"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        assert templates["parallel-default"].mode == TemplateMode.PARALLEL

    def test_sequential_mode_parsed(self, tmp_path):
        _write(tmp_path, "s.yaml", """\
            id: sequential-chain
            info: {name: Chain, severity: high}
            attack: {intent: multi_chain_attacks}
            mode: sequential
            payloads: ["turn1", "turn2", "turn3"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        assert templates["sequential-chain"].mode == TemplateMode.SEQUENTIAL

    def test_invalid_mode_skips_template(self, tmp_path):
        _write(tmp_path, "bad.yaml", """\
            id: bad-mode
            info: {name: Bad, severity: low}
            attack: {intent: jailbreak}
            mode: not-a-real-mode
            payloads: ["x"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        assert "bad-mode" not in templates


class TestMatrixBuilderModes:
    def test_parallel_emits_one_payload_per_item(self, tmp_path):
        _write(tmp_path, "p.yaml", """\
            id: par
            info: {name: Par, severity: medium}
            attack: {intent: jailbreak}
            payloads: ["a", "b", "c"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        payloads = MatrixBuilder().build_from_templates(templates)
        assert len(payloads) == 3
        for p in payloads:
            assert p.followup_prompts == []
            assert p.is_sequential is False
        assert {p.payload_index for p in payloads} == {1, 2, 3}
        assert all(p.payload_total == 3 for p in payloads)

    def test_sequential_emits_one_chained_payload(self, tmp_path):
        _write(tmp_path, "s.yaml", """\
            id: seq
            info: {name: Seq, severity: high}
            attack: {intent: multi_chain_attacks}
            mode: sequential
            payloads: ["t1", "t2", "t3"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        payloads = MatrixBuilder().build_from_templates(templates)
        assert len(payloads) == 1
        p = payloads[0]
        assert p.prompt == "t1"
        assert p.followup_prompts == ["t2", "t3"]
        assert p.all_turns == ["t1", "t2", "t3"]
        assert p.is_sequential is True

    def test_sequential_with_one_payload_has_no_followups(self, tmp_path):
        _write(tmp_path, "s.yaml", """\
            id: short
            info: {name: Short, severity: high}
            attack: {intent: multi_chain_attacks}
            mode: sequential
            payloads: ["only"]
        """)
        templates = TemplateLoader(tmp_path).load_all()
        payloads = MatrixBuilder().build_from_templates(templates)
        assert len(payloads) == 1
        assert payloads[0].followup_prompts == []
        assert payloads[0].is_sequential is False
