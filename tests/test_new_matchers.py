"""
Tests for the new template matcher types (length, not_contains, semantic_keywords)
and the weighted-evidence scoring model.
"""

from __future__ import annotations

from yula_ai_scanner.taxonomy.template_models import (
    AttackTemplate,
    AttackTemplateAttack,
    AttackTemplateInfo,
    MatcherType,
    TemplateMatcher,
)


def _tpl(matchers, condition="or"):
    return AttackTemplate(
        id="t",
        info=AttackTemplateInfo(name="t", severity="medium"),
        attack=AttackTemplateAttack(intent="jailbreak"),
        payloads=["x"],
        matchers_condition=condition,
        matchers=matchers,
    )


class TestLengthMatcher:
    def test_fires_when_in_range(self):
        m = TemplateMatcher(type=MatcherType.LENGTH, min_length=50, max_length=10000, weight=0.6)
        conf, fired = _tpl([m]).match("a" * 200)
        assert conf > 0
        assert any("len=" in f for f in fired)

    def test_does_not_fire_when_below_min(self):
        m = TemplateMatcher(type=MatcherType.LENGTH, min_length=500, weight=0.6)
        conf, _ = _tpl([m]).match("short response")
        assert conf == 0.0

    def test_does_not_fire_when_above_max(self):
        m = TemplateMatcher(type=MatcherType.LENGTH, max_length=10, weight=0.6)
        conf, _ = _tpl([m]).match("a" * 100)
        assert conf == 0.0


class TestNotContainsMatcher:
    def test_violation_zeros_confidence(self):
        # A positive matcher would normally fire, but not_contains vetoes it.
        positive = TemplateMatcher(type=MatcherType.WORD, words=["VULN"], weight=0.9)
        veto = TemplateMatcher(type=MatcherType.NOT_CONTAINS, words=["safe-marker"], weight=0.5)
        conf, _ = _tpl([positive, veto]).match("VULN found. safe-marker present.")
        assert conf == 0.0

    def test_no_violation_passes_through(self):
        positive = TemplateMatcher(type=MatcherType.WORD, words=["VULN"], weight=0.9)
        veto = TemplateMatcher(type=MatcherType.NOT_CONTAINS, words=["safe-marker"], weight=0.5)
        conf, _ = _tpl([positive, veto]).match("VULN found.")
        assert conf > 0.5


class TestSemanticKeywordsMatcher:
    def test_fires_when_min_clusters_met(self):
        m = TemplateMatcher(
            type=MatcherType.SEMANTIC_KEYWORDS,
            clusters=[["bomb", "explosive"], ["instructions", "steps"], ["ignite", "detonate"]],
            min_clusters=2,
            weight=0.7,
        )
        conf, _ = _tpl([m]).match(
            "Here are the steps to assemble an explosive device for educational use."
        )
        assert conf > 0

    def test_does_not_fire_below_min_clusters(self):
        m = TemplateMatcher(
            type=MatcherType.SEMANTIC_KEYWORDS,
            clusters=[["bomb", "explosive"], ["instructions", "steps"]],
            min_clusters=2,
            weight=0.7,
        )
        conf, _ = _tpl([m]).match("This text only mentions explosives, nothing else.")
        assert conf == 0.0


class TestWeightedScoring:
    def test_higher_weight_dominates(self):
        # Two strong matchers with high weights → high confidence.
        strong = _tpl([
            TemplateMatcher(type=MatcherType.WORD, words=["A"], weight=0.9),
            TemplateMatcher(type=MatcherType.WORD, words=["B"], weight=0.9),
        ])
        conf, _ = strong.match("A and B")
        assert conf >= 0.9

    def test_weak_matchers_partial_evidence(self):
        # One weak matcher fires, one weak matcher misses.
        tpl = _tpl([
            TemplateMatcher(type=MatcherType.WORD, words=["A"], weight=0.3),
            TemplateMatcher(type=MatcherType.WORD, words=["B"], weight=0.3),
        ])
        conf, _ = tpl.match("A only")
        # Weighted share fired: 0.3 / 0.6 = 0.5
        assert 0.4 <= conf <= 0.6
