"""
Quality gate for the YULA AI Scanner template corpus.

Each template must satisfy these structural rules so the matcher engine
behaves predictably under benign and refusal responses:

  1. ≥ 3 payloads.
  2. ≥ 1 refusal-style matcher (`negative` or `not_contains`).
  3. No payload contains a literal placeholder string ([payload], etc.).
  4. No single positive matcher with weight ≥ 0.9 standing alone in OR mode
     (a single high-weight positive that fires alone gives confidence 1.0;
     templates must require co-occurrence — see docs/template_authoring.md §3).
  5. attack.intent matches the parent-directory name, EXCEPT for the dimension
     directories `evasions/` and `techniques/` whose templates carry their
     intent in `attack.intent` (the directory says how, not what).
  6. All regex matchers compile (Pydantic validates this at load time; we
     re-assert here for clarity in failure messages).

Rules are defined in docs/template_authoring.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from yula_ai_scanner.taxonomy.template_loader import TemplateLoader
from yula_ai_scanner.taxonomy.template_models import AttackTemplate, MatcherType

from tests.conftest import PROJECT_ROOT

TEMPLATES_DIR = PROJECT_ROOT / "templates"

# Directories that classify a template by attack DIMENSION rather than INTENT.
# Templates inside these dirs are still required to declare a real intent in
# `attack.intent`, but that intent need not equal the directory name.
DIMENSION_DIRS = {"evasions", "techniques"}

PAYLOAD_PLACEHOLDERS = ("[payload]", "[hidden instruction]", "<<INSERT>>")

POSITIVE_MATCHER_TYPES = {
    MatcherType.WORD,
    MatcherType.REGEX,
    MatcherType.LENGTH,
    MatcherType.SEMANTIC_KEYWORDS,
}


def _all_templates() -> list[tuple[str, AttackTemplate]]:
    if not TEMPLATES_DIR.exists():
        pytest.skip("templates/ not found")
    loader = TemplateLoader(TEMPLATES_DIR)
    templates = loader.load_all()
    if not templates:
        pytest.skip("no templates loaded")
    return sorted(templates.items())


def _category_dir_for(template: AttackTemplate) -> str:
    return Path(template.source).parent.name


def _is_under_dimension_dir(template: AttackTemplate) -> bool:
    """True if any ancestor directory of the template is a dimension dir.

    The corpus uses `evasions/<subcategory>/<file>` and `techniques/<file>`,
    so we walk the path parents to see if any ancestor is a dimension dir.
    """
    for parent in Path(template.source).parents:
        if parent.name in DIMENSION_DIRS:
            return True
    return False


def _positive_matchers(template: AttackTemplate):
    return [m for m in template.matchers if m.type in POSITIVE_MATCHER_TYPES]


def _refusal_matchers(template: AttackTemplate):
    return [
        m for m in template.matchers
        if m.type in (MatcherType.NEGATIVE, MatcherType.NOT_CONTAINS)
    ]


@pytest.fixture(scope="module")
def template_corpus() -> list[tuple[str, AttackTemplate]]:
    return _all_templates()


@pytest.mark.parametrize("rule", ["min_payloads"])
def test_min_payload_count(template_corpus, rule):
    """Every template must ship ≥ 3 payloads (per docs/template_authoring.md §8)."""
    failures: list[str] = []
    for tid, t in template_corpus:
        if len(t.payloads) < 3:
            failures.append(f"{tid} ({Path(t.source).name}): {len(t.payloads)} payloads")
    assert not failures, "Templates with too few payloads:\n  " + "\n  ".join(failures)


def test_at_least_one_refusal_matcher(template_corpus):
    """Every template must have ≥ 1 negative or not_contains matcher."""
    failures: list[str] = []
    for tid, t in template_corpus:
        if not _refusal_matchers(t):
            failures.append(f"{tid} ({Path(t.source).name})")
    assert not failures, (
        "Templates with no refusal matcher (need ≥1 negative or not_contains):\n  "
        + "\n  ".join(failures)
    )


def test_no_placeholder_payloads(template_corpus):
    """Payloads must not contain literal placeholders like [payload]."""
    failures: list[str] = []
    for tid, t in template_corpus:
        for i, payload in enumerate(t.payloads):
            for placeholder in PAYLOAD_PLACEHOLDERS:
                if placeholder in payload:
                    failures.append(f"{tid} payload[{i}] contains '{placeholder}'")
                    break
    assert not failures, "Templates with placeholder payloads:\n  " + "\n  ".join(failures)


def test_no_single_high_weight_positive(template_corpus):
    """In OR mode, no single positive matcher may stand alone with weight ≥ 0.9.

    The OR scoring formula is `fired_weight / total_weight`, so a single
    positive matcher firing alone produces confidence 1.0 regardless of weight.
    The ≥ 0.9 floor catches the most egregious cases (templates relying on a
    single high-confidence pattern for an entire vulnerability decision).
    """
    failures: list[str] = []
    for tid, t in template_corpus:
        if t.matchers_condition != "or":
            continue
        positives = _positive_matchers(t)
        if len(positives) == 1 and positives[0].weight >= 0.9:
            failures.append(
                f"{tid} ({Path(t.source).name}): "
                f"single {positives[0].type.value} matcher weight={positives[0].weight}"
            )
    assert not failures, (
        "Templates relying on a single high-weight positive matcher "
        "(see docs/template_authoring.md §3.1):\n  "
        + "\n  ".join(failures)
    )


def test_intent_matches_directory(template_corpus):
    """attack.intent matches the parent-directory name (except dimension dirs)."""
    failures: list[str] = []
    for tid, t in template_corpus:
        if _is_under_dimension_dir(t):
            continue
        category = _category_dir_for(t)
        if t.attack.intent != category:
            failures.append(
                f"{tid} ({Path(t.source).name}): "
                f"intent='{t.attack.intent}' but directory='{category}'"
            )
    assert not failures, (
        "Templates whose attack.intent does not match their parent directory:\n  "
        + "\n  ".join(failures)
    )


def test_regex_patterns_compile(template_corpus):
    """All regex matchers compile (re-asserts what Pydantic checks at load)."""
    failures: list[str] = []
    for tid, t in template_corpus:
        for m in t.matchers:
            for pattern in m.regex:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    failures.append(f"{tid}: {pattern!r} → {exc}")
    assert not failures, "Templates with un-compilable regex:\n  " + "\n  ".join(failures)


def test_corpus_size_lower_bound(template_corpus):
    """Sanity: the corpus should never silently shrink to a handful of templates."""
    assert len(template_corpus) >= 150, (
        f"Template corpus shrank to {len(template_corpus)} — investigate before merging."
    )


def test_arc_pi_attribution_present(template_corpus):
    """Every template must record Arc PI Taxonomy attribution.

    The CC-BY-4.0 license under which the Arc PI Taxonomy is published
    requires per-derivative attribution. We enforce that every YAML in
    `templates/` has the three `info.source*` fields populated.
    """
    failures: list[str] = []
    for tid, t in template_corpus:
        if (
            t.info.source != "Arc PI Taxonomy"
            or t.info.source_url != "https://github.com/Arcanum-Sec/arc_pi_taxonomy"
            or t.info.source_license != "CC-BY-4.0"
        ):
            failures.append(f"{tid} ({Path(t.source).name})")
    assert not failures, (
        "Templates missing Arc PI Taxonomy attribution "
        "(run scripts/add_arcpi_attribution.py):\n  " + "\n  ".join(failures)
    )


def test_no_orphan_negative_only_template(template_corpus):
    """Templates must have ≥1 positive matcher.

    A template with only negative / not_contains matchers can never produce
    a non-zero confidence — it would be silently dead in the scan output.
    """
    failures: list[str] = []
    for tid, t in template_corpus:
        if not _positive_matchers(t):
            failures.append(f"{tid} ({Path(t.source).name})")
    assert not failures, (
        "Templates with only refusal matchers (would always score 0):\n  "
        + "\n  ".join(failures)
    )
