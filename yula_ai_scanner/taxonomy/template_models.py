"""
Pydantic models for attack template YAMLs.

Each attack template is a self-contained YAML file that defines:
  - The attack payloads to send to the target AI
  - Matchers to detect whether the attack succeeded
  - Metadata (id, severity, tags, description)
  - Execution mode (parallel = independent variants, sequential = ordered turns)

Template matchers give precise, attack-specific detection — much more
accurate than applying global regex patterns across all response types.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class TemplateMode(str, Enum):
    """How the template's payload list should be executed.

    PARALLEL: each list item is an INDEPENDENT variant of the attack. Each is
              dispatched as its own fresh request. The template is judged
              vulnerable if ANY variant elicits a vulnerable response.

    SEQUENTIAL: the list items are ordered turns of the SAME conversation.
                Sent turn-by-turn with full message history; analyzed against
                the joined transcript and per-turn.
    """

    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"


class MatcherType(str, Enum):
    """Type of matcher used to detect attack success."""
    WORD = "word"                # plain substring / keyword search
    REGEX = "regex"              # compiled regular expression
    NEGATIVE = "negative"        # words/regex that REDUCE confidence (refusal indicators)
    LENGTH = "length"            # response length within [min_length, max_length]
    NOT_CONTAINS = "not_contains"  # response must NOT contain any of `words`
    SEMANTIC_KEYWORDS = "semantic_keywords"  # at least N distinct keyword clusters present


class TemplateMatcher(BaseModel):
    """One matcher block inside an attack template.

    Attributes:
        type: Detection method.
        words: Plain-text strings (word, negative, not_contains).
        regex: Regular expressions (regex, negative).
        condition: How multiple words/patterns within this matcher are combined.
        case_insensitive: Whether matching ignores case.
        weight: Confidence contribution when this matcher fires.
        min_length / max_length: Bounds for the `length` matcher.
        clusters: List of keyword clusters for `semantic_keywords`.
        min_clusters: Minimum distinct clusters required to fire.
    """

    type: MatcherType
    words: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    condition: Literal["and", "or"] = "or"
    case_insensitive: bool = True
    weight: float = 0.45
    min_length: int | None = None
    max_length: int | None = None
    clusters: list[list[str]] = Field(default_factory=list)
    min_clusters: int = 2

    @field_validator("regex", mode="before")
    @classmethod
    def validate_regex(cls, patterns: list[str]) -> list[str]:
        """Compile-check all regex patterns at load time, not at match time."""
        for pattern in patterns:
            re.compile(pattern)
        return patterns


class AttackTemplateInfo(BaseModel):
    """Metadata block in the attack template."""

    name: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    author: str = "Ihsan Bilkay (0xIHSN)"
    # Optional upstream-attribution fields. Templates derived from a third-party
    # taxonomy (e.g. the Arc PI Taxonomy by Jason Haddix / Arcanum Information
    # Security, CC-BY-4.0) record the provenance here so the license obligation
    # is satisfied per-file. See ATTRIBUTION.md for the canonical credit.
    source: str | None = None
    source_url: str | None = None
    source_license: str | None = None
    # Composite analysis tuning:
    signals: bool = True             # if False, skip the global signal bank for this template
    normalise: bool = True           # collapse whitespace/code fences before matching
    threshold_override: float | None = None  # template-specific vulnerability threshold


class AttackTemplateAttack(BaseModel):
    """Attack dimension selectors in the template."""

    intent: str
    technique: str | None = None
    evasion: str | None = None


class AttackTemplate(BaseModel):
    """A single attack template loaded from a YAML file.

    Attributes:
        id: Unique slug.
        info: Metadata about this template.
        attack: Attack dimension selectors (intent, technique, evasion).
        mode: parallel (default — independent variants) or sequential (chain).
        payloads: List of prompt strings to send to the target.
        matchers_condition: How to combine matchers ("and" | "or").
        matchers: Ordered list of TemplateMatcher objects.
        source: Path to the YAML file this was loaded from.
    """

    id: str
    info: AttackTemplateInfo
    attack: AttackTemplateAttack
    mode: TemplateMode = TemplateMode.PARALLEL
    payloads: list[str] = Field(default_factory=list)
    matchers_condition: Literal["and", "or"] = "or"
    matchers: list[TemplateMatcher] = Field(default_factory=list)
    source: str = ""

    def match(self, response: str) -> tuple[float, list[str]]:
        """Apply this template's matchers to an AI response.

        Returns:
            (confidence in [0,1], list of human-readable fired-matcher labels).
        """
        if not response or not response.strip():
            return 0.0, []

        normalised = _normalise(response) if self.info.normalise else response

        positive_results: list[bool] = []
        positive_weights_total: float = 0.0
        positive_weights_fired: float = 0.0
        fired: list[str] = []
        negative_score: float = 0.0
        not_contains_violation = False

        for matcher in self.matchers:
            hits = self._apply_matcher(matcher, normalised, response)

            if matcher.type == MatcherType.NEGATIVE:
                if hits:
                    negative_score -= abs(matcher.weight)
                    fired.append(f"[-] negative:{','.join(hits[:2])}")
            elif matcher.type == MatcherType.NOT_CONTAINS:
                # NOT_CONTAINS: presence == failure of the requirement.
                # If `condition: and` (default for not_contains semantics) we treat
                # the requirement as a hard veto (zero confidence).
                if hits:
                    not_contains_violation = True
                    fired.append(f"[!] not_contains:{','.join(hits[:2])}")
            else:
                positive_weights_total += matcher.weight
                positive_results.append(bool(hits))
                if hits:
                    positive_weights_fired += matcher.weight
                    label = matcher.type.value
                    fired.extend(f"[+] {label}:{h}" for h in hits[:2])

        # Combine positive matcher results — weighted evidence model.
        if not positive_results:
            positive_confidence = 0.0
        elif self.matchers_condition == "and":
            # All must fire; otherwise contribute proportionally a small amount.
            if all(positive_results):
                positive_confidence = (
                    positive_weights_fired / positive_weights_total
                    if positive_weights_total > 0 else 0.75
                )
            else:
                positive_confidence = (
                    0.15 * (sum(positive_results) / len(positive_results))
                )
        else:
            # OR: weighted share of fired evidence; capped at 1.0.
            if positive_weights_total > 0:
                positive_confidence = positive_weights_fired / positive_weights_total
            else:
                fire_count = sum(positive_results)
                positive_confidence = min(0.8, fire_count * 0.35)

        confidence = max(0.0, min(1.0, positive_confidence + negative_score))
        if not_contains_violation:
            confidence = 0.0
        return confidence, fired

    def _apply_matcher(
        self,
        matcher: TemplateMatcher,
        normalised: str,
        original: str,
    ) -> list[str]:
        """Apply one matcher block and return list of matched strings."""
        if matcher.type == MatcherType.LENGTH:
            n = len(original.strip())
            lo = matcher.min_length if matcher.min_length is not None else 0
            hi = matcher.max_length if matcher.max_length is not None else 10**9
            if lo <= n <= hi:
                return [f"len={n} in [{lo},{hi}]"]
            return []

        if matcher.type == MatcherType.SEMANTIC_KEYWORDS:
            search_text = normalised.lower() if matcher.case_insensitive else normalised
            hit_clusters: list[str] = []
            for cluster in matcher.clusters:
                for kw in cluster:
                    needle = kw.lower() if matcher.case_insensitive else kw
                    if needle in search_text:
                        hit_clusters.append(kw)
                        break
            if len(hit_clusters) >= matcher.min_clusters:
                return hit_clusters[:3]
            return []

        flags = re.IGNORECASE if matcher.case_insensitive else 0
        search_text = normalised.lower() if matcher.case_insensitive else normalised
        hits: list[str] = []

        # Word-style matching (used by word, negative, not_contains).
        if matcher.words:
            for word in matcher.words:
                needle = word.lower() if matcher.case_insensitive else word
                if needle in search_text:
                    hits.append(word)
                    if matcher.condition == "or":
                        break

        # Regex matching (used by regex, negative).
        for pattern in matcher.regex:
            m = re.search(pattern, normalised, flags)
            if m:
                hits.append(m.group(0)[:60])
                if matcher.condition == "or":
                    break

        return hits


_CODE_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n?")
_WS_RE = re.compile(r"[ \t]+")


def _normalise(text: str) -> str:
    """Strip code fences and collapse whitespace runs.

    Cheap pre-processing so word/regex matchers don't miss hits hidden behind
    extra spacing or markdown decoration. Newlines are preserved so MULTILINE
    regexes still work.
    """
    cleaned = _CODE_FENCE_RE.sub("", text)
    cleaned = _WS_RE.sub(" ", cleaned)
    return cleaned.strip()
