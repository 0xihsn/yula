"""
Attack payload data model for YULA AI Scanner.

AttackPayload is the core data structure passed through the engine —
it carries the prompt and all lineage metadata so results can be
traced back to the source template.
"""

from __future__ import annotations

from pydantic import BaseModel


class AttackPayload(BaseModel):
    """One complete attack payload ready to send to a target.

    Attributes:
        prompt: The final text string to send to the AI system.
        intent_id: ID of the attack intent (e.g. "jailbreak").
        intent_title: Display name of the intent.
        technique_id: ID of the technique applied (or None).
        technique_title: Display name of the technique.
        evasion_id: ID of the evasion applied (or None).
        evasion_title: Display name of the evasion.
        raw_example: Original unmodified prompt string.
        is_probe: True for simple probe payloads.
        template_id: Template ID if generated from a YAML template.
        template_name: Template display name.
    """

    prompt: str
    intent_id: str
    intent_title: str
    technique_id: str | None = None
    technique_title: str | None = None
    evasion_id: str | None = None
    evasion_title: str | None = None
    raw_example: str = ""
    is_probe: bool = False
    template_id: str | None = None
    template_name: str | None = None
    # Sequential / multi-turn support: when non-empty, `prompt` is turn 1 and
    # these are turns 2..N of the same conversation.
    followup_prompts: list[str] = []
    # Index of this payload within its parent template (1-based for display).
    payload_index: int = 1
    # Total payloads emitted by the parent template (for "variant N of M" labels).
    payload_total: int = 1

    @property
    def is_sequential(self) -> bool:
        return bool(self.followup_prompts)

    @property
    def all_turns(self) -> list[str]:
        """Full ordered turn list including the first prompt."""
        return [self.prompt, *self.followup_prompts]

    @property
    def label(self) -> str:
        """Short human-readable label for UI display."""
        parts = [self.intent_title]
        if self.technique_title:
            parts.append(self.technique_title)
        if self.evasion_title:
            parts.append(self.evasion_title)
        return " + ".join(parts)
