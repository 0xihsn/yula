"""
Template-based attack payload builder.

Converts attack templates into AttackPayload objects ready for
the executor.

Two execution modes are supported (declared by `mode:` on the template):

  - parallel (default): each item in `payloads:` becomes its OWN AttackPayload.
    Each is dispatched as an independent fresh request. Template verdict is
    OR-aggregated downstream — any vulnerable variant marks the template
    vulnerable.

  - sequential: the entire `payloads:` list is collapsed into ONE AttackPayload
    whose `prompt` is turn 1 and whose `followup_prompts` are turns 2..N. The
    executor sends them as a chained conversation against the same target.
"""

from __future__ import annotations

import random

from yula_ai_scanner.taxonomy.models import AttackPayload
from yula_ai_scanner.taxonomy.template_models import AttackTemplate, TemplateMode


class MatrixBuilder:
    """Builds the attack payload list from loaded attack templates."""

    def build_from_templates(
        self,
        templates: dict[str, AttackTemplate],
        max_payloads: int | None = None,
    ) -> list[AttackPayload]:
        """Build AttackPayload objects from all loaded templates.

        Args:
            templates: Dict mapping template_id → AttackTemplate.
            max_payloads: Optional cap — samples uniformly if exceeded.
                          A sequential chain counts as ONE payload.

        Returns:
            List of AttackPayload objects ready for the executor.
        """
        payloads: list[AttackPayload] = []

        for template in templates.values():
            intent_title = template.attack.intent.replace("_", " ").title()
            technique_title = (
                template.attack.technique.replace("_", " ").title()
                if template.attack.technique else None
            )
            evasion_title = (
                template.attack.evasion.replace("_", " ").title()
                if template.attack.evasion else None
            )

            cleaned = [p for p in template.payloads if p and p.strip()]
            if not cleaned:
                continue

            if template.mode == TemplateMode.SEQUENTIAL:
                # One AttackPayload carrying the full ordered chain.
                transcript = "\n--- TURN ---\n".join(cleaned)
                payloads.append(AttackPayload(
                    prompt=cleaned[0],
                    intent_id=template.attack.intent,
                    intent_title=intent_title,
                    technique_id=template.attack.technique,
                    technique_title=technique_title,
                    evasion_id=template.attack.evasion,
                    evasion_title=evasion_title,
                    raw_example=transcript,
                    template_id=template.id,
                    template_name=template.info.name,
                    followup_prompts=cleaned[1:],
                    payload_index=1,
                    payload_total=1,
                ))
            else:
                total = len(cleaned)
                for idx, raw_prompt in enumerate(cleaned, start=1):
                    payloads.append(AttackPayload(
                        prompt=raw_prompt,
                        intent_id=template.attack.intent,
                        intent_title=intent_title,
                        technique_id=template.attack.technique,
                        technique_title=technique_title,
                        evasion_id=template.attack.evasion,
                        evasion_title=evasion_title,
                        raw_example=raw_prompt,
                        template_id=template.id,
                        template_name=template.info.name,
                        payload_index=idx,
                        payload_total=total,
                    ))

        if max_payloads is not None and len(payloads) > max_payloads:
            payloads = random.sample(payloads, max_payloads)

        return payloads
