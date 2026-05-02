"""
Loader for attack template YAML files.

Scans the templates/ directory tree for *.yaml files and loads
each into an AttackTemplate model. Each template defines its own payloads
and matchers, enabling precise per-attack detection logic.

Directory convention:
    templates/
    ├── jailbreak/
    │   ├── dan_mode.yaml
    │   └── developer_mode.yaml
    ├── system_prompt_leak/
    │   └── direct_extraction.yaml
    └── ...

The template id field must be unique across all loaded templates. If two
templates share an id, the second one wins (with a warning logged).
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from yula_ai_scanner.taxonomy.template_models import (
    AttackTemplate,
    AttackTemplateAttack,
    AttackTemplateInfo,
    TemplateMatcher,
    TemplateMode,
)

logger = logging.getLogger("yula_ai_scanner.templates")


class TemplateLoader:
    """Loads all attack template YAML files from a directory tree."""

    def __init__(self, templates_dir: Path) -> None:
        self.templates_dir = templates_dir

    def load_all(self) -> dict[str, AttackTemplate]:
        templates: dict[str, AttackTemplate] = {}

        if not self.templates_dir.exists():
            logger.debug("Templates directory not found: %s", self.templates_dir)
            return templates

        for yaml_path in sorted(self.templates_dir.rglob("*.yaml")):
            try:
                template = self._load_one(yaml_path)
                if template.id in templates:
                    logger.warning(
                        "Duplicate template id '%s' in %s — overwriting previous",
                        template.id,
                        yaml_path,
                    )
                templates[template.id] = template
                logger.debug("Loaded template: %s (%s)", template.id, yaml_path.name)
            except Exception as exc:
                logger.warning("Skipping %s — %s", yaml_path, exc)

        logger.info("Loaded %d templates from %s", len(templates), self.templates_dir)
        return templates

    def _load_one(self, yaml_path: Path) -> AttackTemplate:
        raw = yaml_path.read_text(encoding="utf-8")
        data: dict = yaml.safe_load(raw)

        if not isinstance(data, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

        template_id = data.get("id")
        if not template_id:
            raise ValueError("Template missing required field: 'id'")

        info_data = data.get("info", {})
        info = AttackTemplateInfo(
            name=info_data.get("name", template_id),
            severity=info_data.get("severity", "medium"),
            description=info_data.get("description", ""),
            tags=info_data.get("tags", []),
            author=info_data.get("author", "Ihsan Bilkay (0xIHSN)"),
            source=info_data.get("source"),
            source_url=info_data.get("source_url"),
            source_license=info_data.get("source_license"),
            signals=bool(info_data.get("signals", True)),
            normalise=bool(info_data.get("normalise", True)),
            threshold_override=info_data.get("threshold_override"),
        )

        attack_data = data.get("attack", {})
        intent = attack_data.get("intent")
        if not intent:
            raise ValueError(f"Template '{template_id}' missing 'attack.intent'")
        attack = AttackTemplateAttack(
            intent=intent,
            technique=attack_data.get("technique"),
            evasion=attack_data.get("evasion"),
        )

        # Mode (parallel | sequential) — Pydantic enum rejects unknown values.
        mode = TemplateMode(data.get("mode", "parallel"))

        payloads: list[str] = []
        for item in data.get("payloads", []):
            if isinstance(item, str) and item.strip():
                payloads.append(item.strip())

        matchers: list[TemplateMatcher] = []
        for m_data in data.get("matchers", []):
            try:
                matchers.append(TemplateMatcher(**self._normalize_matcher(m_data)))
            except (ValidationError, TypeError, ValueError) as exc:
                logger.warning(
                    "Skipping invalid matcher in %s: %s", yaml_path.name, exc
                )

        matchers_condition = data.get("matchers-condition", "or")

        return AttackTemplate(
            id=template_id,
            info=info,
            attack=attack,
            mode=mode,
            payloads=payloads,
            matchers_condition=matchers_condition,
            matchers=matchers,
            source=str(yaml_path),
        )

    @staticmethod
    def _normalize_matcher(data: dict) -> dict:
        """Convert YAML matcher dict to TemplateMatcher constructor kwargs.

        Handles hyphenated keys ('case-insensitive', 'min-length', 'max-length',
        'min-clusters') and the new matcher types' fields.
        """
        return {
            "type": data.get("type", "word"),
            "words": data.get("words", []),
            "regex": data.get("regex", []),
            "condition": data.get("condition", "or"),
            "case_insensitive": data.get("case-insensitive", data.get("case_insensitive", True)),
            "weight": data.get("weight", 0.45),
            "min_length": data.get("min-length", data.get("min_length")),
            "max_length": data.get("max-length", data.get("max_length")),
            "clusters": data.get("clusters", []),
            "min_clusters": data.get("min-clusters", data.get("min_clusters", 2)),
        }
