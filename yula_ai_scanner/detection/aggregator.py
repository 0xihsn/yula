"""
Template-level OR aggregation of test results.

Each AttackPayload is tested individually and produces one TestResult. For
parallel-mode templates this means N TestResult rows per template (one per
variant). Consumers usually want a per-template verdict — "did this template
catch a vulnerability at all?" — rather than scrolling through every variant.

`aggregate()` rolls up all TestResults sharing a template_id into one
TemplateVerdict. Verdict status is OR-aggregated:
  - vulnerable if ANY child variant was vulnerable
  - error if ALL children errored or timed out
  - safe otherwise

The strongest vulnerable child is recorded as the proof so reports can link
straight to the evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

if TYPE_CHECKING:
    from yula_ai_scanner.engine.executor import TestResult


class TemplateVerdict(BaseModel):
    """One per-template aggregated verdict.

    Attributes:
        template_id: Source template id (`AttackPayload.template_id`).
        template_name: Display name.
        intent_id: Intent under test.
        intent_title: Display name of the intent.
        severity: Worst-case severity from any vulnerable child.
        status: vulnerable | safe | error.
        best_confidence: Maximum confidence across all children.
        mean_confidence: Average confidence across non-error children.
        payload_count: Total number of children (variants for parallel mode,
                       or 1 for sequential mode).
        vulnerable_count: Count of children with status == "vulnerable".
        proof_result_index: Index into the original TestResult list of the
                            strongest vulnerable child (None when none vuln).
        child_result_indices: All child indices in their original order.
    """

    template_id: str
    template_name: str
    intent_id: str
    intent_title: str
    severity: str = "info"
    status: Literal["vulnerable", "safe", "error"] = "safe"
    best_confidence: float = 0.0
    mean_confidence: float = 0.0
    payload_count: int = 0
    vulnerable_count: int = 0
    proof_result_index: int | None = None
    child_result_indices: list[int] = []


def aggregate(
    results: "list[TestResult]",
    severities: dict[str, str] | None = None,
) -> list[TemplateVerdict]:
    """Roll up TestResults into per-template TemplateVerdicts.

    Args:
        results: Full list of TestResult objects from the executor.
        severities: Optional template_id → severity string map (e.g. from
                    loaded AttackTemplate.info.severity).

    Returns:
        One TemplateVerdict per distinct template_id. Results without a
        template_id are skipped.
    """
    severities = severities or {}
    groups: dict[str, list[tuple[int, "TestResult"]]] = {}
    for idx, result in enumerate(results):
        tid = result.payload.template_id
        if not tid:
            continue
        groups.setdefault(tid, []).append((idx, result))

    verdicts: list[TemplateVerdict] = []
    for tid, items in groups.items():
        first_payload = items[0][1].payload
        vuln_indices = [(i, r) for i, r in items if r.status == "vulnerable"]
        err_indices = [(i, r) for i, r in items if r.status in ("error", "timeout")]

        if vuln_indices:
            status: Literal["vulnerable", "safe", "error"] = "vulnerable"
            best_idx, best_result = max(
                vuln_indices, key=lambda pair: pair[1].confidence
            )
            proof_idx: int | None = best_idx
            best_conf = best_result.confidence
        elif err_indices and len(err_indices) == len(items):
            status = "error"
            proof_idx = None
            best_conf = 0.0
        else:
            status = "safe"
            proof_idx = None
            best_conf = max((r.confidence for _, r in items), default=0.0)

        non_err = [r for _, r in items if r.status not in ("error", "timeout")]
        mean_conf = (
            sum(r.confidence for r in non_err) / len(non_err) if non_err else 0.0
        )

        verdicts.append(TemplateVerdict(
            template_id=tid,
            template_name=first_payload.template_name or tid,
            intent_id=first_payload.intent_id,
            intent_title=first_payload.intent_title,
            severity=severities.get(tid, "info"),
            status=status,
            best_confidence=best_conf,
            mean_confidence=mean_conf,
            payload_count=len(items),
            vulnerable_count=len(vuln_indices),
            proof_result_index=proof_idx,
            child_result_indices=[i for i, _ in items],
        ))

    # Sort: vulnerable first, then by confidence descending.
    status_order = {"vulnerable": 0, "safe": 1, "error": 2}
    verdicts.sort(
        key=lambda v: (status_order.get(v.status, 3), -v.best_confidence)
    )
    return verdicts
