"""
Per-target scan state used by `scan --continue`.

State is keyed off the target config filename's stem (e.g. `openai_target`)
and persisted under `output/state/<key>.state.json`. Each completed scan
appends an entry recording which templates finished cleanly (vulnerable or
safe) and which errored.

`--continue` filters out templates that have already finished cleanly in any
prior scan, leaving only newly added templates and the ones that errored last
time. Errored templates are deliberately retried because a timeout/connection
blip is not a real verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from yula_ai_scanner.engine.executor import TestResult


_SLUG_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


def target_state_key(target_path: Path, target_url: str) -> str:
    """Stable per-target identifier.

    Uses the target file's basename (without extension) plus a short hash of
    the target URL so two target files with the same name but different URLs
    don't collide.
    """
    stem = _SLUG_RE.sub("_", target_path.stem) or "target"
    digest = hashlib.sha1(target_url.encode("utf-8")).hexdigest()[:8]
    return f"{stem}_{digest}"


class ScanHistoryEntry(BaseModel):
    scan_id: str
    timestamp: datetime
    completed_template_ids: list[str] = Field(default_factory=list)
    errored_template_ids: list[str] = Field(default_factory=list)
    vulnerable_template_ids: list[str] = Field(default_factory=list)


class ScanState(BaseModel):
    target_key: str
    target_url: str
    scans: list[ScanHistoryEntry] = Field(default_factory=list)

    @property
    def completed_template_ids(self) -> set[str]:
        """Union of templates that finished cleanly in any prior scan.

        "Cleanly" = the template produced at least one non-error/non-timeout
        result. Errored templates are NOT counted, so --continue retries them.
        """
        s: set[str] = set()
        for entry in self.scans:
            s.update(entry.completed_template_ids)
        return s

    def add_scan(
        self,
        scan_id: str,
        results: "list[TestResult]",
    ) -> None:
        """Append a new scan record.

        A template is considered "completed" if it has at least one child
        result whose status is not error/timeout. It is also added to the
        errored set if at least one of its children errored.
        """
        completed: set[str] = set()
        errored: set[str] = set()
        vulnerable: set[str] = set()
        for r in results:
            tid = r.payload.template_id
            if not tid:
                continue
            if r.status in ("error", "timeout"):
                errored.add(tid)
            else:
                completed.add(tid)
            if r.status == "vulnerable":
                vulnerable.add(tid)

        self.scans.append(ScanHistoryEntry(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            completed_template_ids=sorted(completed),
            errored_template_ids=sorted(errored),
            vulnerable_template_ids=sorted(vulnerable),
        ))


def state_file_path(state_dir: Path, target_key: str) -> Path:
    """Path of the state file for a given target key."""
    return state_dir / f"{target_key}.state.json"


def load_state(state_dir: Path, target_key: str, target_url: str) -> ScanState:
    """Load the scan state for a target, or return a fresh empty one."""
    path = state_file_path(state_dir, target_key)
    if not path.exists():
        return ScanState(target_key=target_key, target_url=target_url)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ScanState.model_validate(data)
    except Exception:
        # Corrupt state file should not block scanning — start fresh.
        return ScanState(target_key=target_key, target_url=target_url)


def save_state(state: ScanState, state_dir: Path) -> Path:
    """Write the scan state to disk and return the path."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_file_path(state_dir, state.target_key)
    path.write_text(
        state.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return path
