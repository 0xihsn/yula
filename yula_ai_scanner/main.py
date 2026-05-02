"""
YULA AI Scanner CLI — main Typer application.

This module wires together all YULA AI Scanner components into a cohesive CLI.
It defines three commands:

  scan            Run a full security scan against a target
  validate-target Validate a target config and test connectivity
  init-config     Interactive wizard to create a scan.yaml

All attack payloads are loaded from the templates/ directory.
Each command is self-contained and handles its own error reporting.
"""

from __future__ import annotations

import asyncio
import difflib
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from yula_ai_scanner.banner import render_banner
from yula_ai_scanner.config.loader import ConfigurationError, load_scan_config, load_target_config
from yula_ai_scanner.config.scan_schema import ScanConfig, VisibilityLevel
from yula_ai_scanner.detection.aggregator import aggregate
from yula_ai_scanner.detection.analyzer import VulnerabilityAnalyzer
from yula_ai_scanner.engine.executor import TestExecutor
from yula_ai_scanner.logging_setup import setup_logging
from yula_ai_scanner.reporting.report import ReportBuilder
from yula_ai_scanner.reporting.severity import SeverityRating
from yula_ai_scanner.state.scan_state import (
    load_state,
    save_state,
    target_state_key,
)
from yula_ai_scanner.taxonomy.matrix_builder import MatrixBuilder
from yula_ai_scanner.taxonomy.template_loader import TemplateLoader
from yula_ai_scanner.taxonomy.template_models import AttackTemplate
from yula_ai_scanner.ui.panels import make_results_summary

# ─────────────────────────────────────────────────────────────────────────────
# Typer app setup
# ─────────────────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="yula-ai-scanner",
    help="YULA AI Scanner — adversarial AI security testing CLI",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers: load + filter templates
# ─────────────────────────────────────────────────────────────────────────────

def _load_templates(base_dir: Path) -> dict[str, AttackTemplate]:
    """Load all attack templates from templates/."""
    loader = TemplateLoader(base_dir / "templates")
    return loader.load_all()


def _template_folder(template: AttackTemplate, templates_root: Path) -> str | None:
    """Return the first directory segment under `templates/` for a template."""
    if not template.source:
        return None
    try:
        rel = Path(template.source).resolve().relative_to(templates_root.resolve())
    except (ValueError, OSError):
        return None
    parts = rel.parts
    return parts[0] if len(parts) >= 2 else None


def _filter_templates(
    templates: dict[str, AttackTemplate],
    *,
    template_id: str | None,
    folder: str | None,
    tags: list[str] | None,
    templates_root: Path,
) -> dict[str, AttackTemplate]:
    """Apply --template / --folder / --tags filters with AND semantics."""
    selected = templates

    if template_id:
        if template_id in selected:
            selected = {template_id: selected[template_id]}
        else:
            close = difflib.get_close_matches(
                template_id, list(selected.keys()), n=5, cutoff=0.4
            )
            hint = f"\n  Closest matches: {', '.join(close)}" if close else ""
            console.print(
                f"[bold red]Template '{template_id}' not found.[/bold red]{hint}"
            )
            raise typer.Exit(1)

    if folder:
        valid_folders: set[str] = set()
        filtered: dict[str, AttackTemplate] = {}
        for tid, tpl in selected.items():
            f = _template_folder(tpl, templates_root)
            if f:
                valid_folders.add(f)
                if f == folder:
                    filtered[tid] = tpl
        if not filtered:
            available = ", ".join(sorted(valid_folders)) or "(none)"
            console.print(
                f"[bold red]No templates in folder '{folder}'.[/bold red]\n"
                f"  Available folders: {available}"
            )
            raise typer.Exit(1)
        selected = filtered

    if tags:
        wanted = {t.strip().lower() for t in tags if t.strip()}
        filtered = {
            tid: tpl for tid, tpl in selected.items()
            if wanted.issubset({t.lower() for t in tpl.info.tags})
        }
        if not filtered:
            console.print(
                f"[bold red]No templates match tags:[/bold red] {', '.join(sorted(wanted))}"
            )
            raise typer.Exit(1)
        selected = filtered

    return selected


# ─────────────────────────────────────────────────────────────────────────────
# Command: scan
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: Path = typer.Option(
        ...,
        "--target", "-t",
        help="Path to the target YAML file (e.g. config/targets/openai_target.yaml)",
        exists=True,
    ),
    config: Path = typer.Option(
        Path("config/scan.yaml"),
        "--config", "-c",
        help="Path to the scan configuration YAML file",
    ),
    template: Optional[str] = typer.Option(
        None,
        "--template", "-T",
        help="Run only the template with this exact id (e.g. jailbreak-dan-mode)",
    ),
    folder: Optional[str] = typer.Option(
        None,
        "--folder", "-F",
        help="Run only templates under templates/<folder>/ (e.g. jailbreak)",
    ),
    tags: Optional[str] = typer.Option(
        None,
        "--tags",
        help="Comma-separated tags. Templates must have ALL listed tags.",
    ),
    threshold: Optional[float] = typer.Option(
        None,
        "--threshold",
        min=0.1,
        max=0.95,
        help="Override vulnerability_threshold from scan.yaml (range 0.1–0.95)",
    ),
    continue_: bool = typer.Option(
        False,
        "--continue",
        help=(
            "Resume from prior runs against this target. Skips templates "
            "already tested cleanly; runs only new and previously-errored "
            "templates."
        ),
    ),
    verbose: int = typer.Option(
        0,
        "--verbose", "-v",
        count=True,
        help=(
            "Verbosity (repeat). Any -v or higher additionally prints the HTTP "
            "request/response to the terminal for VULNERABLE findings only "
            "(safe templates stay terminal-quiet). The log file always captures "
            "every exchange regardless of verbosity. "
            "-v: only vulnerable / above-safe findings + HTTP request/response. "
            "-vv: every tested template (safe and vulnerable) + HTTP request/response for vulnerable ones. "
            "-vvv: above + full sent prompt, full model response, and evaluation details. "
            "-vvvv: print EVERY HTTP request and response to the terminal as it happens, "
            "including failed/timeout requests (the request that was attempted is shown)."
        ),
    ),
    visibility: Optional[str] = typer.Option(
        None,
        "--visibility",
        help="Override visibility level explicitly: public | internal | confidential | debug",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Override report output path",
    ),
    max_payloads: Optional[int] = typer.Option(
        None,
        "--max-payloads",
        help="Override max_payloads cap from scan.yaml",
    ),
) -> None:
    """Run a security scan against an AI endpoint.

    Loads attack templates from templates/ (optionally filtered by --template,
    --folder, --tags), builds the payload list, runs all attacks against the
    target, and generates a Markdown security report with per-template
    verdicts.

    With no selectors the entire template tree runs (default behaviour).
    Multiple selectors combine with AND.
    """
    render_banner(console)

    base_dir = Path(__file__).parent.parent  # project root

    # ── Load configuration ────────────────────────────────────────────────────
    try:
        scan_config = load_scan_config(config)
        target_config = load_target_config(target)
    except ConfigurationError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    # Apply CLI overrides
    if verbose > 0:
        verbosity_map = {
            1: VisibilityLevel.PUBLIC,
            2: VisibilityLevel.INTERNAL,
        }
        scan_config.scan.visibility = verbosity_map.get(verbose, VisibilityLevel.DEBUG)

    if visibility:
        try:
            scan_config.scan.visibility = VisibilityLevel(visibility.lower())
        except ValueError:
            console.print(
                f"[bold red]Invalid visibility level:[/bold red] '{visibility}'. "
                "Must be: public | internal | confidential | debug"
            )
            raise typer.Exit(1)

    if max_payloads is not None:
        scan_config.scan.max_payloads = max_payloads

    if threshold is not None:
        scan_config.scan.vulnerability_threshold = threshold

    if output:
        scan_config.output.report_path = str(output)

    # ── Validate output directory is writable (fail fast before any work) ─────
    report_path = base_dir / scan_config.output.report_path
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(
            f"[bold red]Cannot create output directory:[/bold red] "
            f"{report_path.parent} ({exc})"
        )
        raise typer.Exit(1) from exc

    if not os.access(report_path.parent, os.W_OK):
        console.print(
            f"[bold red]Output directory is not writable:[/bold red] {report_path.parent}"
        )
        raise typer.Exit(1)

    # ── Set up logging ────────────────────────────────────────────────────────
    setup_logging(
        level=scan_config.output.log_level,
        log_file=scan_config.output.log_file,
        console=console,
    )

    from yula_ai_scanner.engine import http_log
    http_log.configure(
        console=console,
        print_to_terminal=verbose > 0,
        print_all_exchanges=verbose >= 4,
    )

    # ── Load templates ────────────────────────────────────────────────────────
    templates = _load_templates(base_dir)

    if not templates:
        console.print(
            "[bold red]No attack templates found in templates/.[/bold red]\n"
            "Add .yaml template files to templates/ to run a scan."
        )
        raise typer.Exit(1)

    total_templates = len(templates)
    templates_root = base_dir / "templates"
    parsed_tags = (
        [t for t in tags.split(",")] if tags else None
    )
    templates = _filter_templates(
        templates,
        template_id=template,
        folder=folder,
        tags=parsed_tags,
        templates_root=templates_root,
    )

    if len(templates) == total_templates:
        console.print(
            f"[cyan]Templates:[/cyan] [green]✓[/green] {total_templates} attack templates loaded"
        )
    else:
        console.print(
            f"[cyan]Templates:[/cyan] [green]✓[/green] {len(templates)} of "
            f"{total_templates} selected"
        )

    # ── Continue mode: subtract templates already tested cleanly ─────────────
    target_url_for_state = getattr(target_config.endpoint, "url", str(target))
    state_dir = base_dir / "output" / "state"
    state_key = target_state_key(target, target_url_for_state)
    scan_state = load_state(state_dir, state_key, target_url_for_state)

    if continue_:
        already = scan_state.completed_template_ids
        if not scan_state.scans:
            console.print(
                "[yellow]--continue:[/yellow] no prior scan state for this target — "
                "running all selected templates."
            )
        else:
            kept = {tid: tpl for tid, tpl in templates.items() if tid not in already}
            skipped = len(templates) - len(kept)
            templates = kept
            console.print(
                f"[cyan]--continue:[/cyan] skipping [yellow]{skipped}[/yellow] "
                f"already-tested templates from [yellow]{len(scan_state.scans)}[/yellow] "
                f"prior scan(s); [green]{len(templates)}[/green] remaining."
            )
            if not templates:
                console.print(
                    "[green]Nothing to do.[/green] All selected templates have already "
                    "been tested against this target. Drop --continue to re-run them."
                )
                raise typer.Exit(0)

    # ── Build attack payloads ─────────────────────────────────────────────────
    console.print("[cyan]Building attack payloads...[/cyan]", end=" ")
    builder = MatrixBuilder()
    payloads = builder.build_from_templates(templates, scan_config.scan.max_payloads)
    console.print(f"[green]✓[/green] {len(payloads):,} payloads ready")

    # ── Run scan ──────────────────────────────────────────────────────────────
    analyzer = VulnerabilityAnalyzer(
        templates=templates,
        threshold=scan_config.scan.vulnerability_threshold,
        signals_blend=scan_config.scan.signals_blend,
    )
    executor = TestExecutor(scan_config, target_config, analyzer)

    target_url = getattr(target_config.endpoint, "url", "unknown")
    auth_type = target_config.auth.type.value

    console.print(f"\n[bold cyan]Starting scan[/bold cyan] → {target_url}\n")

    start_time = time.monotonic()

    with ScanProgress(
        total=len(payloads),
        visibility=scan_config.scan.visibility,
        target_url=target_url,
        auth_type=auth_type,
        template_count=len(templates),
        console=console,
    ) as progress:
        results = asyncio.run(executor.run_all(payloads, progress))

    duration = time.monotonic() - start_time

    # ── Aggregate per-template verdicts ───────────────────────────────────────
    severities = {tid: tpl.info.severity for tid, tpl in templates.items()}
    verdicts = aggregate(results, severities=severities)

    # ── Persist scan state (used by --continue on later runs) ────────────────
    scan_state.add_scan(scan_id=str(uuid.uuid4()), results=results)
    state_path = save_state(scan_state, state_dir)
    console.print(f"[dim]State:[/dim] {state_path.relative_to(base_dir)}")

    # ── Build report ──────────────────────────────────────────────────────────
    console.print("\n[cyan]Generating report...[/cyan]", end=" ")

    intents = sorted({t.attack.intent for t in templates.values()})
    techniques = sorted({t.attack.technique for t in templates.values() if t.attack.technique})
    evasions = sorted({t.attack.evasion for t in templates.values() if t.attack.evasion})

    report_builder = ReportBuilder()
    rendered = report_builder.build(
        results=results,
        target_url=target_url,
        target_type=target_config.type,
        auth_type=auth_type,
        visibility=scan_config.scan.visibility,
        duration_seconds=duration,
        intents=intents,
        techniques=techniques,
        evasions=evasions,
        verdicts=verdicts,
    )
    report_builder.save(rendered, base_dir / scan_config.output.report_path)
    console.print(f"[green]✓[/green] {scan_config.output.report_path}")

    json_report_path = Path(scan_config.output.report_path).with_suffix(".json")
    json_data = report_builder.build_json(
        results=results,
        target_url=target_url,
        target_type=target_config.type,
        auth_type=auth_type,
        visibility=scan_config.scan.visibility,
        duration_seconds=duration,
        intents=intents,
        techniques=techniques,
        evasions=evasions,
        verdicts=verdicts,
    )
    report_builder.save_json(json_data, base_dir / json_report_path)
    console.print(f"[green]✓[/green] {json_report_path}")

    # ── Final summary ──────────────────────────────────────────────────────────
    severity_counts = {s.value: 0 for s in SeverityRating}
    for r in results:
        if r.status == "vulnerable":
            from yula_ai_scanner.reporting.severity import compute_severity
            sev = compute_severity(r)
            severity_counts[sev.value] = severity_counts.get(sev.value, 0) + 1
        elif r.status == "safe":
            severity_counts["SAFE"] = severity_counts.get("SAFE", 0) + 1

    vuln_templates = [v for v in verdicts if v.status == "vulnerable"]
    console.print()
    if verdicts:
        console.print(
            f"[cyan]Templates:[/cyan] {len(vuln_templates)} vulnerable / "
            f"{len(verdicts)} tested"
        )
    console.print(make_results_summary(
        severity_counts=severity_counts,
        total=len(results),
        duration=duration,
        report_path=scan_config.output.report_path,
    ))

    # Exit non-zero if any verdict is vulnerable at critical/high severity.
    high_or_crit = any(
        v.status == "vulnerable" and v.severity in ("critical", "high")
        for v in verdicts
    )
    if high_or_crit:
        raise typer.Exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Command: validate-target
# ─────────────────────────────────────────────────────────────────────────────

@app.command("validate-target")
def validate_target(
    target: Path = typer.Argument(
        ...,
        help="Path to the target YAML file to validate",
        exists=True,
    ),
) -> None:
    """Validate a target YAML file and test basic connectivity.

    Checks that:
    - The YAML file is valid and passes Pydantic validation
    - Required fields are present
    - The endpoint URL is reachable (for API targets)
    """
    render_banner(console)

    try:
        target_config = load_target_config(target)
        console.print(f"[green]✓[/green] Config file valid: {target}")
        console.print(f"  Type:      {target_config.type}")
        console.print(f"  URL:       {getattr(target_config.endpoint, 'url', 'N/A')}")
        console.print(f"  Auth type: {target_config.auth.type.value}")
    except Exception as exc:
        console.print(f"[bold red]✗ Validation failed:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    # Try a simple connectivity check for API targets
    if target_config.type in ("openai", "anthropic", "custom_api"):
        import httpx
        url = target_config.endpoint.url  # type: ignore[union-attr]
        console.print(f"\n[cyan]Testing connectivity to {url}...[/cyan]", end=" ")
        try:
            with httpx.Client(
                timeout=5,
                verify=True,
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            ) as client:
                resp = client.get(url.rsplit("/", 1)[0] or url)
                console.print(f"[green]✓[/green] HTTP {resp.status_code} received")
        except httpx.ConnectError:
            console.print("[yellow]⚠[/yellow] Connection refused — is the server running?")
        except httpx.TimeoutException:
            console.print("[yellow]⚠[/yellow] Connection timed out")
        except httpx.RequestError as exc:
            console.print(f"[yellow]⚠[/yellow] Network error: {exc}")
        except Exception as exc:
            console.print(f"[dim](connectivity check skipped: {exc})[/dim]")

    console.print("\n[green]Target configuration is valid.[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# Command: init-config
# ─────────────────────────────────────────────────────────────────────────────

@app.command("init-config")
def init_config(
    output: Path = typer.Option(
        Path("config/scan.yaml"),
        "--output", "-o",
        help="Path to write the generated scan.yaml",
    ),
) -> None:
    """Copy the default scan.yaml to a new location.

    The generated file uses sensible defaults with inline documentation.
    """
    render_banner(console)
    console.print("[bold cyan]scan.yaml Configuration Wizard[/bold cyan]\n")
    console.print(
        "A default scan.yaml is already at config/scan.yaml.\n"
        "Copy and edit it for custom configurations.\n\n"
        f"Writing default config to: [cyan]{output}[/cyan]"
    )

    default = Path(__file__).parent.parent / "config" / "scan.yaml"
    if default.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(default.read_text(encoding="utf-8"), encoding="utf-8")
        console.print("[green]✓ Done.[/green]")
    else:
        console.print("[yellow]Default scan.yaml not found. Run from the project root directory.[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# Deferred import to avoid circular dependency at module level
# ─────────────────────────────────────────────────────────────────────────────

from yula_ai_scanner.ui.progress import ScanProgress  # noqa: E402
