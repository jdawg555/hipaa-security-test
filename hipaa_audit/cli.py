from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hipaa_audit import __version__
from hipaa_audit.controls import PACKAGE_ROOT, load_config, load_controls
from hipaa_audit.engine import run_audit
from hipaa_audit.report import write_reports
from hipaa_audit.sra_import import load_sra_json, write_import_artifacts

app = typer.Typer(
    name="hipaa-audit",
    help="Free open-source HIPAA Security Rule compliance auditor.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(Path.cwd(), help="Repository or project root to audit"),
    config: Path = typer.Option(
        Path("hipaa-audit.yaml"),
        "--config",
        "-c",
        help="Audit configuration file",
    ),
    output: Path = typer.Option(
        Path("evidence/latest"),
        "--output",
        "-o",
        help="Directory for reports and evidence artifacts",
    ),
    controls: Path | None = typer.Option(
        None,
        "--controls",
        help="Custom controls YAML (default: bundled HIPAA catalog)",
    ),
    category: list[str] = typer.Option(
        None,
        "--category",
        help="Filter by category (administrative, physical, technical)",
    ),
) -> None:
    """Run automated + manual HIPAA control checks and generate evidence."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    cfg.setdefault("org_name", path.name)

    console.print(f"[bold]HIPAA Audit[/bold] v{__version__} — scanning {path}")
    report = run_audit(
        path,
        config=cfg,
        controls_path=controls,
        evidence_dir=output,
        categories=category,
    )

    paths = write_reports(report, output)
    _print_summary(report)

    console.print("\n[green]Reports written:[/green]")
    for kind, p in paths.items():
        console.print(f"  {kind}: {p}")
    console.print(f"\nOpen dashboard: [link=file://{paths['html'].resolve()}]{paths['html']}[/link]")


@app.command()
def init(
    path: Path = typer.Argument(Path.cwd(), help="Target directory"),
) -> None:
    """Bootstrap a repo with policy templates, config, and CI workflow."""
    import shutil

    src = PACKAGE_ROOT
    targets = [
        (src / "policies", path / "policies"),
        (src / "templates", path / "templates"),
        (src / "scripts" / "collect-external-evidence.sh", path / "scripts" / "collect-external-evidence.sh"),
        (src / "hipaa-audit.example.yaml", path / "hipaa-audit.yaml"),
        (src / ".github" / "workflows" / "compliance-audit.yml", path / ".github" / "workflows" / "compliance-audit.yml"),
    ]
    for s, d in targets:
        if not s.exists():
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_dir():
            if d.exists():
                console.print(f"[yellow]skip[/yellow] {d} (exists)")
            else:
                shutil.copytree(s, d)
                console.print(f"[green]copied[/green] {d}")
        else:
            shutil.copy2(s, d)
            console.print(f"[green]created[/green] {d}")
    (path / "evidence").mkdir(exist_ok=True)
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  1. Edit hipaa-audit.yaml with your org name")
    console.print("  2. Customize policies/ and complete templates/sra-template.md")
    console.print("  3. Optional: bash scripts/collect-external-evidence.sh .")
    console.print("  4. Run: hipaa-audit scan")


@app.command()
def controls(
    controls_path: Path = typer.Option(
        PACKAGE_ROOT / "controls" / "hipaa-security-rule.yaml",
        "--file",
        "-f",
    ),
) -> None:
    """List all controls in the catalog."""
    table = Table(title="HIPAA Control Catalog")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Citation")
    for c in load_controls(controls_path):
        table.add_row(c.id, c.title[:50], c.category, c.citation)
    console.print(table)


@app.command("import-sra")
def import_sra(
    json_file: Path = typer.Argument(..., help="Browser SRA export (.json)"),
    path: Path = typer.Argument(Path.cwd(), help="Project root"),
    output: Path = typer.Option(
        Path("templates/sra-imported.md"),
        "--output",
        "-o",
        help="Merged SRA Markdown output",
    ),
    template: Path = typer.Option(
        Path("templates/sra-template.md"),
        "--template",
        "-t",
        help="Base SRA template to prepend (if present)",
    ),
    evidence: Path = typer.Option(
        Path("evidence/sra"),
        "--evidence",
        help="Directory for import summary JSON",
    ),
) -> None:
    """Import l0lsec/hipaa-sra or SaberGuard browser JSON into Markdown SRA."""
    data = load_sra_json(json_file)
    base = template if template.exists() else PACKAGE_ROOT / "templates" / "sra-template.md"
    base = base if base.exists() else None
    out_path = path / output if not output.is_absolute() else output
    ev_dir = path / evidence if not evidence.is_absolute() else evidence
    paths = write_import_artifacts(
        data,
        output_md=out_path,
        evidence_dir=ev_dir,
        base_template=base,
    )
    console.print(f"[green]Imported SRA[/green] → {paths['markdown']}")
    console.print(f"[green]Summary[/green] → {paths['summary']}")
    console.print("Next: review gaps in section 6, complete sign-off, run hipaa-audit scan")


@app.command()
def sources() -> None:
    """List curated open-source tools for HIPAA evidence (see docs/oss-ecosystem.md)."""
    import yaml

    catalog_path = PACKAGE_ROOT / "integrations" / "oss-catalog.yaml"
    if not catalog_path.exists():
        console.print("[red]oss-catalog.yaml not found[/red]")
        raise typer.Exit(1)
    raw = yaml.safe_load(catalog_path.read_text())
    table = Table(title="OSS HIPAA Compliance Ecosystem")
    table.add_column("ID")
    table.add_column("Tool")
    table.add_column("License")
    table.add_column("Integrated")
    table.add_column("Role")
    for item in raw.get("sources", []):
        integrated = "[green]yes[/green]" if item.get("integrated") else "ref"
        table.add_row(
            item.get("id", ""),
            item.get("name", ""),
            item.get("license", ""),
            integrated,
            (item.get("role", "") or "")[:45],
        )
    console.print(table)
    console.print("\nDetails: [link]docs/oss-ecosystem.md[/link]")


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"hipaa-audit {__version__}")


def _print_summary(report) -> None:
    table = Table(title="Audit Summary")
    table.add_column("Status", style="bold")
    table.add_column("Count")
    for status, count in report.summary.items():
        if count:
            style = {"pass": "green", "fail": "red", "warn": "yellow"}.get(status, "")
            table.add_row(status, str(count), style=style)
    console.print(table)

    fails = [cr for cr in report.controls if cr.status.value in ("fail", "error")]
    if fails:
        console.print("\n[red bold]Failed controls:[/red bold]")
        for cr in fails[:10]:
            console.print(f"  • {cr.control.id}: {cr.results[0].message}")


if __name__ == "__main__":
    app()
