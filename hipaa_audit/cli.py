from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hipaa_audit import __version__
from hipaa_audit.access_reviews import (
    complete_campaign,
    load_campaigns,
    record_decision,
    start_campaign,
)
from hipaa_audit.apps import (
    discover_google_apps,
    discover_okta_apps,
    google_config_from_identity,
    import_google_apps_csv,
    link_app,
    load_inventory,
    merge_discovered,
    okta_config_from_identity,
)
from hipaa_audit.devices import device_csv_template, import_devices_csv, load_devices
from hipaa_audit.auditor_portal import publish_auditor_portal
from hipaa_audit.frameworks import hitrust_report, iso27001_report, pci_report, soc2_report
from hipaa_audit.questionnaires import (
    find_questionnaire,
    import_response,
    load_questionnaires,
    respond_questionnaire,
    send_questionnaire,
)
from hipaa_audit.vendor_portal import publish_vendor_portal
from hipaa_audit.catalog import coverage_report
from hipaa_audit.controls import PACKAGE_ROOT, load_config, load_controls
from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.trust_center import publish_trust_center
from hipaa_audit.vendors import SIG_LITE_KEYS, add_vendor, load_vendors, review_vendor
from hipaa_audit.engine import run_audit
from hipaa_audit.notify import maybe_notify_slack
from hipaa_audit.personnel import import_training_template
from hipaa_audit.export_probo import write_probo_export
from hipaa_audit.posture import compute_posture, record_history
from hipaa_audit.report import write_reports
from hipaa_audit.sra_import import load_sra_json, write_import_artifacts
from hipaa_audit.tasks import complete_task, list_open_tasks, load_tasks, sync_from_report

app = typer.Typer(
    name="hipaa-audit",
    help="Free open-source HIPAA Security Rule compliance auditor.",
    no_args_is_help=True,
)
console = Console()
tasks_app = typer.Typer(help="Remediation task tracker (Drata-style).")
export_app = typer.Typer(help="Export audit evidence for GRC platforms.")
vendor_app = typer.Typer(help="Vendor risk register and SIG-lite questionnaires.")
access_review_app = typer.Typer(help="Quarterly access review campaigns.")
apps_app = typer.Typer(help="SaaS / IdP application inventory.")
trust_app = typer.Typer(help="Public trust center (compliance page).")
devices_app = typer.Typer(help="MDM endpoint inventory (Jamf, Intune).")
framework_app = typer.Typer(help="Multi-framework control catalogs.")
auditor_app = typer.Typer(help="Auditor evidence portal (NDA read-only).")
scaffold_app = typer.Typer(help="Scaffold modules and integrations (parity build kit).")
app.add_typer(tasks_app, name="tasks")
app.add_typer(export_app, name="export")
app.add_typer(vendor_app, name="vendor")
app.add_typer(access_review_app, name="access-review")
app.add_typer(apps_app, name="apps")
app.add_typer(trust_app, name="trust")
app.add_typer(devices_app, name="devices")
app.add_typer(framework_app, name="framework")
app.add_typer(auditor_app, name="auditor")
app.add_typer(scaffold_app, name="scaffold")


@app.command()
def parity(
    phase: int | None = typer.Option(None, "--phase", "-p", help="Filter by build phase (1-6)"),
) -> None:
    """Vanta/Drata parity matrix — gaps, status, and build phases."""
    from hipaa_audit.platform import parity_report

    report = parity_report(phase=phase)
    table = Table(title="Vanta / Drata parity" + (f" — phase {phase}" if phase else ""))
    table.add_column("ID")
    table.add_column("Capability")
    table.add_column("Status")
    table.add_column("Phase")
    table.add_column("Gaps")
    for cap in report["capabilities"]:
        gaps = ", ".join(cap.get("gaps", [])[:2]) or "—"
        table.add_row(
            cap.get("id", ""),
            (cap.get("name", "") or "")[:36],
            cap.get("status", ""),
            str(cap.get("phase", "")),
            gaps[:40],
        )
    console.print(table)
    console.print(
        f"\n[bold]Coverage estimate:[/bold] {report['coverage_pct']}% "
        f"({report['by_status']})"
    )
    console.print("Roadmap: [link]docs/roadmap/PARITY.md[/link]")
    console.print("Build kit: [link]docs/architecture/EXTENSION_MODEL.md[/link]")


@scaffold_app.command("module")
def scaffold_module_cmd(
    name: str = typer.Argument(..., help="Module name e.g. baa_tracking"),
    path: Path = typer.Argument(Path.cwd(), help="Workspace root for example files"),
) -> None:
    """Scaffold a new check module (5-layer extension model)."""
    from hipaa_audit.platform import scaffold_module

    created = scaffold_module(path, name)
    for p in created:
        console.print(f"[green]created[/green] {p}")
    console.print("Next: see platform/scaffold_output.yaml and docs/architecture/EXTENSION_MODEL.md")


@scaffold_app.command("integration")
def scaffold_integration_cmd(
    integration_id: str = typer.Argument(..., help="Integration id e.g. jamf"),
    path: Path = typer.Argument(Path.cwd(), help="Workspace root"),
) -> None:
    """Scaffold an integration adapter stub."""
    from hipaa_audit.platform import scaffold_integration

    created = scaffold_integration(path, integration_id)
    for p in created:
        console.print(f"[green]created[/green] {p}")
    console.print(f"Next: see platform/scaffold-{integration_id}.yaml")


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
    sync_tasks: bool = typer.Option(
        True,
        "--sync-tasks/--no-sync-tasks",
        help="Create remediation tasks for new failures",
    ),
    notify: bool = typer.Option(
        False,
        "--notify/--no-notify",
        help="Send Slack alert on posture drop or failures (requires SLACK_WEBHOOK_URL)",
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
    posture = compute_posture(report)
    record_history(report, path.resolve())
    _print_summary(report)
    console.print(f"\n[bold cyan]Posture score:[/bold cyan] {posture['score']}%")

    if notify or cfg.get("notifications", {}).get("slack", {}).get("enabled", False):
        msg = maybe_notify_slack(
            config=cfg,
            repo_path=path.resolve(),
            current_score=posture["score"],
            summary=report.summary,
            failing=posture.get("failing_controls", []),
        )
        if msg:
            console.print(f"[dim]{msg}[/dim]")

    if sync_tasks:
        tasks_path = path / cfg.get("tasks_path", "compliance/tasks.yaml")
        created = sync_from_report(
            report,
            tasks_path,
            default_owner=cfg.get("tasks", {}).get("default_owner", "security@example.com"),
            due_days=int(cfg.get("tasks", {}).get("due_days", 14)),
        )
        if created:
            console.print(f"[yellow]Created {len(created)} remediation task(s)[/yellow]")

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
        (src / "scripts" / "run-e2e.sh", path / "scripts" / "run-e2e.sh"),
        (src / "compliance" / "tasks.example.yaml", path / "compliance" / "tasks.yaml"),
        (src / "compliance" / "acknowledgments.example.yaml", path / "compliance" / "acknowledgments.yaml"),
        (src / "compliance" / "vendors.example.yaml", path / "compliance" / "vendors.yaml"),
        (src / "compliance" / "access-reviews.example.yaml", path / "compliance" / "access-reviews.yaml"),
        (src / "compliance" / "saas-inventory.example.yaml", path / "compliance" / "saas-inventory.yaml"),
        (src / "compliance" / "certifications.example.yaml", path / "compliance" / "certifications.yaml"),
        (src / "compliance" / "devices.example.yaml", path / "compliance" / "devices.yaml"),
        (src / "compliance" / "vendor-questionnaires.example.yaml", path / "compliance" / "vendor-questionnaires.yaml"),
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
    console.print("  4. Run: bash scripts/run-e2e.sh")


@tasks_app.command("list")
def tasks_list(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List open remediation tasks."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    tasks_path = path / cfg.get("tasks_path", "compliance/tasks.yaml")
    tasks = list_open_tasks(tasks_path)
    if not tasks:
        console.print("[green]No open tasks[/green]")
        return
    table = Table(title="Open remediation tasks")
    table.add_column("ID")
    table.add_column("Control")
    table.add_column("Title")
    table.add_column("Due")
    for t in tasks:
        table.add_row(t.get("id", ""), t.get("control_id", ""), (t.get("title", "") or "")[:40], t.get("due_date", ""))
    console.print(table)


@tasks_app.command("sync")
def tasks_sync(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    report_json: Path = typer.Option(Path("evidence/latest/audit-report.json"), "--report", "-r"),
) -> None:
    """Sync tasks from an audit report JSON."""
    import json

    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    data = json.loads((path / report_json).read_text())
    from hipaa_audit.controls import load_controls
    from hipaa_audit.models import AuditReport, CheckResult, CheckStatus, ControlResult

    controls_map = {c.id: c for c in load_controls()}
    results = []
    for row in data.get("controls", []):
        ctrl = controls_map.get(row["id"])
        if not ctrl:
            continue
        check_results = [
            CheckResult(
                check_id=ch["id"],
                title=ch["id"],
                status=CheckStatus(ch["status"]),
                message=ch.get("message", ""),
                remediation=ch.get("remediation"),
            )
            for ch in row.get("checks", [])
        ]
        results.append(ControlResult(control=ctrl, results=check_results))
    report = AuditReport(
        org_name=data.get("org_name", ""),
        repo_path=str(path),
        controls=results,
        generated_at=data.get("generated_at", ""),
        config=cfg,
    )
    tasks_path = path / cfg.get("tasks_path", "compliance/tasks.yaml")
    created = sync_from_report(report, tasks_path, default_owner=cfg.get("tasks", {}).get("default_owner", "security@example.com"))
    console.print(f"[green]Synced {len(created)} new task(s)[/green]")


@tasks_app.command("done")
def tasks_done(
    task_id: str = typer.Argument(..., help="Task ID e.g. TASK-0001"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Mark a remediation task complete."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    tasks_path = path / cfg.get("tasks_path", "compliance/tasks.yaml")
    if complete_task(tasks_path, task_id):
        console.print(f"[green]Completed {task_id}[/green]")
    else:
        console.print(f"[red]Task not found: {task_id}[/red]")
        raise typer.Exit(1)


@export_app.command("auditor")
def export_auditor(
    path: Path = typer.Argument(Path.cwd()),
    output: Path = typer.Option(Path("evidence/latest/auditor-bundle.zip"), "--output", "-o"),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Zip audit reports, policies, and compliance registers for auditors."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    out = path / output if not output.is_absolute() else output
    build_auditor_bundle(path, out, config=cfg)
    console.print(f"[green]Auditor bundle[/green] → {out}")


@export_app.command("probo")
def export_probo(
    path: Path = typer.Argument(Path.cwd()),
    output: Path = typer.Option(Path("evidence/latest/probo-import.json"), "--output", "-o"),
    report_json: Path = typer.Option(Path("evidence/latest/audit-report.json"), "--report", "-r"),
) -> None:
    """Export audit results for Probo (getprobo/probo) import."""
    import json

    from hipaa_audit.controls import load_controls
    from hipaa_audit.models import AuditReport, CheckResult, CheckStatus, ControlResult

    data = json.loads((path / report_json).read_text())
    controls_map = {c.id: c for c in load_controls()}
    results = []
    for row in data.get("controls", []):
        ctrl = controls_map.get(row["id"])
        if not ctrl:
            continue
        check_results = [
            CheckResult(
                check_id=ch["id"],
                title=ch["id"],
                status=CheckStatus(ch["status"]),
                message=ch.get("message", ""),
                evidence_path=ch.get("evidence_path"),
            )
            for ch in row.get("checks", [])
        ]
        results.append(ControlResult(control=ctrl, results=check_results))
    report = AuditReport(
        org_name=data.get("org_name", ""),
        repo_path=str(path),
        controls=results,
        generated_at=data.get("generated_at", ""),
    )
    out = path / output if not output.is_absolute() else output
    write_probo_export(report, out)
    console.print(f"[green]Probo export[/green] → {out}")
    console.print("Import via Probo MCP or prb measure create — see docs/stacks/probo-hipaa-audit.md")


@vendor_app.command("init")
def vendor_init(
    path: Path = typer.Argument(Path.cwd(), help="Project root"),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Create an empty vendor register from the example template."""
    import shutil

    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    dest = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    if dest.exists():
        console.print(f"[yellow]exists[/yellow] {dest}")
        return
    src = PACKAGE_ROOT / "compliance" / "vendors.example.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    console.print(f"[green]created[/green] {dest}")


@vendor_app.command("add")
def vendor_add_cmd(
    name: str = typer.Argument(..., help="Vendor name"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    phi_access: str = typer.Option("none", help="none|partial|full"),
    risk_tier: str = typer.Option("medium", help="low|medium|high"),
    baa: bool = typer.Option(False, "--baa/--no-baa", help="BAA executed"),
) -> None:
    """Add a vendor to the register."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    vendor = add_vendor(register, name=name, phi_access=phi_access, risk_tier=risk_tier, baa_executed=baa)
    console.print(f"[green]Added[/green] {vendor['id']} — {name}")


@vendor_app.command("list")
def vendor_list_cmd(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List vendors in the register."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    data = load_vendors(register)
    vendors = data.get("vendors", [])
    if not vendors:
        console.print("[yellow]No vendors — run hipaa-audit vendor init[/yellow]")
        return
    table = Table(title="Vendor register")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("PHI")
    table.add_column("Tier")
    table.add_column("BAA")
    table.add_column("Last review")
    for v in vendors:
        table.add_row(
            v.get("id", ""),
            v.get("name", ""),
            v.get("phi_access", ""),
            v.get("risk_tier", ""),
            "Y" if v.get("baa_executed") else "N",
            v.get("last_review") or "—",
        )
    console.print(table)


@vendor_app.command("review")
def vendor_review_cmd(
    vendor_id: str = typer.Argument(..., help="Vendor ID e.g. VND-001"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    reviewer: str = typer.Option("", "--reviewer", "-r"),
    complete: bool = typer.Option(
        False,
        "--complete",
        help="Mark all SIG-lite questionnaire items as satisfied",
    ),
) -> None:
    """Record a vendor security questionnaire review."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    questionnaire = {k: True for k in SIG_LITE_KEYS} if complete else {}
    if not questionnaire:
        console.print("[red]Pass --complete or extend CLI with per-field flags[/red]")
        raise typer.Exit(1)
    if review_vendor(register, vendor_id, questionnaire, reviewer=reviewer):
        console.print(f"[green]Reviewed[/green] {vendor_id}")
    else:
        console.print(f"[red]Vendor not found: {vendor_id}[/red]")
        raise typer.Exit(1)


@vendor_app.command("send")
def vendor_send(
    vendor_id: str = typer.Argument(..., help="Vendor ID e.g. VND-001"),
    contact: str = typer.Argument(..., help="Vendor security contact email"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    due_days: int = typer.Option(30, help="Days until questionnaire due"),
) -> None:
    """Send an outbound SIG-lite questionnaire to a vendor."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    vendors_path = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    q_path = path / cfg.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    entry = send_questionnaire(q_path, vendors_path, vendor_id=vendor_id, contact=contact, due_days=due_days)
    if not entry:
        console.print(f"[red]Vendor not found: {vendor_id}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Sent[/green] {entry['id']} to {contact} — due {entry['due_date']}")
    console.print("Share templates/vendor-questionnaire.md with the vendor contact.")


@vendor_app.command("respond")
def vendor_respond(
    questionnaire_id: str = typer.Argument(..., help="Questionnaire ID e.g. QNR-001"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    reviewer: str = typer.Option("", "--reviewer", "-r"),
    complete: bool = typer.Option(True, "--complete/--partial", help="Mark all SIG-lite items satisfied"),
) -> None:
    """Record vendor questionnaire responses."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    vendors_path = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    q_path = path / cfg.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    responses = {k: True for k in SIG_LITE_KEYS} if complete else {}
    if not responses:
        console.print("[red]Use --complete or extend with per-field flags[/red]")
        raise typer.Exit(1)
    if respond_questionnaire(q_path, vendors_path, questionnaire_id, responses, reviewer=reviewer):
        console.print(f"[green]Recorded[/green] responses for {questionnaire_id}")
    else:
        console.print(f"[red]Questionnaire not found: {questionnaire_id}[/red]")
        raise typer.Exit(1)


@vendor_app.command("questionnaires")
def vendor_questionnaires(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List outbound vendor questionnaires."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    q_path = path / cfg.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    data = load_questionnaires(q_path)
    items = data.get("questionnaires", [])
    if not items:
        console.print("[yellow]No questionnaires — hipaa-audit vendor send[/yellow]")
        return
    table = Table(title="Vendor questionnaires")
    table.add_column("ID")
    table.add_column("Vendor")
    table.add_column("Contact")
    table.add_column("Status")
    table.add_column("Due")
    for q in items:
        table.add_row(
            q.get("id", ""),
            q.get("vendor_name", q.get("vendor_id", "")),
            q.get("contact", ""),
            q.get("status", ""),
            q.get("due_date", ""),
        )
    console.print(table)


@vendor_app.command("portal")
def vendor_portal(
    questionnaire_id: str = typer.Argument(..., help="Questionnaire ID e.g. QNR-001"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Generate in-browser vendor questionnaire HTML form."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    q_path = path / cfg.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    entry = find_questionnaire(q_path, questionnaire_id)
    if not entry:
        console.print(f"[red]Questionnaire not found: {questionnaire_id}[/red]")
        raise typer.Exit(1)
    out = publish_vendor_portal(repo_path=path, config=cfg, questionnaire=entry)
    console.print(f"[green]Vendor portal[/green] → {out}")
    console.print("Send this link/file to the vendor contact to collect SIG-lite responses.")


@vendor_app.command("import-response")
def vendor_import_response(
    questionnaire_id: str = typer.Argument(...),
    response_file: Path = typer.Argument(..., help="YAML downloaded from vendor portal"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Import vendor questionnaire YAML response from vendor portal."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    vendors_path = path / cfg.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
    q_path = path / cfg.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
    if import_response(q_path, vendors_path, questionnaire_id, response_file):
        console.print(f"[green]Imported[/green] responses for {questionnaire_id}")
    else:
        console.print("[red]Import failed — check questionnaire ID and YAML file[/red]")
        raise typer.Exit(1)


@access_review_app.command("start")
def access_review_start(
    name: str = typer.Argument(..., help="Campaign name"),
    owner: str = typer.Argument(..., help="Campaign owner email"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    systems: str = typer.Option(
        "github,aws-iam,okta",
        "--systems",
        "-s",
        help="Comma-separated system ids (id:name pairs optional, use id only)",
    ),
    due_days: int = typer.Option(30, help="Days until campaign due"),
) -> None:
    """Start a quarterly access review campaign."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("access_reviews", {}).get("register_path", "compliance/access-reviews.yaml")
    system_list = []
    for raw in systems.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if ":" in raw:
            sid, sname = raw.split(":", 1)
            system_list.append({"id": sid.strip(), "name": sname.strip(), "owner": owner})
        else:
            system_list.append({"id": raw, "name": raw.replace("-", " ").title(), "owner": owner})
    campaign = start_campaign(register, name=name, owner=owner, systems=system_list, due_days=due_days)
    console.print(f"[green]Started[/green] {campaign['id']} — due {campaign['due_date']}")


@access_review_app.command("list")
def access_review_list(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List access review campaigns."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("access_reviews", {}).get("register_path", "compliance/access-reviews.yaml")
    data = load_campaigns(register)
    campaigns = data.get("campaigns", [])
    if not campaigns:
        console.print("[yellow]No campaigns — run hipaa-audit access-review start[/yellow]")
        return
    table = Table(title="Access review campaigns")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Due")
    table.add_column("Decisions")
    for c in campaigns:
        decisions = len([d for d in data.get("decisions", []) if d.get("campaign_id") == c["id"]])
        table.add_row(c.get("id", ""), c.get("name", ""), c.get("status", ""), c.get("due_date", ""), str(decisions))
    console.print(table)


@access_review_app.command("decide")
def access_review_decide(
    campaign_id: str = typer.Argument(...),
    system_id: str = typer.Argument(...),
    principal: str = typer.Argument(..., help="User or role reviewed"),
    decision: str = typer.Argument(..., help="retain|revoke|modify"),
    reviewer: str = typer.Argument(...),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    notes: str = typer.Option("", "--notes", "-n"),
) -> None:
    """Record an access review decision."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("access_reviews", {}).get("register_path", "compliance/access-reviews.yaml")
    if record_decision(
        register,
        campaign_id=campaign_id,
        system_id=system_id,
        principal=principal,
        decision=decision,
        reviewer=reviewer,
        notes=notes,
    ):
        console.print(f"[green]Recorded[/green] {decision} for {principal} on {system_id}")
    else:
        console.print(f"[red]Campaign not found: {campaign_id}[/red]")
        raise typer.Exit(1)


@access_review_app.command("complete")
def access_review_complete(
    campaign_id: str = typer.Argument(...),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Mark an access review campaign complete."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("access_reviews", {}).get("register_path", "compliance/access-reviews.yaml")
    if complete_campaign(register, campaign_id):
        console.print(f"[green]Completed[/green] {campaign_id}")
    else:
        console.print(f"[red]Campaign not found: {campaign_id}[/red]")
        raise typer.Exit(1)


@apps_app.command("discover")
def apps_discover(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Discover SaaS apps from Okta and/or Google Workspace."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
    discovered: list = []
    sources: list[str] = []

    okta = okta_config_from_identity(cfg)
    if okta:
        domain, token = okta
        okta_apps = discover_okta_apps(domain, token)
        discovered.extend(okta_apps)
        sources.append("okta")
        console.print(f"[green]Okta[/green] {len(okta_apps)} app(s)")

    google = google_config_from_identity(cfg)
    if google:
        try:
            creds_path, admin = google
            google_apps = discover_google_apps(creds_path, admin)
            discovered.extend(google_apps)
            sources.append("google")
            console.print(f"[green]Google[/green] {len(google_apps)} app(s)")
        except ImportError:
            console.print("[yellow]Google skipped — pip install hipaa-audit[identity][/yellow]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Google API error: {exc}[/yellow]")

    if not discovered:
        console.print("[red]Enable identity.okta and/or identity.google with API credentials[/red]")
        raise typer.Exit(1)

    source = "+".join(sources)
    data = merge_discovered(register, discovered, source=source)
    console.print(f"[green]Merged[/green] {len(discovered)} app(s) → {register}")
    console.print(f"[dim]Total inventory: {len(data.get('apps', []))}[/dim]")


@apps_app.command("import-google")
def apps_import_google(
    csv_file: Path = typer.Argument(..., help="Google Admin third-party apps CSV export"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Import Google Workspace apps from Admin Console CSV export."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
    discovered = import_google_apps_csv(csv_file)
    data = merge_discovered(register, discovered, source="google-csv")
    console.print(f"[green]Imported[/green] {len(discovered)} Google app(s) → {register}")
    console.print(f"[dim]Total inventory: {len(data.get('apps', []))}[/dim]")


@apps_app.command("list")
def apps_list(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List SaaS apps in inventory."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
    data = load_inventory(register)
    apps = data.get("apps", [])
    if not apps:
        console.print("[yellow]No apps — run hipaa-audit apps discover[/yellow]")
        return
    table = Table(title=f"SaaS inventory ({data.get('discovered_at', 'unknown')})")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Provider")
    table.add_column("Vendor")
    table.add_column("PHI risk")
    for app in apps:
        table.add_row(
            app.get("id", ""),
            app.get("name", ""),
            app.get("provider", ""),
            app.get("vendor_id") or "—",
            app.get("phi_risk", "unknown"),
        )
    console.print(table)


@apps_app.command("link")
def apps_link(
    app_id: str = typer.Argument(..., help="App ID from inventory"),
    vendor_id: str = typer.Argument(..., help="Vendor ID e.g. VND-001"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    phi_risk: str = typer.Option("", help="low|medium|high"),
) -> None:
    """Link a SaaS app to a vendor register entry."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
    if link_app(register, app_id, vendor_id, phi_risk=phi_risk):
        console.print(f"[green]Linked[/green] {app_id} → {vendor_id}")
    else:
        console.print(f"[red]App not found: {app_id}[/red]")
        raise typer.Exit(1)


@trust_app.command("publish")
def trust_publish(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    report_json: Path = typer.Option(Path("evidence/latest/audit-report.json"), "--report", "-r"),
) -> None:
    """Generate public trust center HTML from latest audit report."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = path / report_json if not report_json.is_absolute() else report_json
    if not report.exists():
        console.print("[red]Run hipaa-audit scan first[/red]")
        raise typer.Exit(1)
    out = publish_trust_center(repo_path=path, config=cfg, report_json=report)
    console.print(f"[green]Trust center[/green] → {out}")
    console.print("Host at compliance/trust-center/ or sync to your public site.")


@devices_app.command("template")
def devices_template(
    path: Path = typer.Argument(Path.cwd()),
    output: Path = typer.Option(Path("compliance/devices-template.csv"), "--output", "-o"),
) -> None:
    """Bootstrap MDM device import CSV template."""
    out = path / output if not output.is_absolute() else output
    device_csv_template(out)
    console.print(f"[green]Created[/green] {out}")


@devices_app.command("import")
def devices_import(
    csv_file: Path = typer.Argument(..., help="Jamf or Intune device export CSV"),
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Import MDM device inventory from CSV."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("devices", {}).get("register_path", "compliance/devices.yaml")
    count = import_devices_csv(register, csv_file)
    console.print(f"[green]Imported[/green] {count} device(s) → {register}")


@devices_app.command("list")
def devices_list(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """List MDM device inventory."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("devices", {}).get("register_path", "compliance/devices.yaml")
    data = load_devices(register)
    devices = data.get("devices", [])
    if not devices:
        console.print("[yellow]No devices — hipaa-audit devices import[/yellow]")
        return
    table = Table(title=f"Device inventory ({data.get('imported_at', 'unknown')})")
    table.add_column("ID")
    table.add_column("Owner")
    table.add_column("Platform")
    table.add_column("MDM")
    table.add_column("Encrypted")
    table.add_column("Screen lock")
    for d in devices:
        table.add_row(
            d.get("id", ""),
            d.get("owner", ""),
            d.get("platform", ""),
            d.get("mdm", ""),
            "Y" if d.get("encrypted") else "N",
            "Y" if d.get("screen_lock") else "N",
        )
    console.print(table)


@auditor_app.command("publish")
def auditor_publish(
    path: Path = typer.Argument(Path.cwd()),
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
    report_json: Path = typer.Option(Path("evidence/latest/audit-report.json"), "--report", "-r"),
) -> None:
    """Publish read-only auditor portal with optional passphrase gate."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = path / report_json if not report_json.is_absolute() else report_json
    if not report.exists():
        console.print("[red]Run hipaa-audit scan first[/red]")
        raise typer.Exit(1)
    portal_cfg = cfg.get("auditor_portal", {})
    passphrase = os.environ.get(portal_cfg.get("access_passphrase_env", "AUDITOR_PORTAL_PASSPHRASE"), "")
    out = publish_auditor_portal(
        repo_path=path,
        config=cfg,
        report_json=report,
        access_passphrase=passphrase,
    )
    console.print(f"[green]Auditor portal[/green] → {out}")
    if passphrase:
        console.print("[dim]Passphrase gate enabled via env[/dim]")
    else:
        console.print("[yellow]No passphrase set — portal is open. Set AUDITOR_PORTAL_PASSPHRASE for NDA gate.[/yellow]")


@framework_app.command("soc2")
def framework_soc2(
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Show SOC 2 TSC supplement status (enable frameworks.soc2 in config)."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = soc2_report(cfg)
    table = Table(title="SOC 2 TSC supplement")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("SOC 2 enabled in config", "yes" if report["enabled"] else "no (set frameworks.soc2: true)")
    table.add_row("SOC 2 controls", str(report["soc2_controls"]))
    table.add_row("HIPAA controls", str(report["hipaa_controls"]))
    table.add_row("Total when enabled", str(report["total_controls"]))
    table.add_row("TSC criteria mapped", str(report["soc2_criteria_count"]))
    console.print(table)
    if not report["enabled"]:
        console.print("[dim]Run scan with frameworks.soc2: true to include SOC2-* controls[/dim]")


@framework_app.command("iso27001")
def framework_iso27001(
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Show ISO 27001 Annex A supplement status."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = iso27001_report(cfg)
    table = Table(title="ISO 27001 Annex A supplement")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("ISO 27001 enabled", "yes" if report["enabled"] else "no (set frameworks.iso27001: true)")
    table.add_row("ISO 27001 controls", str(report["iso27001_controls"]))
    table.add_row("HIPAA controls", str(report["hipaa_controls"]))
    table.add_row("Total when enabled", str(report["total_controls"]))
    table.add_row("Annex A controls mapped", str(report["annex_a_count"]))
    console.print(table)
    if not report["enabled"]:
        console.print("[dim]Run scan with frameworks.iso27001: true to include ISO27001-* controls[/dim]")


@framework_app.command("hitrust")
def framework_hitrust(
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Show HITRUST CSF supplement status."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = hitrust_report(cfg)
    table = Table(title="HITRUST CSF supplement")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("HITRUST enabled", "yes" if report["enabled"] else "no (set frameworks.hitrust: true)")
    table.add_row("HITRUST controls", str(report["hitrust_controls"]))
    table.add_row("HIPAA controls", str(report["hipaa_controls"]))
    table.add_row("Total when enabled", str(report["total_controls"]))
    console.print(table)


@framework_app.command("pci")
def framework_pci(
    config: Path = typer.Option(Path("hipaa-audit.yaml"), "--config", "-c"),
) -> None:
    """Show PCI DSS supplement status."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    report = pci_report(cfg)
    table = Table(title="PCI DSS supplement")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("PCI enabled", "yes" if report["enabled"] else "no (set frameworks.pci: true)")
    table.add_row("PCI controls", str(report["pci_controls"]))
    table.add_row("HIPAA controls", str(report["hipaa_controls"]))
    table.add_row("Total when enabled", str(report["total_controls"]))
    console.print(table)


@app.command("import-training")
def import_training(
    path: Path = typer.Argument(Path.cwd(), help="Project root"),
    output: Path = typer.Option(Path("compliance/training-log.csv"), "--output", "-o"),
) -> None:
    """Bootstrap workforce training CSV template."""
    out = path / output if not output.is_absolute() else output
    import_training_template(out)
    console.print(f"[green]Created[/green] {out}")


@app.command()
def catalog(
    subcommand: str = typer.Argument("coverage", help="coverage"),
) -> None:
    """Probo HIPAA catalog crosswalk (60 CFR specs)."""
    if subcommand != "coverage":
        console.print("[red]Usage: hipaa-audit catalog coverage[/red]")
        raise typer.Exit(1)
    report = coverage_report()
    table = Table(title="Probo HIPAA catalog coverage")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Probo specs", str(report["probo_total"]))
    table.add_row("hipaa-audit controls", str(report["hipaa_audit_controls"]))
    table.add_row("Probo mapped", str(report["probo_mapped"]))
    table.add_row("Coverage", f"{report['coverage_pct']}%")
    console.print(table)
    if report["probo_unmapped"]:
        console.print(f"[yellow]{len(report['probo_unmapped'])} unmapped[/yellow] (run with supplement YAML)")


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
def serve(
    path: Path = typer.Argument(Path.cwd(), help="Compliance workspace directory"),
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8787, "--port", "-p"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open browser"),
) -> None:
    """Start the self-hosted compliance workspace (Vanta/Drata-style UI)."""
    try:
        from hipaa_audit.workspace import run_server
    except ImportError as exc:
        console.print("[red]Install workspace extras: pip install hipaa-audit[serve][/red]")
        raise typer.Exit(1) from exc
    run_server(path, host=host, port=port, open_browser=not no_browser)


@app.command()
def up(
    path: Path = typer.Argument(Path.cwd(), help="Compliance workspace directory"),
    port: int = typer.Option(8787, "--port", "-p"),
) -> None:
    """Alias for hipaa-audit serve — start compliance workspace."""
    serve(path=path, host="127.0.0.1", port=port, no_browser=False)


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
