from __future__ import annotations

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
    discover_okta_apps,
    link_app,
    load_inventory,
    merge_discovered,
    okta_config_from_identity,
)
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
app.add_typer(tasks_app, name="tasks")
app.add_typer(export_app, name="export")
app.add_typer(vendor_app, name="vendor")
app.add_typer(access_review_app, name="access-review")
app.add_typer(apps_app, name="apps")
app.add_typer(trust_app, name="trust")


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
    """Discover SaaS apps from Okta and merge into inventory."""
    cfg = load_config(config if config.exists() else PACKAGE_ROOT / "hipaa-audit.example.yaml")
    register = path / cfg.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
    okta = okta_config_from_identity(cfg)
    if not okta:
        console.print("[red]Enable identity.okta and set OKTA_API_TOKEN[/red]")
        raise typer.Exit(1)
    domain, token = okta
    discovered = discover_okta_apps(domain, token)
    data = merge_discovered(register, discovered, source="okta")
    console.print(f"[green]Discovered[/green] {len(discovered)} Okta app(s) → {register}")
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
