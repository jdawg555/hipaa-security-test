from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from hipaa_audit import __version__
from hipaa_audit.access_reviews import (
    complete_campaign,
    load_campaigns,
    record_decision,
    start_campaign,
)
from hipaa_audit.controls import PACKAGE_ROOT
from hipaa_audit.devices import load_devices
from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.questionnaires import load_questionnaires
from hipaa_audit.report import _load_history
from hipaa_audit.platform.adapters.registry import record_connection_test, test_integration_connection
from hipaa_audit.tasks import assign_task, complete_task, list_open_tasks, load_tasks
from hipaa_audit.vendors import load_vendors
from hipaa_audit.workspace.config_store import (
    apply_integration_toggle,
    ensure_bootstrapped,
    integration_status,
    load_workspace_config,
    save_workspace_config,
)
from hipaa_audit.workspace.scan_runner import get_scan_state, latest_report, run_scan_job

WORKSPACE_DIR = Path(__file__).resolve().parent
TEMPLATES = Environment(
    loader=FileSystemLoader(WORKSPACE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def _framework_label(control_id: str) -> str:
    if control_id.startswith("SOC2-"):
        return "SOC 2"
    if control_id.startswith("ISO27001-"):
        return "ISO 27001"
    return "HIPAA"


def _render(name: str, **ctx: Any) -> HTMLResponse:
    template = TEMPLATES.get_template(name)
    return HTMLResponse(template.render(version=__version__, **ctx))


def _bootstrap_repo(repo_path: Path, org_name: str) -> None:
    src = PACKAGE_ROOT
    targets = [
        (src / "policies", repo_path / "policies"),
        (src / "templates", repo_path / "templates"),
        (src / "compliance" / "tasks.example.yaml", repo_path / "compliance" / "tasks.yaml"),
        (src / "compliance" / "vendors.example.yaml", repo_path / "compliance" / "vendors.yaml"),
        (src / "compliance" / "access-reviews.example.yaml", repo_path / "compliance" / "access-reviews.yaml"),
        (src / "compliance" / "saas-inventory.example.yaml", repo_path / "compliance" / "saas-inventory.yaml"),
        (src / "compliance" / "certifications.example.yaml", repo_path / "compliance" / "certifications.yaml"),
        (src / "compliance" / "devices.example.yaml", repo_path / "compliance" / "devices.yaml"),
        (src / "compliance" / "vendor-questionnaires.example.yaml", repo_path / "compliance" / "vendor-questionnaires.yaml"),
        (src / "compliance" / "acknowledgments.example.yaml", repo_path / "compliance" / "acknowledgments.yaml"),
        (src / ".github" / "workflows" / "compliance-audit.yml", repo_path / ".github" / "workflows" / "compliance-audit.yml"),
    ]
    for s, d in targets:
        if not s.exists():
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_dir():
            if not d.exists():
                shutil.copytree(s, d)
        elif not d.exists():
            shutil.copy2(s, d)
    config = load_workspace_config(repo_path)
    config["org_name"] = org_name
    config.setdefault("workspace", {})["onboarded"] = True
    save_workspace_config(repo_path, config)
    (repo_path / "evidence").mkdir(exist_ok=True)


def create_app(repo_path: Path) -> FastAPI:
    repo_path = repo_path.resolve()
    app = FastAPI(title="hipaa-audit workspace", version=__version__)
    app.mount("/static", StaticFiles(directory=WORKSPACE_DIR / "static"), name="static")

    def base_ctx(page: str) -> dict[str, Any]:
        config = load_workspace_config(repo_path)
        return {"page": page, "org_name": config.get("org_name", repo_path.name), "repo_path": str(repo_path)}

    @app.get("/onboarding", response_class=HTMLResponse)
    def onboarding_page() -> HTMLResponse:
        if ensure_bootstrapped(repo_path):
            return RedirectResponse("/", status_code=302)
        return _render("onboarding.html")

    @app.post("/onboarding")
    def onboarding_submit(org_name: str = Form(...), bootstrap: str = Form("")) -> RedirectResponse:
        if bootstrap:
            _bootstrap_repo(repo_path, org_name)
        else:
            config = load_workspace_config(repo_path)
            config["org_name"] = org_name
            save_workspace_config(repo_path, config)
        return RedirectResponse("/integrations", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        flash = request.query_params.get("flash", "")
        flash_error = request.query_params.get("flash_error", "")
        if not ensure_bootstrapped(repo_path):
            return RedirectResponse("/onboarding", status_code=302)
        config = load_workspace_config(repo_path)
        report = latest_report(repo_path)
        state = get_scan_state()
        summary = report.get("summary", {}) if report else {}
        ctx = base_ctx("dashboard")
        ctx.update(
            {
                "flash": flash,
                "flash_error": flash_error,
                "posture_score": report.get("posture", {}).get("score", "—") if report else "—",
                "summary": summary,
                "last_scan": report.get("generated_at") if report else state.last_finished,
                "open_tasks": len(list_open_tasks(repo_path / config.get("tasks_path", "compliance/tasks.yaml"))),
                "integrations_on": sum(1 for i in integration_status(config) if i["enabled"]),
                "history": _load_history(repo_path),
                "scan_running": state.running,
            }
        )
        return _render("dashboard.html", **ctx)

    @app.get("/monitoring", response_class=HTMLResponse)
    def monitoring(request: Request) -> HTMLResponse:
        flash = request.query_params.get("flash", "")
        if not ensure_bootstrapped(repo_path):
            return RedirectResponse("/onboarding", status_code=302)
        report = latest_report(repo_path)
        controls = []
        if report:
            for row in report.get("controls", []):
                msg = "; ".join(c.get("message", "") for c in row.get("checks", [])[:2])
                controls.append(
                    {
                        "id": row["id"],
                        "title": row.get("title", ""),
                        "framework": _framework_label(row["id"]),
                        "category": row.get("category", ""),
                        "status": row.get("status", "manual"),
                        "message": msg[:200],
                    }
                )
        ctx = base_ctx("monitoring")
        ctx.update({"controls": controls, "scan_running": get_scan_state().running, "flash": flash})
        return _render("monitoring.html", **ctx)

    @app.get("/integrations", response_class=HTMLResponse)
    def integrations(request: Request) -> HTMLResponse:
        if not ensure_bootstrapped(repo_path):
            return RedirectResponse("/onboarding", status_code=302)
        config = load_workspace_config(repo_path)
        ctx = base_ctx("integrations")
        ctx["integrations"] = integration_status(config)
        test = request.query_params.get("test", "")
        msg = request.query_params.get("msg", "").replace("+", " ")
        if test == "ok":
            ctx["flash"] = f"Connection OK: {msg}"
        elif test == "fail":
            ctx["flash_error"] = f"Connection failed: {msg}"
        return _render("integrations.html", **ctx)

    @app.post("/integrations/toggle")
    def integrations_toggle(integration_id: str = Form(...), enabled: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        if integration_id == "jamf":
            config.setdefault("devices", {})["enabled"] = enabled.lower() == "true"
        else:
            config = apply_integration_toggle(config, integration_id, enabled.lower() == "true")
        save_workspace_config(repo_path, config)
        return RedirectResponse("/integrations", status_code=303)

    @app.post("/integrations/test")
    def integrations_test(integration_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        result = test_integration_connection(integration_id, config, repo_path=repo_path)
        config = record_connection_test(config, integration_id, result)
        save_workspace_config(repo_path, config)
        status = "ok" if result.ok else "fail"
        msg = result.message.replace(" ", "+")[:100]
        return RedirectResponse(f"/integrations?test={status}&msg={msg}", status_code=303)

    @app.get("/tasks", response_class=HTMLResponse)
    def tasks_page(request: Request) -> HTMLResponse:
        if not ensure_bootstrapped(repo_path):
            return RedirectResponse("/onboarding", status_code=302)
        config = load_workspace_config(repo_path)
        tasks_path = repo_path / config.get("tasks_path", "compliance/tasks.yaml")
        all_tasks = load_tasks(tasks_path).get("tasks", [])
        open_tasks = [t for t in all_tasks if t.get("status") == "open"]
        done_tasks = [t for t in all_tasks if t.get("status") != "open"]
        ctx = base_ctx("tasks")
        ctx.update(
            {
                "open_tasks": open_tasks,
                "done_tasks": done_tasks,
                "flash": request.query_params.get("flash", ""),
            }
        )
        return _render("tasks.html", **ctx)

    @app.post("/tasks/done")
    def tasks_done(task_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        tasks_path = repo_path / config.get("tasks_path", "compliance/tasks.yaml")
        if complete_task(tasks_path, task_id):
            return RedirectResponse("/tasks?flash=Task+marked+done", status_code=303)
        return RedirectResponse("/tasks?flash=Task+not+found", status_code=303)

    @app.post("/tasks/assign")
    def tasks_assign(task_id: str = Form(...), owner: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        tasks_path = repo_path / config.get("tasks_path", "compliance/tasks.yaml")
        if assign_task(tasks_path, task_id, owner):
            return RedirectResponse("/tasks?flash=Owner+updated", status_code=303)
        return RedirectResponse("/tasks?flash=Task+not+found", status_code=303)

    @app.get("/personnel", response_class=HTMLResponse)
    def personnel() -> HTMLResponse:
        return _render("personnel.html", **base_ctx("personnel"))

    @app.get("/vendors", response_class=HTMLResponse)
    def vendors_page() -> HTMLResponse:
        config = load_workspace_config(repo_path)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        ctx = base_ctx("vendors")
        ctx["vendors"] = load_vendors(vpath).get("vendors", [])
        ctx["questionnaires"] = load_questionnaires(qpath).get("questionnaires", [])
        return _render("vendors.html", **ctx)

    def _access_review_path(config: dict[str, Any]) -> Path:
        return repo_path / config.get("access_reviews", {}).get("register_path", "compliance/access-reviews.yaml")

    def _campaign_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
        campaigns = []
        for c in data.get("campaigns", []):
            related = [d for d in data.get("decisions", []) if d.get("campaign_id") == c["id"]]
            campaigns.append({**c, "decisions": len(related), "decision_rows": related})
        return campaigns

    @app.get("/access-reviews", response_class=HTMLResponse)
    def access_reviews_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        data = load_campaigns(_access_review_path(config))
        ctx = base_ctx("access_reviews")
        ctx["campaigns"] = _campaign_rows(data)
        ctx["flash"] = request.query_params.get("flash", "")
        return _render("access_reviews.html", **ctx)

    @app.post("/access-reviews/start")
    def access_reviews_start(
        name: str = Form(...),
        owner: str = Form(...),
        due_days: int = Form(30),
        systems_text: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        path = _access_review_path(config)
        systems: list[dict[str, str]] = []
        for line in systems_text.strip().splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                systems.append(
                    {
                        "id": parts[0],
                        "name": parts[1],
                        "owner": parts[2] if len(parts) > 2 else owner,
                    }
                )
        if not systems:
            systems = [
                {"id": "github", "name": "GitHub organization", "owner": owner},
                {"id": "aws-iam", "name": "AWS IAM users and roles", "owner": owner},
            ]
        start_campaign(path, name=name, owner=owner, systems=systems, due_days=due_days)
        return RedirectResponse("/access-reviews?flash=Campaign+started", status_code=303)

    @app.post("/access-reviews/decide")
    def access_reviews_decide(
        campaign_id: str = Form(...),
        system_id: str = Form(...),
        principal: str = Form(...),
        decision: str = Form(...),
        reviewer: str = Form(...),
        notes: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        path = _access_review_path(config)
        if record_decision(
            path,
            campaign_id=campaign_id,
            system_id=system_id,
            principal=principal,
            decision=decision,
            reviewer=reviewer,
            notes=notes,
        ):
            return RedirectResponse("/access-reviews?flash=Decision+recorded", status_code=303)
        return RedirectResponse("/access-reviews?flash=Campaign+not+found", status_code=303)

    @app.post("/access-reviews/complete")
    def access_reviews_complete(campaign_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        path = _access_review_path(config)
        if complete_campaign(path, campaign_id):
            return RedirectResponse("/access-reviews?flash=Campaign+completed", status_code=303)
        return RedirectResponse("/access-reviews?flash=Campaign+not+found", status_code=303)

    @app.get("/devices", response_class=HTMLResponse)
    def devices_page() -> HTMLResponse:
        config = load_workspace_config(repo_path)
        path = repo_path / config.get("devices", {}).get("register_path", "compliance/devices.yaml")
        ctx = base_ctx("devices")
        ctx["devices"] = load_devices(path).get("devices", [])
        return _render("devices.html", **ctx)

    @app.get("/policies", response_class=HTMLResponse)
    def policies_page() -> HTMLResponse:
        config = load_workspace_config(repo_path)
        pdir = repo_path / config.get("policy_dir", "policies")
        policies = sorted(p.name for p in pdir.glob("*.md")) if pdir.is_dir() else []
        ctx = base_ctx("policies")
        ctx["policies"] = policies
        return _render("policies.html", **ctx)

    @app.get("/audits", response_class=HTMLResponse)
    def audits_page(flash: str = "") -> HTMLResponse:
        config = load_workspace_config(repo_path)
        trust = repo_path / config.get("trust_center", {}).get("output_dir", "compliance/trust-center") / "index.html"
        auditor = repo_path / config.get("auditor_portal", {}).get("output_dir", "compliance/auditor-portal") / "index.html"
        ctx = base_ctx("audits")
        ctx.update(
            {
                "flash": flash,
                "trust_exists": trust.exists(),
                "auditor_exists": auditor.exists(),
            }
        )
        return _render("audits.html", **ctx)

    @app.post("/audits/export")
    def audits_export() -> RedirectResponse:
        config = load_workspace_config(repo_path)
        out = repo_path / "evidence" / "latest" / "auditor-bundle.zip"
        build_auditor_bundle(repo_path, out, config=config)
        return RedirectResponse("/audits?flash=Auditor+ZIP+ready+at+evidence%2Flatest%2Fauditor-bundle.zip", status_code=303)

    @app.get("/portals/trust", response_model=None)
    def portal_trust():
        config = load_workspace_config(repo_path)
        path = repo_path / config.get("trust_center", {}).get("output_dir", "compliance/trust-center") / "index.html"
        if path.exists():
            return FileResponse(path)
        return RedirectResponse("/audits", status_code=302)

    @app.get("/portals/auditor", response_model=None)
    def portal_auditor():
        config = load_workspace_config(repo_path)
        path = repo_path / config.get("auditor_portal", {}).get("output_dir", "compliance/auditor-portal") / "index.html"
        if path.exists():
            return FileResponse(path)
        return RedirectResponse("/audits", status_code=302)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request) -> HTMLResponse:
        flash = request.query_params.get("flash", "")
        config = load_workspace_config(repo_path)
        ctx = base_ctx("settings")
        ctx["config"] = config
        ctx["schedule_hours"] = config.get("workspace", {}).get("schedule_hours", 0)
        ctx["flash"] = "Settings saved." if flash == "saved" else ""
        return _render("settings.html", **ctx)

    @app.post("/settings")
    def settings_save(
        org_name: str = Form(""),
        github_repo: str = Form(""),
        okta_domain: str = Form(""),
        soc2: str = Form(""),
        iso27001: str = Form(""),
        schedule_hours: int = Form(0),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        config["org_name"] = org_name
        config.setdefault("github", {})["repo"] = github_repo
        config.setdefault("identity", {}).setdefault("okta", {})["domain"] = okta_domain
        config.setdefault("frameworks", {})["soc2"] = soc2 == "on"
        config.setdefault("frameworks", {})["iso27001"] = iso27001 == "on"
        config.setdefault("workspace", {})["schedule_hours"] = max(0, min(168, schedule_hours))
        save_workspace_config(repo_path, config)
        return RedirectResponse("/settings?flash=saved", status_code=303)

    @app.post("/scan")
    def trigger_scan() -> RedirectResponse:
        try:
            run_scan_job(repo_path)
            return RedirectResponse("/monitoring?flash=Scan+completed", status_code=303)
        except RuntimeError:
            return RedirectResponse("/?flash_error=Scan+already+running", status_code=303)
        except Exception as exc:  # noqa: BLE001
            return RedirectResponse(f"/?flash_error={str(exc)[:120]}", status_code=303)

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        report = latest_report(repo_path)
        state = get_scan_state()
        return {
            "version": __version__,
            "scan_running": state.running,
            "last_score": state.last_score,
            "posture": report.get("posture") if report else None,
            "summary": report.get("summary") if report else None,
        }

    return app


def _scheduler_loop(repo_path: Path, hours: int) -> None:
    while True:
        time.sleep(max(hours, 1) * 3600)
        try:
            if not get_scan_state().running:
                run_scan_job(repo_path)
        except Exception:  # noqa: BLE001
            pass


def run_server(
    repo_path: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser: bool = True,
) -> None:
    import uvicorn

    config = load_workspace_config(repo_path)
    hours = int(config.get("workspace", {}).get("schedule_hours", 0))
    if hours > 0:
        thread = threading.Thread(target=_scheduler_loop, args=(repo_path, hours), daemon=True)
        thread.start()

    app = create_app(repo_path)
    url = f"http://{host}:{port}"
    print(f"hipaa-audit workspace → {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    uvicorn.run(app, host=host, port=port, log_level="info")
