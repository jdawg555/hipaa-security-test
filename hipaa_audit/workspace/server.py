from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from hipaa_audit import __version__
from hipaa_audit.ai_assist import suggest_sig_lite_responses
from hipaa_audit.access_reviews import (
    complete_campaign,
    load_campaigns,
    record_decision,
    start_campaign,
)
from hipaa_audit.apps import discover_from_config, link_app, load_inventory, merge_discovered
from hipaa_audit.baas import add_baa, delete_baa, expiring_baas, load_baas, update_baa
from hipaa_audit.controls import PACKAGE_ROOT
from hipaa_audit.auditor_requests import (
    add_message,
    create_request,
    db_path as auditor_db_path,
    get_request,
    list_requests,
    session_token,
    update_request_status,
    verify_auditor_passphrase,
)
from hipaa_audit.devices import load_devices, sync_devices_intune, sync_devices_jamf
from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.identity_users import list_okta_users
from hipaa_audit.notify import maybe_notify_task_assigned, send_questionnaire_email, send_questionnaire_reminder
from hipaa_audit.oauth_connect import (
    OAUTH_PROVIDERS,
    authorize_url,
    exchange_code,
    new_oauth_state,
    oauth_available,
    oauth_redirect_base,
)
from hipaa_audit.pbc_attachments import list_attachments, save_attachment
from hipaa_audit.personnel import (
    ensure_workforce_tokens,
    find_worker_by_token,
    pending_policies_for_employee,
    record_acknowledgment,
    sync_workforce_hris,
)
from hipaa_audit.policy_versions import list_versions, policy_diff, read_archive, snapshot_policy, sync_policy_version_to_acks
from hipaa_audit.questionnaires import (
    find_questionnaire,
    find_questionnaire_by_token,
    load_questionnaires,
    mark_questionnaire_emailed,
    mark_reminder_sent,
    record_questionnaire_open,
    respond_questionnaire,
    send_questionnaire,
)
from hipaa_audit.vendor_portal import publish_vendor_portal, render_vendor_portal_html
from hipaa_audit.report import _load_history, load_history_points
from hipaa_audit.platform.adapters.registry import record_connection_test, test_integration_connection
from hipaa_audit.tasks import assign_task, complete_task, list_open_tasks, load_tasks
from hipaa_audit.vendors import add_vendor, delete_vendor, load_vendors, update_vendor
from hipaa_audit.workspace.secrets import (
    CONNECT_FIELDS,
    apply_workspace_secrets,
    load_secrets,
    merge_secrets,
    secrets_path,
)
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
    if control_id.startswith("HITRUST-"):
        return "HITRUST CSF"
    if control_id.startswith("PCI-"):
        return "PCI DSS"
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
        (src / "compliance" / "baas.example.yaml", repo_path / "compliance" / "baas.yaml"),
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
    config.setdefault("workspace", {})["schedule_hours"] = 1
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
        integrations = integration_status(config)
        ctx.update(
            {
                "flash": flash,
                "flash_error": flash_error,
                "posture_score": report.get("posture", {}).get("score", "—") if report else "—",
                "summary": summary,
                "last_scan": report.get("generated_at") if report else state.last_finished,
                "open_tasks": len(list_open_tasks(repo_path / config.get("tasks_path", "compliance/tasks.yaml"))),
                "integrations_on": sum(1 for i in integrations if i["enabled"]),
                "integrations": integrations,
                "history": _load_history(repo_path),
                "history_points": load_history_points(repo_path),
                "schedule_hours": config.get("workspace", {}).get("schedule_hours", 0),
                "scan_running": state.running,
                "baa_alerts": expiring_baas(
                    repo_path / config.get("baas", {}).get("register_path", "compliance/baas.yaml"),
                    within_days=int(config.get("baas", {}).get("expiry_warning_days", 30)),
                ),
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

    @app.get("/integrations/connect/{integration_id}", response_class=HTMLResponse)
    def integrations_connect(integration_id: str) -> HTMLResponse:
        if not ensure_bootstrapped(repo_path):
            return RedirectResponse("/onboarding", status_code=302)
        fields = CONNECT_FIELDS.get(integration_id)
        if not fields:
            return RedirectResponse("/integrations", status_code=302)
        config = load_workspace_config(repo_path)
        cards = {c["id"]: c for c in integration_status(config)}
        ctx = base_ctx("integrations")
        sec = load_secrets(secrets_path(repo_path, config))
        ctx.update(
            {
                "integration_id": integration_id,
                "integration_name": cards.get(integration_id, {}).get("name", integration_id),
                "fields": fields,
                "oauth_available": oauth_available(integration_id, config=config, secrets=sec),
                "oauth_provider": integration_id if integration_id in OAUTH_PROVIDERS else "",
            }
        )
        return _render("connect.html", **ctx)

    @app.post("/integrations/connect/{integration_id}")
    async def integrations_connect_save(integration_id: str, request: Request) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        form = await request.form()
        updates = {
            k: str(v).strip()
            for k, v in form.items()
            if str(v).strip() and not k.endswith("_note")
        }
        if updates:
            merge_secrets(secrets_path(repo_path, config), updates)
        if integration_id != "aws":
            if integration_id in ("jamf", "intune"):
                config.setdefault("devices", {})["enabled"] = True
            elif integration_id == "rippling":
                config.setdefault("personnel", {})["enabled"] = True
            elif integration_id == "bamboohr":
                config.setdefault("personnel", {})["enabled"] = True
                company = updates.get("bamboohr_company", "")
                if company:
                    config.setdefault("personnel", {}).setdefault("bamboohr", {})["company_domain"] = company
            else:
                config = apply_integration_toggle(config, integration_id, True)
            save_workspace_config(repo_path, config)
        apply_workspace_secrets(repo_path, config)
        result = test_integration_connection(integration_id, config, repo_path=repo_path)
        config = load_workspace_config(repo_path)
        config = record_connection_test(config, integration_id, result)
        save_workspace_config(repo_path, config)
        status = "ok" if result.ok else "fail"
        msg = result.message.replace(" ", "+")[:100]
        return RedirectResponse(f"/integrations?test={status}&msg={msg}", status_code=303)

    @app.post("/integrations/test")
    def integrations_test(integration_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        result = test_integration_connection(integration_id, config, repo_path=repo_path)
        config = record_connection_test(config, integration_id, result)
        save_workspace_config(repo_path, config)
        status = "ok" if result.ok else "fail"
        msg = result.message.replace(" ", "+")[:100]
        return RedirectResponse(f"/integrations?test={status}&msg={msg}", status_code=303)

    @app.get("/integrations/oauth/{provider}/start")
    def oauth_start(provider: str) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        sec = load_secrets(secrets_path(repo_path, config))
        state = new_oauth_state()
        redirect_uri = f"{oauth_redirect_base(config)}/integrations/oauth/{provider}/callback"
        url = authorize_url(provider, redirect_uri=redirect_uri, state=state, config=config, secrets=sec)
        if not url:
            return RedirectResponse(
                f"/integrations/connect/{provider}?flash=OAuth+not+configured",
                status_code=303,
            )
        response = RedirectResponse(url, status_code=302)
        response.set_cookie("oauth_state", state, httponly=True, max_age=600, samesite="lax")
        return response

    @app.get("/integrations/oauth/{provider}/callback")
    def oauth_callback(
        provider: str,
        request: Request,
        code: str = "",
        state: str = "",
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        if not code or state != request.cookies.get("oauth_state"):
            return RedirectResponse(f"/integrations/connect/{provider}?flash=OAuth+state+mismatch", status_code=303)
        sec = load_secrets(secrets_path(repo_path, config))
        redirect_uri = f"{oauth_redirect_base(config)}/integrations/oauth/{provider}/callback"
        token, err = exchange_code(
            provider,
            code=code,
            redirect_uri=redirect_uri,
            config=config,
            secrets=sec,
        )
        if err or not token:
            return RedirectResponse(
                f"/integrations/connect/{provider}?flash=OAuth+failed",
                status_code=303,
            )
        meta = OAUTH_PROVIDERS.get(provider, {})
        token_key = meta.get("token_secret", "github_token")
        merge_secrets(secrets_path(repo_path, config), {token_key: token})
        if provider == "github":
            config.setdefault("github", {})["enabled"] = True
            save_workspace_config(repo_path, config)
        elif provider == "gitlab":
            config.setdefault("gitlab", {})["enabled"] = True
            save_workspace_config(repo_path, config)
        apply_workspace_secrets(repo_path, config)
        result = test_integration_connection(provider, config, repo_path=repo_path)
        config = load_workspace_config(repo_path)
        config = record_connection_test(config, provider, result)
        save_workspace_config(repo_path, config)
        status = "ok" if result.ok else "fail"
        response = RedirectResponse(f"/integrations/connect/{provider}?test={status}", status_code=303)
        response.delete_cookie("oauth_state")
        return response

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
        apply_workspace_secrets(repo_path, config)
        tasks_path = repo_path / config.get("tasks_path", "compliance/tasks.yaml")
        data = load_tasks(tasks_path)
        task = next((t for t in data.get("tasks", []) if t.get("id") == task_id), None)
        if task and assign_task(tasks_path, task_id, owner):
            task["owner"] = owner
            maybe_notify_task_assigned(config=config, task=task, repo_path=repo_path)
            return RedirectResponse("/tasks?flash=Owner+updated", status_code=303)
        return RedirectResponse("/tasks?flash=Task+not+found", status_code=303)

    @app.get("/personnel", response_class=HTMLResponse)
    def personnel(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        ack_path = repo_path / config.get("personnel", {}).get(
            "acknowledgments_path", "compliance/acknowledgments.yaml"
        )
        training_path = repo_path / config.get("personnel", {}).get("training_csv", "compliance/training-log.csv")
        ack_count = 0
        workforce: list[dict[str, Any]] = []
        if ack_path.exists():
            import yaml

            data = ensure_workforce_tokens(ack_path)
            ack_count = len(data.get("acknowledgments", []))
            workforce = data.get("workforce", [])
        training_rows = 0
        if training_path.exists():
            training_rows = max(0, len(training_path.read_text().strip().splitlines()) - 1)
        ctx = base_ctx("personnel")
        ctx.update(
            {
                "ack_count": ack_count,
                "training_rows": training_rows,
                "workforce": workforce,
                "flash": request.query_params.get("flash", ""),
                "flash_error": request.query_params.get("flash_error", ""),
            }
        )
        return _render("personnel.html", **ctx)

    @app.post("/personnel/sync-rippling")
    def personnel_sync_rippling() -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        ack_path = repo_path / config.get("personnel", {}).get(
            "acknowledgments_path", "compliance/acknowledgments.yaml"
        )
        from hipaa_audit.platform.adapters.rippling import RipplingAdapter

        workers = RipplingAdapter().discover(config)
        if not workers:
            return RedirectResponse("/personnel?flash_error=No+workforce+from+Rippling", status_code=303)
        count = sync_workforce_hris(ack_path, workers)
        return RedirectResponse(f"/personnel?flash=Synced+{count}+employee(s)+from+Rippling", status_code=303)

    @app.post("/personnel/sync-bamboohr")
    def personnel_sync_bamboohr() -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        ack_path = repo_path / config.get("personnel", {}).get(
            "acknowledgments_path", "compliance/acknowledgments.yaml"
        )
        from hipaa_audit.platform.adapters.bamboohr import BambooHRAdapter

        workers = BambooHRAdapter().discover(config)
        if not workers:
            return RedirectResponse("/personnel?flash_error=No+workforce+from+BambooHR", status_code=303)
        count = sync_workforce_hris(ack_path, workers)
        return RedirectResponse(f"/personnel?flash=Synced+{count}+employee(s)+from+BambooHR", status_code=303)

    @app.get("/vendors", response_class=HTMLResponse)
    def vendors_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        ctx = base_ctx("vendors")
        ctx["vendors"] = load_vendors(vpath).get("vendors", [])
        ctx["questionnaires"] = load_questionnaires(qpath).get("questionnaires", [])
        ctx["flash"] = request.query_params.get("flash", "")
        ctx["ai_enabled"] = config.get("ai_assist", {}).get("enabled", False)
        ctx["assist_result"] = None
        return _render("vendors.html", **ctx)

    @app.post("/vendors/assist")
    async def vendors_assist(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        form = await request.form()
        vendor_text = str(form.get("vendor_text", ""))
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        result = suggest_sig_lite_responses(vendor_text, config)
        ctx = base_ctx("vendors")
        ctx["vendors"] = load_vendors(vpath).get("vendors", [])
        ctx["questionnaires"] = load_questionnaires(qpath).get("questionnaires", [])
        ctx["ai_enabled"] = config.get("ai_assist", {}).get("enabled", False)
        ctx["assist_result"] = result
        ctx["vendor_text"] = vendor_text
        ctx["flash"] = ""
        return _render("vendors.html", **ctx)

    @app.post("/vendors/add")
    def vendors_add(
        name: str = Form(...),
        phi_access: str = Form("none"),
        risk_tier: str = Form("medium"),
        baa_executed: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        add_vendor(
            vpath,
            name=name,
            phi_access=phi_access,
            risk_tier=risk_tier,
            baa_executed=baa_executed == "on",
        )
        return RedirectResponse("/vendors?flash=Vendor+added", status_code=303)

    @app.post("/vendors/update")
    def vendors_update(
        vendor_id: str = Form(...),
        name: str = Form(...),
        phi_access: str = Form(...),
        risk_tier: str = Form(...),
        baa_executed: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        update_vendor(
            vpath,
            vendor_id,
            name=name,
            phi_access=phi_access,
            risk_tier=risk_tier,
            baa_executed=baa_executed == "on",
        )
        return RedirectResponse("/vendors?flash=Vendor+updated", status_code=303)

    @app.post("/vendors/delete")
    def vendors_delete(vendor_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        if delete_vendor(vpath, vendor_id):
            return RedirectResponse("/vendors?flash=Vendor+removed", status_code=303)
        return RedirectResponse("/vendors?flash=Vendor+not+found", status_code=303)

    @app.post("/vendors/questionnaire/send")
    def vendors_questionnaire_send(
        vendor_id: str = Form(...),
        contact: str = Form(...),
        due_days: int = Form(30),
        send_email: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        entry = send_questionnaire(qpath, vpath, vendor_id=vendor_id, contact=contact, due_days=due_days)
        if not entry:
            return RedirectResponse("/vendors?flash=Vendor+not+found", status_code=303)
        publish_vendor_portal(repo_path=repo_path, config=config, questionnaire=entry)
        if send_email == "on":
            token = entry.get("portal_token", entry["id"])
            portal_url = f"http://127.0.0.1:8787/portals/vendor/{token}"
            err = send_questionnaire_email(
                config=config,
                contact=contact,
                questionnaire=entry,
                portal_url=portal_url,
                repo_path=repo_path,
            )
            if err:
                return RedirectResponse(f"/vendors?flash=Questionnaire+created+({err})", status_code=303)
            mark_questionnaire_emailed(qpath, entry["id"])
        return RedirectResponse("/vendors?flash=Questionnaire+sent", status_code=303)

    @app.post("/vendors/questionnaire/remind")
    def vendors_questionnaire_remind(questionnaire_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        entry = find_questionnaire(qpath, questionnaire_id)
        if not entry:
            return RedirectResponse("/vendors?flash=Questionnaire+not+found", status_code=303)
        token = entry.get("portal_token", entry["id"])
        err = send_questionnaire_reminder(
            config=config,
            questionnaire=entry,
            portal_url=f"http://127.0.0.1:8787/portals/vendor/{token}",
            repo_path=repo_path,
        )
        if err:
            return RedirectResponse(f"/vendors?flash=Reminder+failed+({err})", status_code=303)
        mark_reminder_sent(qpath, questionnaire_id)
        return RedirectResponse("/vendors?flash=Reminder+sent", status_code=303)

    @app.get("/baas", response_class=HTMLResponse)
    def baas_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        bpath = repo_path / config.get("baas", {}).get("register_path", "compliance/baas.yaml")
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        ctx = base_ctx("baas")
        ctx["baas"] = load_baas(bpath).get("baas", [])
        ctx["vendors"] = load_vendors(vpath).get("vendors", [])
        ctx["expiring"] = expiring_baas(
            bpath, within_days=int(config.get("baas", {}).get("expiry_warning_days", 30))
        )
        ctx["flash"] = request.query_params.get("flash", "")
        return _render("baas.html", **ctx)

    @app.post("/baas/add")
    def baas_add(
        vendor_id: str = Form(...),
        vendor_name: str = Form(...),
        effective_date: str = Form(...),
        expiry_date: str = Form(...),
        document_path: str = Form(""),
        signed_by: str = Form(""),
        notes: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        bpath = repo_path / config.get("baas", {}).get("register_path", "compliance/baas.yaml")
        add_baa(
            bpath,
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            effective_date=effective_date,
            expiry_date=expiry_date,
            document_path=document_path,
            signed_by=signed_by,
            notes=notes,
        )
        return RedirectResponse("/baas?flash=BAA+added", status_code=303)

    @app.post("/baas/update")
    def baas_update(
        baa_id: str = Form(...),
        expiry_date: str = Form(...),
        status: str = Form("active"),
        document_path: str = Form(""),
        notes: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        bpath = repo_path / config.get("baas", {}).get("register_path", "compliance/baas.yaml")
        if update_baa(
            bpath,
            baa_id,
            expiry_date=expiry_date,
            status=status,
            document_path=document_path,
            notes=notes,
        ):
            return RedirectResponse("/baas?flash=BAA+updated", status_code=303)
        return RedirectResponse("/baas?flash=BAA+not+found", status_code=303)

    @app.post("/baas/delete")
    def baas_delete(baa_id: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        bpath = repo_path / config.get("baas", {}).get("register_path", "compliance/baas.yaml")
        if delete_baa(bpath, baa_id):
            return RedirectResponse("/baas?flash=BAA+removed", status_code=303)
        return RedirectResponse("/baas?flash=BAA+not+found", status_code=303)

    @app.get("/saas", response_class=HTMLResponse)
    def saas_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        ipath = repo_path / config.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        ctx = base_ctx("saas")
        inv = load_inventory(ipath)
        ctx["apps"] = inv.get("apps", [])
        ctx["discovered_at"] = inv.get("discovered_at")
        ctx["vendors"] = load_vendors(vpath).get("vendors", [])
        ctx["flash"] = request.query_params.get("flash", "")
        ctx["flash_error"] = request.query_params.get("flash_error", "")
        return _render("saas.html", **ctx)

    @app.post("/saas/discover")
    def saas_discover() -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        ipath = repo_path / config.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
        try:
            discovered, source = discover_from_config(config)
            if not discovered:
                return RedirectResponse(
                    "/saas?flash_error=Enable+Okta+or+Google+and+add+credentials",
                    status_code=303,
                )
            merge_discovered(ipath, discovered, source=source)
            return RedirectResponse(f"/saas?flash=Discovered+{len(discovered)}+apps", status_code=303)
        except Exception as exc:  # noqa: BLE001
            return RedirectResponse(f"/saas?flash_error={str(exc)[:80]}", status_code=303)

    @app.post("/saas/link")
    def saas_link(
        app_id: str = Form(...),
        vendor_id: str = Form(...),
        phi_risk: str = Form("unknown"),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        ipath = repo_path / config.get("saas_inventory", {}).get("register_path", "compliance/saas-inventory.yaml")
        if link_app(ipath, app_id, vendor_id, phi_risk=phi_risk):
            return RedirectResponse("/saas?flash=App+linked", status_code=303)
        return RedirectResponse("/saas?flash_error=App+not+found", status_code=303)

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
        apply_workspace_secrets(repo_path, config)
        ctx["campaigns"] = _campaign_rows(data)
        ctx["idp_principals"] = list_okta_users(config)
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
    def devices_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        path = repo_path / config.get("devices", {}).get("register_path", "compliance/devices.yaml")
        data = load_devices(path)
        ctx = base_ctx("devices")
        ctx["devices"] = data.get("devices", [])
        ctx["imported_at"] = data.get("imported_at")
        ctx["flash"] = request.query_params.get("flash", "")
        ctx["flash_error"] = request.query_params.get("flash_error", "")
        return _render("devices.html", **ctx)

    @app.post("/devices/sync")
    def devices_sync(source: str = Form("jamf")) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        path = repo_path / config.get("devices", {}).get("register_path", "compliance/devices.yaml")
        try:
            if source == "intune":
                count = sync_devices_intune(path, config)
                label = "Intune"
            else:
                count = sync_devices_jamf(path, config)
                label = "Jamf"
            if count:
                return RedirectResponse(f"/devices?flash=Synced+{count}+device(s)+from+{label}", status_code=303)
            return RedirectResponse(f"/devices?flash_error=No+devices+from+{label}", status_code=303)
        except Exception as exc:  # noqa: BLE001
            return RedirectResponse(f"/devices?flash_error={str(exc)[:80]}", status_code=303)

    @app.get("/policies", response_class=HTMLResponse)
    def policies_page() -> HTMLResponse:
        config = load_workspace_config(repo_path)
        pdir = repo_path / config.get("policy_dir", "policies")
        policies = sorted(p.name for p in pdir.glob("*.md")) if pdir.is_dir() else []
        ctx = base_ctx("policies")
        ctx["policies"] = policies
        return _render("policies.html", **ctx)

    @app.get("/policies/edit/{policy_name}", response_class=HTMLResponse)
    def policies_edit(policy_name: str, request: Request) -> HTMLResponse:
        if ".." in policy_name or "/" in policy_name or not policy_name.endswith(".md"):
            return RedirectResponse("/policies", status_code=302)
        config = load_workspace_config(repo_path)
        pdir = repo_path / config.get("policy_dir", "policies")
        path = pdir / policy_name
        if not path.is_file():
            return RedirectResponse("/policies", status_code=302)
        ctx = base_ctx("policies")
        ctx.update(
            {
                "policy_name": policy_name,
                "content": path.read_text(),
                "versions": list_versions(pdir, policy_name),
                "flash": request.query_params.get("flash", ""),
            }
        )
        return _render("policy_edit.html", **ctx)

    @app.post("/policies/edit/{policy_name}")
    def policies_save(
        policy_name: str,
        content: str = Form(...),
        summary: str = Form(""),
        bump_version: str = Form(""),
    ) -> RedirectResponse:
        if ".." in policy_name or "/" in policy_name or not policy_name.endswith(".md"):
            return RedirectResponse("/policies", status_code=302)
        config = load_workspace_config(repo_path)
        pdir = repo_path / config.get("policy_dir", "policies")
        path = pdir / policy_name
        if not path.is_file():
            return RedirectResponse("/policies", status_code=302)
        meta = snapshot_policy(
            pdir,
            policy_name,
            new_content=content,
            summary=summary,
            bump_version=bump_version == "on",
        )
        if bump_version == "on":
            ack_path = repo_path / config.get("personnel", {}).get(
                "acknowledgments_path", "compliance/acknowledgments.yaml"
            )
            sync_policy_version_to_acks(ack_path, policy_name, meta["version"])
        return RedirectResponse(
            f"/policies/edit/{policy_name}?flash=Saved+v{meta['version']}",
            status_code=303,
        )

    @app.get("/policies/diff/{policy_name}", response_class=HTMLResponse)
    def policies_diff(policy_name: str, left: str = "current", right: str = "") -> HTMLResponse:
        if ".." in policy_name or "/" in policy_name:
            return RedirectResponse("/policies", status_code=302)
        config = load_workspace_config(repo_path)
        pdir = repo_path / config.get("policy_dir", "policies")
        versions = list_versions(pdir, policy_name)
        if not right and versions:
            right = versions[-1].get("archive", "current")
        diff_text = policy_diff(pdir, policy_name, left, right or "current")
        ctx = base_ctx("policies")
        ctx.update({"policy_name": policy_name, "diff_text": diff_text, "left": left, "right": right})
        return _render("policy_diff.html", **ctx)

    @app.get("/audits", response_class=HTMLResponse)
    def audits_page(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        trust = repo_path / config.get("trust_center", {}).get("output_dir", "compliance/trust-center") / "index.html"
        auditor = repo_path / config.get("auditor_portal", {}).get("output_dir", "compliance/auditor-portal") / "index.html"
        adb = auditor_db_path(repo_path, config)
        ctx = base_ctx("audits")
        ctx.update(
            {
                "flash": request.query_params.get("flash", ""),
                "trust_exists": trust.exists(),
                "trust_public_url": config.get("trust_center", {}).get("public_url", "").strip(),
                "auditor_exists": auditor.exists(),
                "pbc_requests": list_requests(adb),
            }
        )
        return _render("audits.html", **ctx)

    @app.post("/audits/pbc/create")
    def audits_pbc_create(
        title: str = Form(...),
        control_ref: str = Form(""),
        due_date: str = Form(""),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        adb = auditor_db_path(repo_path, config)
        create_request(adb, title=title, control_ref=control_ref, due_date=due_date)
        return RedirectResponse("/audits?flash=PBC+request+created", status_code=303)

    @app.get("/audits/pbc/{request_id}", response_class=HTMLResponse)
    def audits_pbc_detail(request_id: str) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        adb = auditor_db_path(repo_path, config)
        req = get_request(adb, request_id)
        if not req:
            return RedirectResponse("/audits", status_code=302)
        ctx = base_ctx("audits")
        ctx["pbc"] = req
        ctx["attachments"] = list_attachments(repo_path, request_id)
        return _render("auditor_pbc.html", **ctx)

    @app.post("/audits/pbc/{request_id}/message")
    async def audits_pbc_message(
        request_id: str,
        author: str = Form(...),
        body: str = Form(...),
        file: UploadFile | None = File(None),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        adb = auditor_db_path(repo_path, config)
        attachment_path = ""
        if file and file.filename:
            data = await file.read()
            attachment_path = save_attachment(repo_path, request_id, file.filename, data)
        add_message(
            adb,
            request_id=request_id,
            author=author,
            author_role="org",
            body=body,
            attachment_path=attachment_path,
        )
        return RedirectResponse(f"/audits/pbc/{request_id}?flash=Reply+posted", status_code=303)

    @app.get("/audits/pbc/{request_id}/attachment/{filename}", response_model=None)
    def audits_pbc_attachment(request_id: str, filename: str):
        if ".." in filename:
            return RedirectResponse("/audits", status_code=302)
        path = repo_path / "compliance" / "pbc-attachments" / request_id.replace("/", "") / filename
        if path.is_file():
            return FileResponse(path)
        return RedirectResponse("/audits", status_code=302)

    @app.post("/audits/pbc/{request_id}/status")
    def audits_pbc_status(request_id: str, status: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        adb = auditor_db_path(repo_path, config)
        update_request_status(adb, request_id, status)
        return RedirectResponse("/audits?flash=PBC+status+updated", status_code=303)

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

    @app.post("/portals/auditor/login")
    def portal_auditor_login(passphrase: str = Form(...)) -> Response:
        config = load_workspace_config(repo_path)
        if not verify_auditor_passphrase(config, passphrase):
            return RedirectResponse("/portals/auditor/requests?error=1", status_code=303)
        resp = RedirectResponse("/portals/auditor/requests", status_code=303)
        resp.set_cookie("auditor_session", session_token(passphrase), httponly=True, samesite="lax")
        return resp

    @app.get("/portals/auditor/requests", response_class=HTMLResponse)
    def portal_auditor_requests(request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        import os

        env_key = config.get("auditor_portal", {}).get("access_passphrase_env", "AUDITOR_PORTAL_PASSPHRASE")
        expected = os.environ.get(env_key, "")
        if expected and request.cookies.get("auditor_session") != session_token(expected):
            return _render(
                "auditor_login.html",
                **{**base_ctx("audits"), "error": request.query_params.get("error", "")},
            )
        adb = auditor_db_path(repo_path, config)
        ctx = base_ctx("audits")
        ctx["pbc_requests"] = list_requests(adb)
        return _render("auditor_requests.html", **ctx)

    @app.get("/portals/auditor/requests/{request_id}", response_class=HTMLResponse)
    def portal_auditor_request_detail(request_id: str, request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        import os

        env_key = config.get("auditor_portal", {}).get("access_passphrase_env", "AUDITOR_PORTAL_PASSPHRASE")
        expected = os.environ.get(env_key, "")
        if expected and request.cookies.get("auditor_session") != session_token(expected):
            return RedirectResponse("/portals/auditor/requests?error=1", status_code=302)
        adb = auditor_db_path(repo_path, config)
        req = get_request(adb, request_id)
        if not req:
            return RedirectResponse("/portals/auditor/requests", status_code=302)
        ctx = base_ctx("audits")
        ctx["pbc"] = req
        ctx["auditor_view"] = True
        ctx["flash"] = request.query_params.get("flash", "")
        return _render("auditor_pbc.html", **ctx)

    @app.post("/portals/auditor/requests/{request_id}/message")
    def portal_auditor_message(
        request_id: str,
        author: str = Form(...),
        body: str = Form(...),
    ) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        adb = auditor_db_path(repo_path, config)
        add_message(adb, request_id=request_id, author=author, author_role="auditor", body=body)
        return RedirectResponse(f"/portals/auditor/requests/{request_id}?flash=Reply+posted", status_code=303)

    @app.get("/portals/ack/{token}", response_class=HTMLResponse)
    def portal_ack(token: str, request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        ack_path = repo_path / config.get("personnel", {}).get(
            "acknowledgments_path", "compliance/acknowledgments.yaml"
        )
        worker = find_worker_by_token(ack_path, token)
        if not worker:
            return HTMLResponse("<p>Invalid acknowledgment link.</p>", status_code=404)
        import yaml

        data = yaml.safe_load(ack_path.read_text()) or {}
        employee_id = worker.get("id") or worker.get("employee_id", "")
        pending = pending_policies_for_employee(data, employee_id)
        ctx = {
            "org_name": config.get("org_name", "Organization"),
            "employee_id": employee_id,
            "pending": pending,
            "token": token,
            "flash": request.query_params.get("flash", ""),
            "done": request.query_params.get("done") == "1",
        }
        return _render("ack_portal.html", **ctx)

    @app.post("/portals/ack/{token}")
    def portal_ack_submit(token: str, policy: str = Form(...), version: str = Form(...)) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        ack_path = repo_path / config.get("personnel", {}).get(
            "acknowledgments_path", "compliance/acknowledgments.yaml"
        )
        worker = find_worker_by_token(ack_path, token)
        if not worker:
            return RedirectResponse("/personnel", status_code=303)
        employee_id = worker.get("id") or worker.get("employee_id", "")
        record_acknowledgment(ack_path, employee_id=employee_id, policy=policy, version=version)
        return RedirectResponse(f"/portals/ack/{token}?flash=Acknowledged", status_code=303)

    @app.get("/portals/vendor/{token}", response_class=HTMLResponse)
    def portal_vendor(token: str, request: Request) -> HTMLResponse:
        config = load_workspace_config(repo_path)
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        entry = find_questionnaire_by_token(qpath, token)
        if not entry:
            return HTMLResponse("<p>Questionnaire not found.</p>", status_code=404)
        record_questionnaire_open(qpath, token)
        html = render_vendor_portal_html(
            config=config,
            questionnaire=entry,
            submit_url=f"/portals/vendor/{token}",
            flash=request.query_params.get("flash", ""),
            submitted=request.query_params.get("submitted") == "1",
        )
        return HTMLResponse(html)

    @app.post("/portals/vendor/{token}")
    async def portal_vendor_submit(token: str, request: Request) -> RedirectResponse:
        config = load_workspace_config(repo_path)
        qpath = repo_path / config.get("vendors", {}).get("questionnaires_path", "compliance/vendor-questionnaires.yaml")
        vpath = repo_path / config.get("vendors", {}).get("register_path", "compliance/vendors.yaml")
        entry = find_questionnaire_by_token(qpath, token)
        if not entry:
            return RedirectResponse("/vendors", status_code=303)
        form = await request.form()
        from hipaa_audit.vendors import SIG_LITE_KEYS

        responses = {k: form.get(k) == "true" for k in SIG_LITE_KEYS if k in form}
        reviewer = str(form.get("reviewer", ""))
        respond_questionnaire(qpath, vpath, entry["id"], responses, reviewer=reviewer)
        return RedirectResponse(f"/portals/vendor/{token}?submitted=1", status_code=303)

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
    async def settings_save(request: Request) -> RedirectResponse:
        form = await request.form()
        config = load_workspace_config(repo_path)
        config["org_name"] = str(form.get("org_name", ""))
        config.setdefault("github", {})["repo"] = str(form.get("github_repo", ""))
        config.setdefault("gitlab", {})["project"] = str(form.get("gitlab_project", ""))
        config.setdefault("identity", {}).setdefault("okta", {})["domain"] = str(form.get("okta_domain", ""))
        config.setdefault("identity", {}).setdefault("azure", {})["enabled"] = form.get("azure_enabled") == "on"
        config.setdefault("aws", {})["multi_region"] = form.get("aws_multi_region") == "on"
        regions_text = str(form.get("aws_regions", "")).strip()
        if regions_text:
            config.setdefault("aws", {})["regions"] = [
                r.strip() for r in regions_text.replace(",", " ").split() if r.strip()
            ]
        config.setdefault("frameworks", {})["soc2"] = form.get("soc2") == "on"
        config.setdefault("frameworks", {})["iso27001"] = form.get("iso27001") == "on"
        config.setdefault("frameworks", {})["hitrust"] = form.get("hitrust") == "on"
        config.setdefault("frameworks", {})["pci"] = form.get("pci") == "on"
        integrations = config.setdefault("integrations", {})
        integrations.setdefault("prowler_azure", {})["enabled"] = form.get("prowler_azure") == "on"
        integrations.setdefault("prowler_gcp", {})["enabled"] = form.get("prowler_gcp") == "on"
        integrations.setdefault("snyk", {})["enabled"] = form.get("snyk_enabled") == "on"
        config.setdefault("ai_assist", {})["enabled"] = form.get("ai_assist_enabled") == "on"
        config.setdefault("ai_assist", {})["use_llm"] = form.get("ai_assist_llm") == "on"
        config.setdefault("trust_center", {})["public_url"] = str(form.get("trust_public_url", "")).strip()
        config.setdefault("workspace", {})["schedule_hours"] = max(
            0, min(168, int(form.get("schedule_hours", 0) or 0))
        )
        slack = config.setdefault("notifications", {}).setdefault("slack", {})
        slack["enabled"] = form.get("slack_enabled") == "on"
        slack["notify_on_fail"] = form.get("slack_notify_fail") == "on"
        slack["notify_on_task_assign"] = form.get("slack_notify_task_assign") == "on"
        slack["min_score_drop"] = float(form.get("slack_min_drop", 5) or 5)
        webhook = str(form.get("slack_webhook", "")).strip()
        if webhook:
            merge_secrets(secrets_path(repo_path, config), {"slack_webhook_url": webhook})
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
