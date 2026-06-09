from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hipaa_audit.auditor_portal import publish_auditor_portal
from hipaa_audit.export_auditor import build_auditor_bundle
from hipaa_audit.engine import run_audit
from hipaa_audit.posture import compute_posture, record_history
from hipaa_audit.report import write_reports
from hipaa_audit.tasks import sync_from_report
from hipaa_audit.trust_center import publish_trust_center
from hipaa_audit.workspace.config_store import load_workspace_config
from hipaa_audit.workspace.secrets import apply_workspace_secrets


@dataclass
class ScanState:
    running: bool = False
    last_started: str | None = None
    last_finished: str | None = None
    last_error: str | None = None
    last_score: float | None = None


_state = ScanState()
_lock = threading.Lock()


def get_scan_state() -> ScanState:
    return _state


def latest_report(repo_path: Path) -> dict[str, Any] | None:
    report_path = repo_path / "evidence" / "latest" / "audit-report.json"
    if not report_path.exists():
        return None
    return json.loads(report_path.read_text())


def run_scan_job(repo_path: Path, *, publish_portals: bool = True) -> dict[str, Any]:
    with _lock:
        if _state.running:
            raise RuntimeError("Scan already in progress")
        _state.running = True
        _state.last_started = datetime.now(UTC).isoformat()
        _state.last_error = None

    try:
        repo_path = repo_path.resolve()
        config = load_workspace_config(repo_path)
        apply_workspace_secrets(repo_path, config)
        config.setdefault("org_name", repo_path.name)
        devices_path = repo_path / config.get("devices", {}).get("register_path", "compliance/devices.yaml")
        if config.get("devices", {}).get("jamf_sync"):
            try:
                from hipaa_audit.devices import sync_devices_jamf

                sync_devices_jamf(devices_path, config)
            except Exception:  # noqa: BLE001
                pass
        if config.get("devices", {}).get("intune_sync"):
            try:
                from hipaa_audit.devices import sync_devices_intune

                sync_devices_intune(devices_path, config)
            except Exception:  # noqa: BLE001
                pass
        output = repo_path / "evidence" / "latest"
        report = run_audit(repo_path, config=config, evidence_dir=output)
        write_reports(report, output)
        posture = compute_posture(report)
        record_history(report, repo_path)
        sync_from_report(
            report,
            repo_path / config.get("tasks_path", "compliance/tasks.yaml"),
            default_owner=config.get("tasks", {}).get("default_owner", "security@example.com"),
            due_days=int(config.get("tasks", {}).get("due_days", 14)),
        )
        try:
            from hipaa_audit.notify import send_questionnaire_reminder
            from hipaa_audit.questionnaires import mark_reminder_sent, questionnaires_needing_reminder

            qpath = repo_path / config.get("vendors", {}).get(
                "questionnaires_path", "compliance/vendor-questionnaires.yaml"
            )
            for q in questionnaires_needing_reminder(qpath):
                token = q.get("portal_token", q["id"])
                portal_url = f"http://127.0.0.1:8787/portals/vendor/{token}"
                err = send_questionnaire_reminder(
                    config=config,
                    questionnaire=q,
                    portal_url=portal_url,
                    repo_path=repo_path,
                )
                if not err:
                    mark_reminder_sent(qpath, q["id"])
        except Exception:  # noqa: BLE001
            pass

        if config.get("auditor_portal", {}).get("auto_export_on_scan"):
            try:
                out = repo_path / "evidence" / "latest" / "auditor-bundle.zip"
                build_auditor_bundle(repo_path, out, config=config)
            except Exception:  # noqa: BLE001
                pass

        if publish_portals:
            report_json = output / "audit-report.json"
            try:
                publish_trust_center(repo_path=repo_path, config=config, report_json=report_json)
                publish_auditor_portal(repo_path=repo_path, config=config, report_json=report_json, access_passphrase="")
            except Exception:  # noqa: BLE001 — portals are best-effort
                pass

        with _lock:
            _state.last_finished = datetime.now(UTC).isoformat()
            _state.last_score = posture["score"]
        return {"score": posture["score"], "summary": report.summary}
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _state.last_error = str(exc)
        raise
    finally:
        with _lock:
            _state.running = False
