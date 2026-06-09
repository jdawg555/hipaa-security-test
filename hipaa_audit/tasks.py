from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.models import AuditReport, CheckStatus

DEFAULT_TASKS_PATH = Path("compliance/tasks.yaml")


def load_tasks(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"tasks": []}
    return yaml.safe_load(path.read_text()) or {"tasks": []}


def save_tasks(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def sync_from_report(
    report: AuditReport,
    tasks_path: Path,
    *,
    default_owner: str = "security@example.com",
    due_days: int = 14,
) -> list[dict[str, Any]]:
    data = load_tasks(tasks_path)
    existing = {(t.get("control_id"), t.get("check_id")) for t in data.get("tasks", [])}
    due = (datetime.now(UTC) + timedelta(days=due_days)).strftime("%Y-%m-%d")
    created: list[dict[str, Any]] = []
    seq = len(data.get("tasks", [])) + 1

    for cr in report.controls:
        for result in cr.results:
            if result.status not in (CheckStatus.FAIL, CheckStatus.ERROR, CheckStatus.WARN):
                continue
            key = (cr.control.id, result.check_id)
            if key in existing:
                continue
            task = {
                "id": f"TASK-{seq:04d}",
                "control_id": cr.control.id,
                "check_id": result.check_id,
                "title": result.title or cr.control.title,
                "message": result.message,
                "owner": default_owner,
                "due_date": due,
                "status": "open",
                "created_at": datetime.now(UTC).isoformat(),
                "remediation": result.remediation,
            }
            data.setdefault("tasks", []).append(task)
            created.append(task)
            existing.add(key)
            seq += 1

    if created:
        save_tasks(tasks_path, data)
    return created


def list_open_tasks(tasks_path: Path) -> list[dict[str, Any]]:
    return [t for t in load_tasks(tasks_path).get("tasks", []) if t.get("status") == "open"]


def complete_task(tasks_path: Path, task_id: str) -> bool:
    data = load_tasks(tasks_path)
    for task in data.get("tasks", []):
        if task.get("id") == task_id:
            task["status"] = "done"
            task["completed_at"] = datetime.now(UTC).isoformat()
            save_tasks(tasks_path, data)
            return True
    return False
