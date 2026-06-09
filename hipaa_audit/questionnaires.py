from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.vendors import SIG_LITE_KEYS, load_vendors, review_vendor


def load_questionnaires(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"questionnaires": []}
    return yaml.safe_load(path.read_text()) or {"questionnaires": []}


def save_questionnaires(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def send_questionnaire(
    q_path: Path,
    vendors_path: Path,
    *,
    vendor_id: str,
    contact: str,
    due_days: int = 30,
) -> dict[str, Any] | None:
    vendors = load_vendors(vendors_path)
    vendor = next((v for v in vendors.get("vendors", []) if v.get("id") == vendor_id), None)
    if not vendor:
        return None

    data = load_questionnaires(q_path)
    seq = len(data.get("questionnaires", [])) + 1
    due = (datetime.now(UTC) + timedelta(days=due_days)).strftime("%Y-%m-%d")
    entry = {
        "id": f"QNR-{seq:03d}",
        "vendor_id": vendor_id,
        "vendor_name": vendor.get("name"),
        "contact": contact,
        "sent_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "due_date": due,
        "status": "pending",
        "responded_at": None,
        "portal_token": secrets.token_urlsafe(16),
        "email_sent_at": None,
        "opened_at": None,
        "responses": {k: None for k in SIG_LITE_KEYS},
    }
    data.setdefault("questionnaires", []).append(entry)
    save_questionnaires(q_path, data)
    return entry


def respond_questionnaire(
    q_path: Path,
    vendors_path: Path,
    questionnaire_id: str,
    responses: dict[str, Any],
    *,
    reviewer: str = "",
) -> bool:
    data = load_questionnaires(q_path)
    for q in data.get("questionnaires", []):
        if q.get("id") != questionnaire_id:
            continue
        q["responses"].update(responses)
        q["status"] = "responded"
        q["responded_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
        save_questionnaires(q_path, data)
        review_vendor(vendors_path, q["vendor_id"], responses, reviewer=reviewer)
        return True
    return False


def assess_questionnaires(q_path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_questionnaires(q_path)
    items = data.get("questionnaires", [])
    if not items:
        return "manual", "No outbound questionnaires — hipaa-audit vendor send", []

    now = datetime.now(UTC).date()
    issues: list[str] = []
    for q in items:
        if q.get("status") == "responded":
            continue
        due = _parse_date(q.get("due_date", ""))
        if due and now > due:
            issues.append(f"{q['id']}: overdue ({q.get('vendor_name')})")
        elif q.get("status") == "pending":
            issues.append(f"{q['id']}: awaiting response ({q.get('vendor_name')})")

    if not issues:
        return "pass", "All vendor questionnaires responded", []
    if len(issues) <= 2:
        return "warn", "; ".join(issues[:3]), issues
    return "fail", f"{len(issues)} questionnaire gap(s)", issues


def import_response(
    q_path: Path,
    vendors_path: Path,
    questionnaire_id: str,
    response_path: Path,
) -> bool:
    data = parse_response_yaml(response_path)
    if data.get("questionnaire_id") and data["questionnaire_id"] != questionnaire_id:
        return False
    responses = data.get("responses") or {}
    reviewer = data.get("reviewer", "")
    return respond_questionnaire(
        q_path,
        vendors_path,
        questionnaire_id,
        responses,
        reviewer=reviewer,
    )


def parse_response_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def find_questionnaire(q_path: Path, questionnaire_id: str) -> dict[str, Any] | None:
    data = load_questionnaires(q_path)
    return next((q for q in data.get("questionnaires", []) if q.get("id") == questionnaire_id), None)


def find_questionnaire_by_token(q_path: Path, token: str) -> dict[str, Any] | None:
    data = load_questionnaires(q_path)
    return next((q for q in data.get("questionnaires", []) if q.get("portal_token") == token), None)


def record_questionnaire_open(q_path: Path, token: str) -> bool:
    data = load_questionnaires(q_path)
    for q in data.get("questionnaires", []):
        if q.get("portal_token") != token:
            continue
        if not q.get("opened_at"):
            q["opened_at"] = datetime.now(UTC).isoformat()
            save_questionnaires(q_path, data)
        return True
    return False


def questionnaires_needing_reminder(q_path: Path, *, days_before_due: int = 7) -> list[dict[str, Any]]:
    data = load_questionnaires(q_path)
    now = datetime.now(UTC).date()
    due_cutoff = now + timedelta(days=days_before_due)
    items: list[dict[str, Any]] = []
    for q in data.get("questionnaires", []):
        if q.get("status") != "pending":
            continue
        due = _parse_date(q.get("due_date", ""))
        if due and now <= due <= due_cutoff and not q.get("reminder_sent_at"):
            items.append(q)
    return items


def mark_reminder_sent(q_path: Path, questionnaire_id: str) -> None:
    data = load_questionnaires(q_path)
    for q in data.get("questionnaires", []):
        if q.get("id") == questionnaire_id:
            q["reminder_sent_at"] = datetime.now(UTC).isoformat()
            save_questionnaires(q_path, data)
            return


def mark_questionnaire_emailed(q_path: Path, questionnaire_id: str) -> None:
    data = load_questionnaires(q_path)
    for q in data.get("questionnaires", []):
        if q.get("id") == questionnaire_id:
            q["email_sent_at"] = datetime.now(UTC).isoformat()
            save_questionnaires(q_path, data)
            return


def _parse_date(value: str | Any):
    if not value:
        return None
    if hasattr(value, "year") and hasattr(value, "month"):
        return value
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except ValueError:
        return None
