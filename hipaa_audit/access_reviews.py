from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml


def load_campaigns(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"campaigns": [], "decisions": []}
    return yaml.safe_load(path.read_text()) or {"campaigns": [], "decisions": []}


def save_campaigns(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def start_campaign(
    path: Path,
    *,
    name: str,
    owner: str,
    systems: list[dict[str, str]],
    due_days: int = 30,
) -> dict[str, Any]:
    data = load_campaigns(path)
    seq = len(data.get("campaigns", [])) + 1
    campaign_id = f"AR-{datetime.now(UTC).strftime('%Y')}-Q{((datetime.now(UTC).month - 1) // 3) + 1}-{seq:02d}"
    due = (datetime.now(UTC) + timedelta(days=due_days)).strftime("%Y-%m-%d")
    campaign = {
        "id": campaign_id,
        "name": name,
        "owner": owner,
        "started_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "due_date": due,
        "status": "in_progress",
        "systems": systems,
    }
    data.setdefault("campaigns", []).append(campaign)
    save_campaigns(path, data)
    return campaign


def record_decision(
    path: Path,
    *,
    campaign_id: str,
    system_id: str,
    principal: str,
    decision: str,
    reviewer: str,
    notes: str = "",
) -> bool:
    data = load_campaigns(path)
    campaigns = {c["id"]: c for c in data.get("campaigns", [])}
    if campaign_id not in campaigns:
        return False
    entry = {
        "campaign_id": campaign_id,
        "system_id": system_id,
        "principal": principal,
        "decision": decision,
        "reviewer": reviewer,
        "reviewed_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "notes": notes,
    }
    data.setdefault("decisions", []).append(entry)
    save_campaigns(path, data)
    return True


def complete_campaign(path: Path, campaign_id: str) -> bool:
    data = load_campaigns(path)
    for campaign in data.get("campaigns", []):
        if campaign.get("id") == campaign_id:
            campaign["status"] = "completed"
            campaign["completed_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
            save_campaigns(path, data)
            return True
    return False


def assess_access_reviews(path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_campaigns(path)
    campaigns = data.get("campaigns", [])
    if not campaigns:
        return "manual", "No access review campaigns — run hipaa-audit access-review start", []

    max_age = int(config.get("access_reviews", {}).get("max_campaign_age_days", 120))
    now = datetime.now(UTC).date()
    issues: list[str] = []

    completed_recent = False
    for c in campaigns:
        started = _parse_date(c.get("started_at", ""))
        status = c.get("status", "draft")
        if status == "completed" and started and (now - started).days <= max_age:
            completed_recent = True
        if status == "in_progress":
            due = _parse_date(c.get("due_date", ""))
            if due and now > due:
                issues.append(f"{c['id']}: overdue (due {c.get('due_date')})")
            systems = c.get("systems", [])
            decisions = [d for d in data.get("decisions", []) if d.get("campaign_id") == c["id"]]
            if systems and len(decisions) < len(systems):
                issues.append(f"{c['id']}: {len(decisions)}/{len(systems)} systems reviewed")

    if completed_recent and not issues:
        return "pass", "Access review campaign completed within SLA", []
    if issues:
        return "warn" if len(issues) <= 2 else "fail", "; ".join(issues[:3]), issues
    return "manual", "Start or complete a quarterly access review campaign", []


def _parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None
