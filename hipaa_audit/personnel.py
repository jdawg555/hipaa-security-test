from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.checks.policies import REQUIRED_POLICIES


def load_acknowledgments(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"policies": [], "acknowledgments": []}
    return yaml.safe_load(path.read_text()) or {"acknowledgments": []}


def load_workforce(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = load_acknowledgments(path)
    return data.get("workforce", [])


def check_acknowledgments(
    repo_path: Path,
    config: dict[str, Any],
) -> tuple[str, list[str], list[str]]:
    """Returns status tier message, missing policies, missing employees."""
    personnel = config.get("personnel", {})
    ack_path = repo_path / personnel.get("acknowledgments_path", "compliance/acknowledgments.yaml")
    data = load_acknowledgments(ack_path)
    if not data.get("acknowledgments"):
        return "missing", [], ["No acknowledgments file — copy compliance/acknowledgments.example.yaml"]

    required_policy_files = [f for f, _ in REQUIRED_POLICIES]
    policy_versions = {p["policy"]: p.get("version", "1.0") for p in data.get("policies", []) if p.get("policy")}
    if not policy_versions:
        policy_versions = {f: "1.0" for f in required_policy_files}

    workforce = data.get("workforce") or [
        {"id": a.get("employee_id", a.get("email", "unknown"))}
        for a in data["acknowledgments"]
    ]
    active_ids = {w.get("id") or w.get("employee_id") or w.get("email") for w in workforce if w.get("active", True)}

    acks: dict[tuple[str, str], set[str]] = {}
    for row in data["acknowledgments"]:
        emp = row.get("employee_id") or row.get("email")
        pol = row.get("policy")
        ver = row.get("version", policy_versions.get(pol, "1.0"))
        if emp and pol:
            acks.setdefault((pol, ver), set()).add(emp)

    gaps: list[str] = []
    for pol_file, label in REQUIRED_POLICIES:
        ver = policy_versions.get(pol_file, "1.0")
        signed = acks.get((pol_file, ver), set())
        missing_emps = active_ids - signed
        if missing_emps:
            gaps.append(f"{label}: {len(missing_emps)} employee(s) missing v{ver}")

    if not gaps:
        return "pass", list(policy_versions.keys()), []
    if len(gaps) <= 2:
        return "warn", list(policy_versions.keys()), gaps
    return "fail", list(policy_versions.keys()), gaps


def check_training_csv(repo_path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    personnel = config.get("personnel", {})
    csv_path = repo_path / personnel.get("training_csv", "compliance/training-log.csv")
    if not csv_path.exists():
        return "manual", "No training CSV — run hipaa-audit import-training or add compliance/training-log.csv", []

    issues: list[str] = []
    now = datetime.now(UTC).date()
    hire_window = int(personnel.get("initial_training_days", 30))
    annual_days = int(personnel.get("annual_training_days", 365))

    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    if not rows:
        return "fail", "Training CSV is empty", []

    for row in rows:
        emp = row.get("employee_id") or row.get("name") or "?"
        hire = _parse_date(row.get("hire_date", ""))
        initial = _parse_date(row.get("initial_training") or row.get("initial_training_date", ""))
        annual = _parse_date(row.get("annual_refresher") or row.get("annual_training", ""))
        attested = (row.get("attested") or row.get("attested_y_n", "")).upper()

        if attested not in ("Y", "YES", "TRUE", "1"):
            issues.append(f"{emp}: not attested")
            continue
        if hire and initial and (initial - hire).days > hire_window:
            issues.append(f"{emp}: initial training >{hire_window}d after hire")
        if annual and (now - annual).days > annual_days:
            issues.append(f"{emp}: annual refresher >{annual_days}d stale")

    if not issues:
        return "pass", f"Training current for {len(rows)} employee(s)", []
    if len(issues) <= 3:
        return "warn", f"{len(issues)} training gap(s)", issues
    return "fail", f"{len(issues)} training gap(s)", issues


def _parse_date(value: str):
    if not value or value.upper() == "TBD":
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            continue
    return None


def save_acknowledgments(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def ensure_workforce_tokens(path: Path) -> dict[str, Any]:
    import secrets

    data = load_acknowledgments(path)
    changed = False
    for worker in data.get("workforce", []):
        if not worker.get("ack_token"):
            worker["ack_token"] = secrets.token_urlsafe(12)
            changed = True
    if changed:
        save_acknowledgments(path, data)
    return data


def find_worker_by_token(path: Path, token: str) -> dict[str, Any] | None:
    data = load_acknowledgments(path)
    return next((w for w in data.get("workforce", []) if w.get("ack_token") == token), None)


def pending_policies_for_employee(data: dict[str, Any], employee_id: str) -> list[dict[str, str]]:
    policy_versions = {p["policy"]: p.get("version", "1.0") for p in data.get("policies", []) if p.get("policy")}
    signed = {
        (a.get("policy"), a.get("version", "1.0"))
        for a in data.get("acknowledgments", [])
        if (a.get("employee_id") or a.get("email")) == employee_id
    }
    pending: list[dict[str, str]] = []
    for pol, ver in policy_versions.items():
        if (pol, ver) not in signed:
            pending.append({"policy": pol, "version": ver})
    return pending


def record_acknowledgment(path: Path, *, employee_id: str, policy: str, version: str) -> None:
    data = load_acknowledgments(path)
    data.setdefault("acknowledgments", []).append(
        {
            "employee_id": employee_id,
            "policy": policy,
            "version": version,
            "acknowledged_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        }
    )
    save_acknowledgments(path, data)


def sync_workforce_hris(ack_path: Path, workers: list[dict[str, Any]]) -> int:
    """Merge HRIS workforce rows into acknowledgments register."""
    data = ensure_workforce_tokens(ack_path)
    existing = {w.get("id") or w.get("employee_id"): w for w in data.get("workforce", [])}
    count = 0
    for worker in workers:
        wid = worker.get("id") or worker.get("employee_id")
        if not wid:
            continue
        merged = {**existing.get(wid, {}), **worker, "id": wid}
        if worker.get("email"):
            merged["email"] = worker["email"]
        existing[wid] = merged
        count += 1
    data["workforce"] = list(existing.values())
    save_acknowledgments(ack_path, data)
    ensure_workforce_tokens(ack_path)
    return count


def import_training_template(output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        return output
    output.write_text(
        "employee_id,role,hire_date,initial_training,annual_refresher,module,attested\n"
        "EMP001,Engineer,2026-01-15,2026-01-20,2026-01-20,HIPAA-101,Y\n"
    )
    return output
