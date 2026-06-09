from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any


def _previous_score(history_path: Path) -> float | None:
    if not history_path.exists():
        return None
    lines = [ln for ln in history_path.read_text().strip().splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    try:
        prev = json.loads(lines[-2])
        return float(prev.get("score", 0))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def maybe_notify_slack(
    *,
    config: dict[str, Any],
    repo_path: Path,
    current_score: float,
    summary: dict[str, int],
    failing: list[dict[str, Any]],
) -> str | None:
    slack = config.get("notifications", {}).get("slack", {})
    if not slack.get("enabled", False):
        return None

    webhook = os.environ.get(slack.get("webhook_env", "SLACK_WEBHOOK_URL"), "")
    if not webhook:
        return "Slack enabled but webhook env not set"

    min_drop = float(slack.get("min_score_drop", 5))
    history = repo_path / "evidence" / "history" / "posture.jsonl"
    prev = _previous_score(history)
    drop = (prev - current_score) if prev is not None else 0

    notify_on_fail = slack.get("notify_on_fail", True)
    should = (drop >= min_drop) or (notify_on_fail and summary.get("fail", 0) > 0)
    if not should:
        return None

    fail_lines = "\n".join(f"• {f['id']}: {f.get('title', '')[:50]}" for f in failing[:5])
    text = (
        f"*HIPAA posture update* — {config.get('org_name', 'org')}\n"
        f"Score: {current_score}%"
        + (f" (↓{drop:.1f} from {prev}%)" if prev is not None and drop > 0 else "")
        + f"\nPass/Fail/Warn: {summary.get('pass', 0)}/{summary.get('fail', 0)}/{summary.get('warn', 0)}"
    )
    if fail_lines:
        text += f"\n\n*Failures:*\n{fail_lines}"

    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(  # noqa: S310
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15):  # noqa: S310
            pass
        return "Slack notification sent"
    except Exception as exc:  # noqa: BLE001
        return f"Slack notification failed: {exc}"


def send_email(
    *,
    config: dict[str, Any],
    to: str,
    subject: str,
    body: str,
    repo_path: Path | None = None,
) -> str | None:
    """Send email via SMTP. Returns error message or None on success."""
    email_cfg = config.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return "Email notifications disabled"

    if repo_path is not None:
        from hipaa_audit.workspace.secrets import apply_workspace_secrets

        apply_workspace_secrets(repo_path, config)

    host = os.environ.get(email_cfg.get("smtp_host_env", "SMTP_HOST"), email_cfg.get("smtp_host", ""))
    port = int(os.environ.get(email_cfg.get("smtp_port_env", "SMTP_PORT"), email_cfg.get("smtp_port", 587)))
    user = os.environ.get(email_cfg.get("smtp_user_env", "SMTP_USER"), "")
    password = os.environ.get(email_cfg.get("smtp_password_env", "SMTP_PASSWORD"), "")
    from_addr = email_cfg.get("from_address") or user or "security@example.com"

    if not host:
        return "SMTP host not configured (notifications.email.smtp_host or SMTP_HOST)"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            if email_cfg.get("use_tls", True):
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return None
    except Exception as exc:  # noqa: BLE001
        return f"Email send failed: {exc}"


def send_questionnaire_email(
    *,
    config: dict[str, Any],
    contact: str,
    questionnaire: dict[str, Any],
    portal_url: str,
    repo_path: Path,
) -> str | None:
    org = config.get("org_name", "Organization")
    subject = f"[{org}] Security questionnaire — {questionnaire.get('vendor_name', '')}"
    body = (
        f"Hello,\n\n"
        f"{org} has sent a SIG-lite security questionnaire (ID {questionnaire.get('id')}).\n"
        f"Due date: {questionnaire.get('due_date')}\n\n"
        f"Complete the form here:\n{portal_url}\n\n"
        f"Thank you,\n{org} Security"
    )
    return send_email(config=config, to=contact, subject=subject, body=body, repo_path=repo_path)


def send_questionnaire_reminder(
    *,
    config: dict[str, Any],
    questionnaire: dict[str, Any],
    portal_url: str,
    repo_path: Path,
) -> str | None:
    org = config.get("org_name", "Organization")
    subject = f"[{org}] Reminder: security questionnaire due {questionnaire.get('due_date')}"
    body = (
        f"Reminder: questionnaire {questionnaire.get('id')} for {questionnaire.get('vendor_name')} "
        f"is due {questionnaire.get('due_date')}.\n\nComplete here:\n{portal_url}\n"
    )
    return send_email(
        config=config,
        to=questionnaire.get("contact", ""),
        subject=subject,
        body=body,
        repo_path=repo_path,
    )


def maybe_notify_task_assigned(
    *,
    config: dict[str, Any],
    task: dict[str, Any],
    repo_path: Path,
) -> str | None:
    slack = config.get("notifications", {}).get("slack", {})
    if not slack.get("notify_on_task_assign", False):
        return None
    webhook = os.environ.get(slack.get("webhook_env", "SLACK_WEBHOOK_URL"), "")
    if not webhook:
        return "Slack task notify enabled but webhook not set"
    owner = task.get("owner", "")
    text = (
        f"*Task assigned* — {config.get('org_name', 'org')}\n"
        f"{task.get('id')}: {task.get('title', '')[:80]}\n"
        f"Owner: {owner} · Due: {task.get('due_date', '—')}"
    )
    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15):  # noqa: S310
            pass
        return None
    except Exception as exc:  # noqa: BLE001
        return f"Slack task notify failed: {exc}"
