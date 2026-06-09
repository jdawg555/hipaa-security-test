from __future__ import annotations

import json
import os
import urllib.request
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
