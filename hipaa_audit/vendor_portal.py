from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from jinja2 import Template

from hipaa_audit.vendors import SIG_LITE_KEYS

QUESTIONS = [
    ("soc2_or_iso", "SOC 2 Type II or ISO 27001 certification current?"),
    ("encryption_at_rest", "Encryption at rest for customer/PHI data?"),
    ("encryption_in_transit", "Encryption in transit (TLS 1.2+)?"),
    ("mfa_enforced", "MFA enforced for administrative access?"),
    ("access_logging", "Access logging retained ≥ 1 year?"),
    ("incident_notification", "Incident notification within 24–72 hours?"),
    ("subprocessors_disclosed", "Subprocessors list provided and current?"),
    ("data_retention_defined", "Data retention and deletion policy documented?"),
]

VENDOR_PORTAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Questionnaire — {{ vendor_name }}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 0 auto; padding: 2rem 1.25rem; color: #101828; }
    h1 { font-size: 1.5rem; }
    .meta { color: #667085; margin-bottom: 1.5rem; }
    label { display: block; margin: 1rem 0 .35rem; font-weight: 600; }
    select, input[type=text], textarea { width: 100%; padding: .6rem; border: 1px solid #d0d5dd; border-radius: 8px; }
    button { margin-top: 1.5rem; background: #0c6e7c; color: white; border: 0; padding: .75rem 1.25rem;
             border-radius: 8px; cursor: pointer; }
    .flash { background: #e0f2f4; padding: .75rem 1rem; border-radius: 8px; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>Vendor Security Questionnaire (SIG-lite)</h1>
  <p class="meta">{{ org_name }} · {{ questionnaire_id }} · Due {{ due_date }}</p>
  {% if flash %}<div class="flash">{{ flash }}</div>{% endif %}
  {% if submitted %}
  <p><strong>Thank you.</strong> Your responses were recorded.</p>
  {% else %}
  <p>Complete this form for <strong>{{ vendor_name }}</strong>.</p>
  <form method="post" action="{{ submit_url }}">
    {% for key, label in questions %}
    <label for="{{ key }}">{{ loop.index }}. {{ label }}</label>
    <select id="{{ key }}" name="{{ key }}" required>
      <option value="">Select…</option>
      <option value="true">Yes</option>
      <option value="false">No</option>
    </select>
    {% endfor %}
    <label for="reviewer">Your name / title</label>
    <input type="text" id="reviewer" name="reviewer" required>
    <label for="notes">Additional notes (optional)</label>
    <textarea id="notes" name="notes" rows="3"></textarea>
    <button type="submit">Submit responses</button>
  </form>
  {% endif %}
</body>
</html>
"""


def render_vendor_portal_html(
    *,
    config: dict[str, Any],
    questionnaire: dict[str, Any],
    submit_url: str,
    flash: str = "",
    submitted: bool = False,
) -> str:
    return Template(VENDOR_PORTAL_TEMPLATE).render(
        org_name=config.get("org_name", "Organization"),
        questionnaire_id=questionnaire["id"],
        vendor_id=questionnaire.get("vendor_id", ""),
        vendor_name=questionnaire.get("vendor_name", ""),
        contact=questionnaire.get("contact", ""),
        due_date=questionnaire.get("due_date", ""),
        questions=QUESTIONS,
        submit_url=submit_url,
        flash=flash,
        submitted=submitted,
    )


def publish_vendor_portal(
    *,
    repo_path: Path,
    config: dict[str, Any],
    questionnaire: dict[str, Any],
) -> Path:
    out_dir = repo_path / config.get("vendors", {}).get("portal_dir", "compliance/vendor-portals")
    out_dir.mkdir(parents=True, exist_ok=True)
    qid = questionnaire["id"]
    token = questionnaire.get("portal_token", qid)
    html = render_vendor_portal_html(
        config=config,
        questionnaire=questionnaire,
        submit_url=f"/portals/vendor/{token}",
    )
    out = out_dir / f"{qid}.html"
    out.write_text(html)
    return out


def parse_response_file(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}
