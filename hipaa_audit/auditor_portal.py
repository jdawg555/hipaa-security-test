from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jinja2 import Template

PORTAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auditor Portal — {{ org_name }}</title>
  <style>
    :root { --accent:#1d4ed8; --bg:#f1f5f9; --pass:#15803d; --fail:#b91c1c; --warn:#b45309; }
    body { font-family: system-ui, sans-serif; margin: 0; background: var(--bg); color: #0f172a; }
    #gate { position: fixed; inset: 0; background: rgba(15,23,42,.92); display: flex; align-items: center;
            justify-content: center; z-index: 10; }
    #gate.hidden { display: none; }
    .panel { background: white; padding: 2rem; border-radius: 12px; max-width: 400px; width: 90%; }
    input { width: 100%; padding: .75rem; margin: .75rem 0; border: 1px solid #cbd5e1; border-radius: 8px; }
    button { background: var(--accent); color: white; border: 0; padding: .75rem 1.25rem; border-radius: 8px;
             cursor: pointer; width: 100%; }
    header { background: var(--accent); color: white; padding: 1.5rem 2rem; }
    main { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 1.5rem; }
    th, td { text-align: left; padding: .7rem 1rem; border-bottom: 1px solid #e2e8f0; font-size: .9rem; }
    th { background: #e2e8f0; }
    .badge { padding: .15rem .45rem; border-radius: 4px; font-size: .75rem; font-weight: 600; text-transform: uppercase; }
    .pass { background: #dcfce7; color: var(--pass); }
    .fail { background: #fee2e2; color: var(--fail); }
    .warn { background: #fef3c7; color: var(--warn); }
    .manual, .skip { background: #f1f5f9; color: #64748b; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .card { background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
    .card strong { font-size: 1.5rem; display: block; }
    ul.files { list-style: none; padding: 0; }
    ul.files li { background: white; margin: .35rem 0; padding: .6rem 1rem; border-radius: 6px; }
    footer { text-align: center; padding: 2rem; color: #64748b; font-size: .85rem; }
  </style>
</head>
<body>
  {% if access_hash %}
  <div id="gate">
    <div class="panel">
      <h2>Auditor access</h2>
      <p>Enter the access passphrase shared under NDA.</p>
      <input type="password" id="pass" placeholder="Passphrase" autocomplete="off">
      <button onclick="unlock()">View evidence</button>
      <p id="err" style="color:#b91c1c;display:none">Incorrect passphrase</p>
    </div>
  </div>
  {% endif %}

  <header>
    <h1>{{ org_name }} — Auditor Portal</h1>
    <p>Read-only compliance evidence · Generated {{ generated_at[:10] }}</p>
  </header>
  <main>
    <div class="grid">
      <div class="card"><strong>{{ posture_score }}%</strong>Posture score</div>
      <div class="card"><strong>{{ summary.pass }}</strong>Passing</div>
      <div class="card"><strong>{{ summary.fail }}</strong>Failing</div>
      <div class="card"><strong>{{ control_count }}</strong>Controls</div>
    </div>

    <h2>Control results</h2>
    <table>
      <thead><tr><th>ID</th><th>Title</th><th>Framework</th><th>Status</th><th>Details</th></tr></thead>
      <tbody>
        {% for row in rows %}
        <tr>
          <td>{{ row.id }}</td>
          <td>{{ row.title }}</td>
          <td>{{ row.framework }}</td>
          <td><span class="badge {{ row.status }}">{{ row.status }}</span></td>
          <td>{{ row.message }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>Evidence artifacts</h2>
    <ul class="files">
      {% for f in evidence_files %}
      <li>{{ f }}</li>
      {% endfor %}
    </ul>

    <h2>Policy documents</h2>
    <ul class="files">
      {% for p in policies %}
      <li>{{ p }}</li>
      {% endfor %}
    </ul>
  </main>
  <footer>hipaa-audit auditor portal · Share only under NDA · Not a formal audit opinion</footer>

  {% if access_hash %}
  <script>
    const HASH = "{{ access_hash }}";
    function unlock() {
      const pass = document.getElementById('pass').value;
      const data = new TextEncoder().encode(pass);
      crypto.subtle.digest('SHA-256', data).then(buf => {
        const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
        if (hex === HASH) {
          document.getElementById('gate').classList.add('hidden');
          sessionStorage.setItem('auditor_unlocked', '1');
        } else {
          document.getElementById('err').style.display = 'block';
        }
      });
    }
    if (sessionStorage.getItem('auditor_unlocked') === '1') {
      document.getElementById('gate').classList.add('hidden');
    }
  </script>
  {% endif %}
</body>
</html>
"""


def _framework_label(control_id: str) -> str:
    if control_id.startswith("SOC2-"):
        return "SOC 2"
    if control_id.startswith("ISO27001-"):
        return "ISO 27001"
    return "HIPAA"


def _collect_evidence_files(repo_path: Path) -> list[str]:
    files: list[str] = []
    for pattern in [
        "evidence/latest/audit-report.json",
        "evidence/latest/audit-report.md",
        "evidence/latest/dashboard.html",
        "evidence/latest/posture.json",
        "evidence/latest/probo-import.json",
        "evidence/latest/auditor-bundle.zip",
    ]:
        p = repo_path / pattern
        if p.exists():
            files.append(pattern)
    return files


def publish_auditor_portal(
    *,
    repo_path: Path,
    config: dict[str, Any],
    report_json: Path,
    access_passphrase: str = "",
) -> Path:
    portal_cfg = config.get("auditor_portal", {})
    output_dir = repo_path / portal_cfg.get("output_dir", "compliance/auditor-portal")
    output_dir.mkdir(parents=True, exist_ok=True)

    data = json.loads(report_json.read_text())
    rows = []
    for ctrl in data.get("controls", []):
        msg = "; ".join(ch.get("message", "") for ch in ctrl.get("checks", [])[:2])
        rows.append(
            {
                "id": ctrl["id"],
                "title": ctrl.get("title", ""),
                "framework": _framework_label(ctrl["id"]),
                "status": ctrl.get("status", "manual"),
                "message": msg[:180],
            }
        )

    policy_dir = repo_path / config.get("policy_dir", "policies")
    policies = sorted(p.name for p in policy_dir.glob("*.md")) if policy_dir.is_dir() else []

    access_hash = ""
    if access_passphrase:
        access_hash = hashlib.sha256(access_passphrase.encode()).hexdigest()

    html = Template(PORTAL_TEMPLATE).render(
        org_name=data.get("org_name", config.get("org_name", "Organization")),
        generated_at=data.get("generated_at", ""),
        posture_score=data.get("posture", {}).get("score", 0),
        summary=data.get("summary", {}),
        control_count=len(rows),
        rows=rows,
        evidence_files=_collect_evidence_files(repo_path),
        policies=policies,
        access_hash=access_hash,
    )
    out = output_dir / "index.html"
    out.write_text(html)
    return out
