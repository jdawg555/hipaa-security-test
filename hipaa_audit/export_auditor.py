from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


INCLUDE_GLOBS = [
    "evidence/latest/audit-report.json",
    "evidence/latest/audit-report.md",
    "evidence/latest/dashboard.html",
    "evidence/latest/posture.json",
    "evidence/latest/probo-import.json",
    "compliance/vendors.example.yaml",
    "compliance/access-reviews.example.yaml",
    "compliance/certifications.example.yaml",
    "compliance/tasks.example.yaml",
    "templates/*.md",
    "policies/*.md",
]

OPTIONAL_PATHS = [
    "compliance/vendors.yaml",
    "compliance/access-reviews.yaml",
    "compliance/certifications.yaml",
    "compliance/acknowledgments.yaml",
    "compliance/training-log.csv",
    "compliance/saas-inventory.yaml",
    "compliance/devices.yaml",
    "compliance/vendor-questionnaires.yaml",
    "compliance/trust-center/index.html",
    "evidence/history/posture.jsonl",
]


def build_auditor_bundle(repo_path: Path, output: Path, *, config: dict[str, Any]) -> Path:
    repo_path = repo_path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "format": "hipaa-audit-auditor-v1",
        "org_name": config.get("org_name", repo_path.name),
        "generated_at": datetime.now(UTC).isoformat(),
        "files": [],
    }

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for pattern in INCLUDE_GLOBS:
            for path in sorted(repo_path.glob(pattern)):
                if path.is_file():
                    arc = str(path.relative_to(repo_path))
                    zf.write(path, arc)
                    manifest["files"].append(arc)

        for rel in OPTIONAL_PATHS:
            path = repo_path / rel
            if path.is_file():
                arc = str(path.relative_to(repo_path))
                zf.write(path, arc)
                manifest["files"].append(arc)

        zf.writestr("auditor-manifest.json", json.dumps(manifest, indent=2))

    return output
