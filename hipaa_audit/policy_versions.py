from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


def manifest_path(policy_dir: Path) -> Path:
    return policy_dir / ".history" / "manifest.yaml"


def load_manifest(policy_dir: Path) -> dict[str, Any]:
    path = manifest_path(policy_dir)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def save_manifest(policy_dir: Path, data: dict[str, Any]) -> None:
    path = manifest_path(policy_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def _next_version(current: str, bump: bool) -> str:
    if not bump:
        return current
    match = re.match(r"^(\d+)\.(\d+)$", current or "1.0")
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        return f"{major}.{minor + 1}"
    return "1.1"


def snapshot_policy(
    policy_dir: Path,
    policy_name: str,
    *,
    new_content: str,
    saved_by: str = "workspace",
    summary: str = "",
    bump_version: bool = False,
) -> dict[str, Any]:
    """Archive prior content and update manifest before saving new policy text."""
    policy_path = policy_dir / policy_name
    history_dir = policy_dir / ".history" / policy_name
    history_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(policy_dir)
    entry = manifest.get(policy_name, {"current_version": "1.0", "versions": []})
    current = entry.get("current_version", "1.0")
    new_version = _next_version(current, bump_version)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    if policy_path.exists():
        prior = policy_path.read_text()
        if prior != new_content:
            archive = history_dir / f"{new_version}-{timestamp}.md"
            archive.write_text(prior)

    version_row = {
        "version": new_version,
        "saved_at": datetime.now(UTC).isoformat(),
        "saved_by": saved_by,
        "summary": summary or ("Version bump" if bump_version else "Edited in workspace"),
        "archive": str((history_dir / f"{new_version}-{timestamp}.md").name) if policy_path.exists() else "",
    }
    versions = [v for v in entry.get("versions", []) if v.get("version") != new_version]
    versions.append(version_row)
    entry["current_version"] = new_version
    entry["versions"] = versions[-20:]
    manifest[policy_name] = entry
    save_manifest(policy_dir, manifest)

    policy_path.write_text(new_content)
    return {"policy": policy_name, "version": new_version, "versions": entry["versions"]}


def list_versions(policy_dir: Path, policy_name: str) -> list[dict[str, Any]]:
    manifest = load_manifest(policy_dir)
    return manifest.get(policy_name, {}).get("versions", [])


def policy_diff(policy_dir: Path, policy_name: str, left: str, right: str) -> str:
    import difflib

    left_text = read_archive(policy_dir, policy_name, left) if left.endswith(".md") else left
    right_text = read_archive(policy_dir, policy_name, right) if right.endswith(".md") else right
    if left == "current":
        left_text = (policy_dir / policy_name).read_text() if (policy_dir / policy_name).exists() else ""
    if right == "current":
        right_text = (policy_dir / policy_name).read_text() if (policy_dir / policy_name).exists() else ""
    lines = difflib.unified_diff(
        left_text.splitlines(keepends=True),
        right_text.splitlines(keepends=True),
        fromfile=left,
        tofile=right,
    )
    return "".join(lines) or "(no differences)"


def sync_policy_version_to_acks(ack_path: Path, policy_name: str, version: str) -> None:
    """Update acknowledgments register when policy version bumps."""
    import yaml

    if not ack_path.exists():
        return
    data = yaml.safe_load(ack_path.read_text()) or {}
    policies = data.get("policies", [])
    found = False
    for p in policies:
        if p.get("policy") == policy_name:
            p["version"] = version
            found = True
    if not found:
        policies.append({"policy": policy_name, "version": version})
    data["policies"] = policies
    ack_path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def read_archive(policy_dir: Path, policy_name: str, archive_name: str) -> str:
    if ".." in archive_name or "/" in archive_name:
        return ""
    path = policy_dir / ".history" / policy_name / archive_name
    return path.read_text() if path.is_file() else ""
