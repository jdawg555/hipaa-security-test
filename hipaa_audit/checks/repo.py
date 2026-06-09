from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus

# Patterns that suggest PHI or credentials in source (heuristic, not definitive)
PHI_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN-like pattern"),
    (r"\bMRN[:\s]+\d+", "MRN reference"),
    (r"patient_name\s*=\s*['\"][A-Z][a-z]+", "hardcoded patient name"),
]

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}", "inline secret"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private key block"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
]

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "evidence",
    "__pycache__",
}


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    handler = check.get("handler", check_id)
    handlers = {
        "gitignore_env": _gitignore_env,
        "no_secrets_in_repo": _no_secrets_in_repo,
        "phi_heuristic_scan": _phi_heuristic_scan,
        "sra_template_present": _sra_template_present,
        "risk_register_present": _risk_register_present,
        "baa_register_present": _baa_register_present,
        "incident_runbook_present": _incident_runbook_present,
        "encryption_docs_present": _encryption_docs_present,
        "precommit_or_ci_security": _precommit_or_ci_security,
        "dependency_lockfile": _dependency_lockfile,
        "file_exists": _file_exists,
    }
    fn = handlers.get(handler)
    if fn is None:
        return _file_exists(check, repo_path=repo_path, config=config, evidence_dir=evidence_dir)
    return fn(check, repo_path=repo_path, config=config, evidence_dir=evidence_dir)


def _file_exists(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    paths = check.get("paths", [])
    found = [p for p in paths if (repo_path / p).exists()]
    if found:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"Found: {', '.join(found)}",
            evidence_path=str(found[0]),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"Missing required paths: {', '.join(paths)}",
        remediation=check.get("remediation"),
    )


def _gitignore_env(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    gitignore = repo_path / ".gitignore"
    if not gitignore.exists():
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message="No .gitignore found",
            remediation="Add .gitignore with .env, *.pem, credentials.json",
        )
    content = gitignore.read_text()
    required = [".env", ".env.*", "*.pem", "credentials"]
    missing = [r for r in required if r not in content]
    if missing:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f".gitignore missing patterns: {', '.join(missing)}",
            remediation="Add environment and credential patterns to .gitignore",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=".gitignore covers env files and credentials",
    )


def _scan_files(repo_path: Path, patterns: list[tuple[str, str]], max_hits: int = 20) -> list[dict]:
    hits: list[dict] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in {".png", ".jpg", ".gif", ".woff", ".woff2", ".ico", ".pdf"}:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern, label in patterns:
                if re.search(pattern, line) and "example" not in line.lower():
                    hits.append({"file": str(path.relative_to(repo_path)), "line": line_no, "type": label})
                    if len(hits) >= max_hits:
                        return hits
    return hits


def _no_secrets_in_repo(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    hits = _scan_files(repo_path, SECRET_PATTERNS)
    evidence_file = evidence_dir / "secret-scan.json"
    evidence_file.write_text(json.dumps(hits, indent=2))
    if hits:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Potential secrets in {len(hits)} location(s). See {evidence_file.name}",
            evidence_path=str(evidence_file),
            remediation="Rotate exposed credentials and remove from git history",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message="No obvious inline secrets detected (heuristic scan)",
        evidence_path=str(evidence_file),
    )


def _phi_heuristic_scan(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    hits = _scan_files(repo_path, PHI_PATTERNS, max_hits=10)
    evidence_file = evidence_dir / "phi-heuristic-scan.json"
    evidence_file.write_text(json.dumps(hits, indent=2))
    if hits:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"PHI-like patterns in {len(hits)} location(s) — verify synthetic/test data only",
            evidence_path=str(evidence_file),
            remediation="Use synthetic fixtures; never commit real PHI",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message="No PHI-like literals detected in repo (heuristic)",
        evidence_path=str(evidence_file),
    )


def _policy_path(repo_path: Path, config: dict[str, Any], name: str) -> Path | None:
    policy_dir = config.get("policy_dir", "policies")
    candidates = [
        repo_path / policy_dir / name,
        repo_path / "compliance" / "policies" / name,
        repo_path / "docs" / "security" / "policies" / name,
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _sra_template_present(check, *, repo_path, config, evidence_dir) -> CheckResult:
    paths = [
        "templates/sra-imported.md",
        "templates/sra-template.md",
        "docs/security/sra-imported.md",
        "docs/security/sra.md",
        "compliance/sra.md",
        config.get("sra_path", ""),
    ]
    paths = [p for p in paths if p]
    return _file_exists({**check, "paths": paths}, repo_path=repo_path, config=config, evidence_dir=evidence_dir)


def _risk_register_present(check, *, repo_path, config, evidence_dir) -> CheckResult:
    paths = ["templates/risk-register.md", "compliance/risk-register.md", config.get("risk_register_path", "")]
    paths = [p for p in paths if p]
    result = _file_exists({**check, "paths": paths}, repo_path=repo_path, config=config, evidence_dir=evidence_dir)
    if result.status == CheckStatus.FAIL:
        result.status = CheckStatus.MANUAL
        result.message = "Risk register not found — complete templates/risk-register.md"
    return result


def _baa_register_present(check, *, repo_path, config, evidence_dir) -> CheckResult:
    paths = ["templates/baa-register.md", "compliance/baa-registry.md", config.get("baa_register_path", "")]
    paths = [p for p in paths if p]
    result = _file_exists({**check, "paths": paths}, repo_path=repo_path, config=config, evidence_dir=evidence_dir)
    if result.status == CheckStatus.FAIL:
        result.status = CheckStatus.MANUAL
        result.message = "BAA register not found — document all PHI subprocessors"
    return result


def _incident_runbook_present(check, *, repo_path, config, evidence_dir) -> CheckResult:
    paths = [
        "policies/incident-response-plan.md",
        "compliance/policies/04-incident-response.md",
        "docs/runbooks/incident-response.md",
    ]
    return _file_exists({**check, "paths": paths}, repo_path=repo_path, config=config, evidence_dir=evidence_dir)


def _encryption_docs_present(check, *, repo_path, config, evidence_dir) -> CheckResult:
    paths = [
        "policies/encryption-policy.md",
        "compliance/policies/11-encryption.md",
        "docs/security/encryption.md",
    ]
    return _file_exists({**check, "paths": paths}, repo_path=repo_path, config=config, evidence_dir=evidence_dir)


def _precommit_or_ci_security(check, *, repo_path, config, evidence_dir) -> CheckResult:
    ci = repo_path / ".github" / "workflows"
    has_ci = ci.exists() and any(ci.glob("*.yml"))
    precommit = (repo_path / ".pre-commit-config.yaml").exists()
    if has_ci or precommit:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="CI workflows or pre-commit hooks configured",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="No CI workflows or pre-commit config found",
        remediation="Add .github/workflows/compliance-audit.yml from this repo",
    )


def _dependency_lockfile(check, *, repo_path, config, evidence_dir) -> CheckResult:
    lockfiles = list(repo_path.glob("**/package-lock.json")) + list(repo_path.glob("**/uv.lock"))
    lockfiles += list(repo_path.glob("**/poetry.lock")) + list(repo_path.glob("**/Pipfile.lock"))
    if lockfiles:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"Lockfiles present: {len(lockfiles)}",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="No dependency lockfiles found",
        remediation="Pin dependencies with lockfiles for reproducible builds",
    )
