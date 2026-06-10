from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path: Path,
    config: dict[str, Any],
    evidence_dir: Path,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    integrations = config.get("integrations", {})
    if not integrations:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="No integrations configured in hipaa-audit.yaml",
        )

    handler = check.get("handler", check_id)
    handlers = {
        "prowler_findings": _prowler_findings,
        "prowler_hipaa_crosswalk": _prowler_hipaa_crosswalk,
        "prowler_azure_hipaa_crosswalk": _prowler_azure_hipaa_crosswalk,
        "prowler_gcp_hipaa_crosswalk": _prowler_gcp_hipaa_crosswalk,
        "trivy_vulnerabilities": _trivy_vulnerabilities,
        "osv_vulnerabilities": _osv_vulnerabilities,
        "snyk_vulnerabilities": _snyk_vulnerabilities,
        "checkov_findings": _checkov_findings,
        "compliancekit_mapping": _compliancekit_mapping,
        "sra_json_imported": _sra_json_imported,
        "evidence_freshness": _evidence_freshness,
        "ai_risk_register": _ai_risk_register,
        "state_law_overlay": _state_law_overlay,
    }
    fn = handlers.get(handler)
    if fn is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown integrations handler: {handler}",
        )
    return fn(check, repo_path=repo_path, config=integrations, evidence_dir=evidence_dir)


def _glob_files(repo_path: Path, pattern: str) -> list[Path]:
    # pattern like evidence/prowler/*.json — relative to repo root
    return sorted(repo_path.glob(pattern))


def _max_age_days(config: dict[str, Any]) -> int:
    return int(config.get("max_evidence_age_days", 7))


def _stale(paths: list[Path], max_days: int) -> list[str]:
    stale = []
    now = datetime.now(UTC)
    for p in paths:
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=UTC)
        age = (now - mtime).days
        if age > max_days:
            stale.append(f"{p.name} ({age}d old)")
    return stale


def _prowler_findings(check, *, repo_path, config, evidence_dir) -> CheckResult:
    prowler_cfg = config.get("prowler", {})
    if not prowler_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Prowler integration disabled",
        )
    pattern = prowler_cfg.get("evidence_glob", "evidence/prowler/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No Prowler evidence at {pattern}. Run: prowler aws -M json -o evidence/prowler/",
            remediation=check.get("remediation"),
        )

    failures: list[str] = []
    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            failures.append(f"invalid JSON: {path.name}")
            continue
        failures.extend(_parse_prowler_json(data, path.name))

    out = evidence_dir / "integration-prowler-summary.json"
    out.write_text(json.dumps({"failures": failures[:50], "files": [str(f) for f in files]}, indent=2))

    stale = _stale(files, _max_age_days(config))
    if failures:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Prowler: {len(failures)} FAIL finding(s). See {out.name}",
            evidence_path=str(out),
            remediation="Remediate failed Prowler checks or document risk acceptance",
        )
    if stale:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"Prowler evidence stale: {', '.join(stale)}",
            evidence_path=str(out),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"Prowler evidence clean ({len(files)} file(s))",
        evidence_path=str(out),
    )


def _prowler_cloud_crosswalk(
    check,
    *,
    repo_path,
    config,
    evidence_dir,
    provider: str,
    config_key: str,
    evidence_subdir: str,
) -> CheckResult:
    from hipaa_audit.prowler_crosswalk import collect_finding_statuses, rollup_requirements

    prowler_cfg = config.get(config_key, {})
    if not prowler_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message=f"Prowler {provider} integration disabled",
        )
    pattern = prowler_cfg.get("evidence_glob", f"evidence/{evidence_subdir}/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No Prowler {provider} evidence at {pattern}",
            remediation=f"Run: prowler {provider} --compliance hipaa_{provider} -M json -o evidence/{evidence_subdir}/",
        )
    statuses = collect_finding_statuses(files)
    rollup = rollup_requirements(statuses, provider=provider)
    failed_reqs = [r for r in rollup if r["status"] == "fail"]
    out = evidence_dir / f"integration-prowler-{provider}-crosswalk.json"
    out.write_text(json.dumps({"requirements": rollup, "finding_count": len(statuses)}, indent=2))
    if failed_reqs:
        names = ", ".join(r["id"] for r in failed_reqs[:3])
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Prowler {provider} HIPAA: {len(failed_reqs)} requirement(s) failing ({names})",
            evidence_path=str(out),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"Prowler {provider} HIPAA crosswalk: {len(rollup)} requirement(s) assessed",
        evidence_path=str(out),
    )


def _prowler_azure_hipaa_crosswalk(check, *, repo_path, config, evidence_dir) -> CheckResult:
    return _prowler_cloud_crosswalk(
        check,
        repo_path=repo_path,
        config=config,
        evidence_dir=evidence_dir,
        provider="azure",
        config_key="prowler_azure",
        evidence_subdir="prowler-azure",
    )


def _prowler_gcp_hipaa_crosswalk(check, *, repo_path, config, evidence_dir) -> CheckResult:
    return _prowler_cloud_crosswalk(
        check,
        repo_path=repo_path,
        config=config,
        evidence_dir=evidence_dir,
        provider="gcp",
        config_key="prowler_gcp",
        evidence_subdir="prowler-gcp",
    )


def _prowler_hipaa_crosswalk(check, *, repo_path, config, evidence_dir) -> CheckResult:
    from hipaa_audit.prowler_crosswalk import collect_finding_statuses, rollup_requirements

    prowler_cfg = config.get("prowler", {})
    if not prowler_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Prowler integration disabled",
        )
    pattern = prowler_cfg.get("evidence_glob", "evidence/prowler/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No Prowler evidence at {pattern}",
            remediation=check.get("remediation"),
        )

    statuses = collect_finding_statuses(files)
    rollup = rollup_requirements(statuses, provider="aws")
    failed_reqs = [r for r in rollup if r["status"] == "fail"]
    unknown_reqs = [r for r in rollup if r["status"] == "unknown"]

    out = evidence_dir / "integration-prowler-crosswalk.json"
    out.write_text(json.dumps({"requirements": rollup, "finding_count": len(statuses)}, indent=2))

    if failed_reqs:
        names = ", ".join(r["id"] for r in failed_reqs[:3])
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Prowler HIPAA crosswalk: {len(failed_reqs)} requirement(s) failing ({names})",
            evidence_path=str(out),
            remediation="Remediate failed Prowler checks mapped to HIPAA requirements",
        )
    if unknown_reqs and len(unknown_reqs) > len(rollup) // 2:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"Prowler crosswalk: {len(unknown_reqs)} requirement(s) without matching findings",
            evidence_path=str(out),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"Prowler HIPAA crosswalk: {len(rollup)} requirement(s) assessed",
        evidence_path=str(out),
    )


def _parse_prowler_json(data: Any, source: str) -> list[str]:
    """Support Prowler OCSF JSON array and legacy {findings:[]} shapes."""
    failures: list[str] = []
    items: list[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings") or data.get("Results") or data.get("checks") or []
        if isinstance(data.get("status"), str) and data["status"].upper() in ("FAIL", "FAILED"):
            failures.append(f"{source}: top-level FAIL")

    for item in items:
        if not isinstance(item, dict):
            continue
        status = (
            item.get("status")
            or item.get("Status")
            or item.get("status_code")
            or item.get("compliance", {}).get("status")
            or ""
        )
        status_s = str(status).upper()
        if status_s in ("FAIL", "FAILED", "FAILURE"):
            title = (
                item.get("check_title")
                or item.get("Title")
                or item.get("metadata", {}).get("event_code")
                or item.get("check_id")
                or "unknown"
            )
            failures.append(str(title))
    return failures


def _trivy_vulnerabilities(check, *, repo_path, config, evidence_dir) -> CheckResult:
    trivy_cfg = config.get("trivy", {})
    if not trivy_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Trivy integration disabled",
        )
    pattern = trivy_cfg.get("evidence_glob", "evidence/trivy/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No Trivy evidence at {pattern}. Run: trivy fs --format json -o evidence/trivy/report.json .",
            remediation=check.get("remediation"),
        )

    block_severities = {s.upper() for s in trivy_cfg.get("fail_severities", ["CRITICAL", "HIGH"])}
    hits: list[str] = []
    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            hits.append(f"invalid JSON: {path.name}")
            continue
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                sev = str(vuln.get("Severity", "")).upper()
                if sev in block_severities:
                    hits.append(f"{vuln.get('VulnerabilityID', '?')} ({sev}) in {path.name}")

    out = evidence_dir / "integration-trivy-summary.json"
    out.write_text(json.dumps({"hits": hits[:50]}, indent=2))

    if hits:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Trivy: {len(hits)} {block_severities} vulnerabilit(ies)",
            evidence_path=str(out),
            remediation="Patch or document accepted risk for critical/high CVEs",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message="No critical/high Trivy findings in evidence",
        evidence_path=str(out),
    )


def _checkov_findings(check, *, repo_path, config, evidence_dir) -> CheckResult:
    checkov_cfg = config.get("checkov", {})
    if not checkov_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Checkov integration disabled",
        )
    pattern = checkov_cfg.get("evidence_glob", "evidence/checkov/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=(
                f"No Checkov evidence at {pattern}. "
                "Run: checkov -d . --framework terraform -o json --output-file-path evidence/checkov"
            ),
            remediation=check.get("remediation"),
        )

    failures: list[str] = []
    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            failures.append(f"invalid JSON: {path.name}")
            continue
        failures.extend(_parse_checkov_json(data, path.name))

    out = evidence_dir / "integration-checkov-summary.json"
    out.write_text(json.dumps({"failures": failures[:50], "files": [str(f) for f in files]}, indent=2))

    if failures:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Checkov: {len(failures)} failed IaC check(s). See {out.name}",
            evidence_path=str(out),
            remediation="Fix Terraform/K8s misconfigurations or document exceptions in .checkov.yaml",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"Checkov evidence clean ({len(files)} file(s))",
        evidence_path=str(out),
    )


def _parse_checkov_json(data: Any, source: str) -> list[str]:
    """Parse Checkov JSON (single file or list of scan results)."""
    failures: list[str] = []
    payloads = data if isinstance(data, list) else [data]
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        results = payload.get("results") or {}
        for item in results.get("failed_checks") or []:
            if not isinstance(item, dict):
                continue
            check_id = item.get("check_id") or item.get("check_name") or "unknown"
            resource = item.get("resource") or item.get("file_path") or ""
            failures.append(f"{check_id} ({resource}) in {source}")
    return failures


def _compliancekit_mapping(check, *, repo_path, config, evidence_dir) -> CheckResult:
    ck_cfg = config.get("compliancekit", {})
    if not ck_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="ComplianceKit integration disabled",
        )
    pattern = ck_cfg.get("evidence_glob", "evidence/compliancekit/**/control-mapping.csv")
    files = _glob_files(repo_path, pattern)
    if not files:
        # Also search one-level evidence packs: evidence/*/control-mapping.csv
        files = sorted(repo_path.glob("evidence/*/control-mapping.csv"))
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=(
                "No ComplianceKit control-mapping.csv found. "
                "Run: compliancekit evidence --output evidence/compliancekit/<period>"
            ),
            remediation=check.get("remediation"),
        )

    fail_statuses = {s.lower() for s in ck_cfg.get("fail_statuses", ["fail", "error"])}
    hipaa_rows = 0
    failures: list[str] = []
    waived = 0
    for path in files:
        text = path.read_text()
        reader = csv.DictReader(StringIO(text))
        for row in reader:
            fw = (row.get("framework_id") or "").lower()
            if "hipaa" not in fw:
                continue
            hipaa_rows += 1
            if (row.get("waiver_active") or "").lower() == "true":
                waived += 1
                continue
            status = (row.get("status") or "").lower()
            if status in fail_statuses:
                ctrl = row.get("control_id") or "?"
                chk = row.get("check_id") or "?"
                failures.append(f"{ctrl}/{chk} ({row.get('severity', '')})")

    out = evidence_dir / "integration-compliancekit-summary.json"
    out.write_text(
        json.dumps(
            {
                "hipaa_rows": hipaa_rows,
                "failures": failures[:50],
                "waived": waived,
                "files": [str(f) for f in files],
            },
            indent=2,
        )
    )

    if hipaa_rows == 0:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message="ComplianceKit CSV found but no HIPAA framework rows",
            evidence_path=str(out),
        )
    if failures:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"ComplianceKit HIPAA: {len(failures)} open finding(s)",
            evidence_path=str(out),
            remediation="Remediate cloud findings or document waivers in ComplianceKit",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"ComplianceKit HIPAA mapping clean ({hipaa_rows} rows, {waived} waived)",
        evidence_path=str(out),
    )


def _sra_json_imported(check, *, repo_path, config, evidence_dir) -> CheckResult:
    sra_cfg = config.get("sra_import", {})
    globs = sra_cfg.get(
        "evidence_globs",
        [
            "templates/sra-imported.md",
            "docs/security/sra-imported.md",
            "evidence/sra-import-summary.json",
        ],
    )
    found_md = False
    for pat in globs:
        paths = _glob_files(repo_path, pat) if "*" in pat else [repo_path / pat]
        for p in paths:
            if not p.exists():
                continue
            if p.suffix == ".md":
                found_md = True
    if found_md:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message="SRA JSON imported — review templates/sra-imported.md and sign section 8",
        )
    if sra_cfg.get("require_import", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message="Run: hipaa-audit import-sra <browser-export.json>",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.SKIP,
        message="SRA JSON import not required (optional: hipaa-audit import-sra)",
    )


def _osv_vulnerabilities(check, *, repo_path, config, evidence_dir) -> CheckResult:
    osv_cfg = config.get("osv", {})
    if not osv_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="OSV-Scanner integration disabled",
        )
    pattern = osv_cfg.get("evidence_glob", "evidence/osv/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No OSV evidence at {pattern}",
        )
    vulns = 0
    for path in files:
        data = json.loads(path.read_text())
        vulns += len(data.get("results", [])) if isinstance(data, dict) else 0
    if vulns:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"OSV-Scanner reported {vulns} vulnerable package(s)",
            remediation="Update dependencies or document exceptions",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message="OSV-Scanner evidence shows no vulnerabilities",
    )


def _snyk_vulnerabilities(check, *, repo_path, config, evidence_dir) -> CheckResult:
    snyk_cfg = config.get("snyk", {})
    if not snyk_cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Snyk integration disabled",
        )
    pattern = snyk_cfg.get("evidence_glob", "evidence/snyk/*.json")
    files = _glob_files(repo_path, pattern)
    if not files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"No Snyk evidence at {pattern}. Run: snyk test --json-file-output=evidence/snyk/report.json",
            remediation=check.get("remediation"),
        )
    block = {s.lower() for s in snyk_cfg.get("fail_severities", ["high", "critical"])}
    hits: list[str] = []
    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            hits.append(f"invalid JSON: {path.name}")
            continue
        for vuln in data.get("vulnerabilities", []) or data.get("issues", []):
            sev = str(vuln.get("severity", vuln.get("issueData", {}).get("severity", ""))).lower()
            if sev in block:
                title = vuln.get("title") or vuln.get("issueData", {}).get("title", "?")
                hits.append(f"{title} ({sev})")
    out = evidence_dir / "integration-snyk-summary.json"
    out.write_text(json.dumps({"hits": hits[:50]}, indent=2))
    if hits:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"Snyk: {len(hits)} {block} issue(s)",
            evidence_path=str(out),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message="No high/critical Snyk issues in evidence",
        evidence_path=str(out),
    )


def _evidence_freshness(check, *, repo_path, config, evidence_dir) -> CheckResult:
    max_days = _max_age_days(config)
    patterns = config.get("freshness_globs", ["evidence/latest/*.json", "evidence/prowler/*.json"])
    all_files: list[Path] = []
    for pat in patterns:
        all_files.extend(_glob_files(repo_path, pat))
    if not all_files:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message="No evidence artifacts found — run hipaa-audit scan and external scanners",
        )
    stale = _stale(all_files, max_days)
    if stale:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"Stale evidence (>{max_days}d): {', '.join(stale[:5])}",
            remediation="Re-run compliance scan and upload fresh evidence",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.PASS,
        message=f"Evidence fresh within {max_days} days ({len(all_files)} artifact(s))",
    )


def _template_present(name: str, repo_path: Path, config: dict[str, Any]) -> bool:
    candidates = [
        repo_path / "templates" / name,
        repo_path / config.get("templates_dir", "templates") / name,
    ]
    return any(c.exists() for c in candidates)


def _ai_risk_register(check, *, repo_path, config, evidence_dir) -> CheckResult:
    if not config.get("require_ai_register", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="AI risk register not required (set integrations.require_ai_register: true)",
        )
    if _template_present("ai-risk-register.md", repo_path, config):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="AI risk register template present",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.MANUAL,
        message="Complete templates/ai-risk-register.md for clinical AI systems",
    )


def _state_law_overlay(check, *, repo_path, config, evidence_dir) -> CheckResult:
    states = config.get("applicable_states", [])
    if not states:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="No applicable_states configured — add e.g. [CA, TX, WA] to hipaa-audit.yaml",
        )
    if _template_present("state-law-overlay.md", repo_path, config):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message=f"Complete state-law-overlay for: {', '.join(states)}",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="Add templates/state-law-overlay.md",
    )
