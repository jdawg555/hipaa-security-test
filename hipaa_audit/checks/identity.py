from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from hipaa_audit.models import CheckResult, CheckStatus


def run(
    check: dict[str, Any],
    *,
    repo_path,
    config: dict[str, Any],
    evidence_dir,
) -> CheckResult:
    check_id = check["id"]
    title = check.get("title", check_id)
    identity = config.get("identity", {})
    handler = check.get("handler", check_id)
    handlers = {
        "okta_mfa_policy": _okta_mfa_policy,
        "okta_inactive_users": _okta_inactive_users,
        "google_2sv_enforced": _google_2sv_enforced,
        "google_external_sharing": _google_external_sharing,
    }
    fn = handlers.get(handler)
    if fn is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown identity handler: {handler}",
        )
    return fn(check, identity=identity, evidence_dir=evidence_dir)


def _okta_config(identity: dict[str, Any]) -> tuple[str, str] | None:
    okta = identity.get("okta", {})
    if not okta.get("enabled", False):
        return None
    domain = okta.get("domain") or os.environ.get(okta.get("domain_env", "OKTA_DOMAIN"), "")
    token = os.environ.get(okta.get("token_env", "OKTA_API_TOKEN"), "")
    if domain and token:
        return domain.rstrip("/"), token
    return None


def _okta_get(domain: str, token: str, path: str) -> Any:
    import urllib.error
    import urllib.request

    url = f"https://{domain}/api/v1{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _okta_mfa_policy(check, *, identity, evidence_dir) -> CheckResult:
    cfg = _okta_config(identity)
    if not cfg:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Okta disabled — set identity.okta.enabled and OKTA_API_TOKEN",
        )
    domain, token = cfg
    try:
        policies = _okta_get(domain, token, "/policies?type=MFA_ENROLL")
        active = [p for p in policies if p.get("status") == "ACTIVE"]
        evidence = evidence_dir / "okta-mfa-policies.json"
        evidence.write_text(json.dumps(active, indent=2))
        if active:
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.PASS,
                message=f"{len(active)} active Okta MFA enrollment policy/policies",
                evidence_path=str(evidence),
            )
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message="No active Okta MFA enrollment policies",
            evidence_path=str(evidence),
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.ERROR,
            message=f"Okta API error: {exc}",
        )


def _okta_inactive_users(check, *, identity, evidence_dir) -> CheckResult:
    cfg = _okta_config(identity)
    if not cfg:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Okta disabled",
        )
    domain, token = cfg
    max_days = int(identity.get("okta", {}).get("inactive_days", 90))
    cutoff = datetime.now(UTC) - timedelta(days=max_days)
    try:
        users = _okta_get(domain, token, '/users?filter=status eq "SUSPENDED" or status eq "DEPROVISIONED"')
        stale = []
        for user in users:
            last = user.get("lastLogin")
            if last:
                ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
                if ts < cutoff:
                    stale.append(user.get("profile", {}).get("login", user.get("id")))
        evidence = evidence_dir / "okta-inactive-users.json"
        evidence.write_text(json.dumps(stale, indent=2))
        if not stale:
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.PASS,
                message="No long-inactive Okta accounts flagged",
                evidence_path=str(evidence),
            )
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message=f"{len(stale)} inactive Okta account(s) — review deprovisioning",
            evidence_path=str(evidence),
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.ERROR,
            message=f"Okta API error: {exc}",
        )


def _google_creds(identity: dict[str, Any]):
    google = identity.get("google", {})
    if not google.get("enabled", False):
        return None
    creds_path = google.get("credentials_file") or os.environ.get(
        google.get("credentials_env", "GOOGLE_APPLICATION_CREDENTIALS"), ""
    )
    admin = google.get("admin_email") or os.environ.get(google.get("admin_email_env", "GOOGLE_ADMIN_EMAIL"), "")
    if creds_path and admin:
        return creds_path, admin
    return None


def _google_2sv_enforced(check, *, identity, evidence_dir) -> CheckResult:
    creds = _google_creds(identity)
    if not creds:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Google Workspace disabled — set identity.google.enabled + credentials",
        )
    creds_path, admin = creds
    try:
        from google.oauth2 import service_account  # noqa: PLC0415
        from googleapiclient.discovery import build  # noqa: PLC0415

        scopes = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
        credentials = service_account.Credentials.from_service_account_file(creds_path, scopes=scopes)
        delegated = credentials.with_subject(admin)
        service = build("admin", "reports_v1", credentials=delegated, cache_discovery=False)
        # 2-Step Verification enforcement visible in login audit settings — use users list as proxy
        directory = build("admin", "directory_v1", credentials=delegated, cache_discovery=False)
        users = directory.users().list(customer="my_customer", maxResults=100, orderBy="email").execute()
        without_2sv = [
            u["primaryEmail"]
            for u in users.get("users", [])
            if not u.get("isEnrolledIn2Sv") and not u.get("isEnforcedIn2Sv")
        ]
        evidence = evidence_dir / "google-2sv.json"
        evidence.write_text(json.dumps(without_2sv, indent=2))
        if not without_2sv:
            return CheckResult(
                check_id=check["id"],
                title=check.get("title", check["id"]),
                status=CheckStatus.PASS,
                message="All sampled Google users enrolled in 2SV",
                evidence_path=str(evidence),
            )
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message=f"{len(without_2sv)} user(s) without 2SV enrollment",
            evidence_path=str(evidence),
        )
    except ImportError:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Install identity extras: pip install hipaa-audit[identity]",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.ERROR,
            message=f"Google API error: {exc}",
        )


def _google_external_sharing(check, *, identity, evidence_dir) -> CheckResult:
    creds = _google_creds(identity)
    if not creds:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="Google Workspace disabled",
        )
    # Drive sharing policies require Drive API — document as manual proxy via admin console export
    evidence = evidence_dir / "google-external-sharing.json"
    evidence.write_text(json.dumps({"note": "Verify Drive external sharing disabled in Admin console"}, indent=2))
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.MANUAL,
        message="Confirm Google Drive external sharing restricted (Admin → Drive → sharing)",
        evidence_path=str(evidence),
    )
