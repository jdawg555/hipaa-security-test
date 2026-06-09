from __future__ import annotations

import json
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
    aws_config = config.get("aws", {})
    if not aws_config.get("enabled", False):
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="AWS checks disabled — set aws.enabled: true in hipaa-audit.yaml",
        )
    try:
        import boto3  # noqa: PLC0415
    except ImportError:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.SKIP,
            message="Install aws extras: pip install hipaa-audit[aws]",
        )

    region = aws_config.get("region", "us-east-1")
    handlers = {
        "cloudtrail_enabled": _cloudtrail_enabled,
        "s3_public_access_blocked": _s3_public_access_blocked,
        "rds_encryption": _rds_encryption,
        "kms_rotation": _kms_rotation,
        "guardduty_enabled": _guardduty_enabled,
    }
    handler = check.get("handler", check_id)
    fn = handlers.get(handler)
    if fn is None:
        return CheckResult(
            check_id=check_id,
            title=title,
            status=CheckStatus.ERROR,
            message=f"Unknown AWS handler: {handler}",
        )
    return fn(check, region=region, config=aws_config, evidence_dir=evidence_dir)


def _cloudtrail_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("cloudtrail", region_name=region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    evidence = evidence_dir / "aws-cloudtrail.json"
    evidence.write_text(json.dumps(trails, indent=2, default=str))
    if multi_region:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"{len(multi_region)} multi-region trail(s) configured",
            evidence_path=str(evidence),
        )
    if trails:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message="CloudTrail exists but no multi-region trail",
            evidence_path=str(evidence),
            remediation="Enable a multi-region organization trail",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message="No CloudTrail trails found",
        evidence_path=str(evidence),
        remediation="Enable CloudTrail with log file validation",
    )


def _s3_public_access_blocked(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("s3", region_name=region)
    findings = []
    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            block = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(
                block.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                findings.append(name)
        except client.exceptions.ClientError:
            findings.append(f"{name} (no block config)")
    evidence = evidence_dir / "aws-s3-public-access.json"
    evidence.write_text(json.dumps(findings, indent=2))
    if not findings:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All S3 buckets have public access block enabled",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"{len(findings)} bucket(s) without full public access block",
        evidence_path=str(evidence),
        remediation="Enable S3 Block Public Access on all buckets",
    )


def _rds_encryption(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("rds", region_name=region)
    unencrypted = []
    for inst in client.describe_db_instances().get("DBInstances", []):
        if not inst.get("StorageEncrypted"):
            unencrypted.append(inst["DBInstanceIdentifier"])
    evidence = evidence_dir / "aws-rds-encryption.json"
    evidence.write_text(json.dumps(unencrypted, indent=2))
    if not unencrypted:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All RDS instances use storage encryption",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"Unencrypted RDS: {', '.join(unencrypted)}",
        evidence_path=str(evidence),
        remediation="Enable encryption at rest on RDS instances",
    )


def _kms_rotation(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("kms", region_name=region)
    disabled = []
    for key in client.list_keys().get("Keys", []):
        meta = client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
        if meta.get("KeyManager") != "CUSTOMER":
            continue
        rot = client.get_key_rotation_status(KeyId=key["KeyId"])
        if not rot.get("KeyRotationEnabled"):
            disabled.append(meta.get("KeyId"))
    evidence = evidence_dir / "aws-kms-rotation.json"
    evidence.write_text(json.dumps(disabled, indent=2))
    if not disabled:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Customer KMS keys have rotation enabled",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message=f"{len(disabled)} KMS key(s) without auto-rotation",
        evidence_path=str(evidence),
        remediation="Enable annual rotation on customer-managed KMS keys",
    )


def _guardduty_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("guardduty", region_name=region)
    detectors = client.list_detectors().get("DetectorIds", [])
    evidence = evidence_dir / "aws-guardduty.json"
    evidence.write_text(json.dumps(detectors, indent=2))
    if detectors:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GuardDuty detector enabled",
            evidence_path=str(evidence),
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="GuardDuty not enabled in this region",
        evidence_path=str(evidence),
        remediation="Enable GuardDuty for threat detection",
    )
