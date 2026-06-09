from __future__ import annotations

import json
from typing import Any, Callable

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
    handlers: dict[str, Callable] = {
        "cloudtrail_enabled": _cloudtrail_enabled,
        "cloudtrail_log_validation": _cloudtrail_log_validation,
        "s3_public_access_blocked": _s3_public_access_blocked,
        "s3_default_encryption": _s3_default_encryption,
        "rds_encryption": _rds_encryption,
        "rds_backup_enabled": _rds_backup_enabled,
        "kms_rotation": _kms_rotation,
        "guardduty_enabled": _guardduty_enabled,
        "security_hub_enabled": _security_hub_enabled,
        "config_recorder_enabled": _config_recorder_enabled,
        "iam_root_mfa": _iam_root_mfa,
        "iam_password_policy": _iam_password_policy,
        "vpc_flow_logs": _vpc_flow_logs,
        "ebs_encryption_by_default": _ebs_encryption_by_default,
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


def _write_evidence(evidence_dir, name: str, data: Any) -> str:
    path = evidence_dir / name
    path.write_text(json.dumps(data, indent=2, default=str))
    return str(path)


def _cloudtrail_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("cloudtrail", region_name=region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    evidence = _write_evidence(evidence_dir, "aws-cloudtrail.json", trails)
    if multi_region:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"{len(multi_region)} multi-region trail(s) configured",
            evidence_path=evidence,
        )
    if trails:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.WARN,
            message="CloudTrail exists but no multi-region trail",
            evidence_path=evidence,
            remediation="Enable a multi-region organization trail",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message="No CloudTrail trails found",
        evidence_path=evidence,
        remediation="Enable CloudTrail with log file validation",
    )


def _cloudtrail_log_validation(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("cloudtrail", region_name=region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    bad = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
    evidence = _write_evidence(evidence_dir, "aws-cloudtrail-validation.json", bad)
    if trails and not bad:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All trails have log file validation enabled",
            evidence_path=evidence,
        )
    if not trails:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message="No CloudTrail trails",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"Trails without log validation: {', '.join(bad)}",
        evidence_path=evidence,
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
    evidence = _write_evidence(evidence_dir, "aws-s3-public-access.json", findings)
    if not findings:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All S3 buckets have public access block enabled",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"{len(findings)} bucket(s) without full public access block",
        evidence_path=evidence,
        remediation="Enable S3 Block Public Access on all buckets",
    )


def _s3_default_encryption(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("s3", region_name=region)
    missing = []
    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            enc = client.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                missing.append(name)
        except client.exceptions.ClientError:
            missing.append(name)
    evidence = _write_evidence(evidence_dir, "aws-s3-encryption.json", missing)
    if not missing:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All S3 buckets have default encryption",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"{len(missing)} bucket(s) without default encryption",
        evidence_path=evidence,
    )


def _rds_encryption(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("rds", region_name=region)
    unencrypted = [
        inst["DBInstanceIdentifier"]
        for inst in client.describe_db_instances().get("DBInstances", [])
        if not inst.get("StorageEncrypted")
    ]
    evidence = _write_evidence(evidence_dir, "aws-rds-encryption.json", unencrypted)
    if not unencrypted:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="All RDS instances use storage encryption",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"Unencrypted RDS: {', '.join(unencrypted)}",
        evidence_path=evidence,
    )


def _rds_backup_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("rds", region_name=region)
    no_backup = [
        inst["DBInstanceIdentifier"]
        for inst in client.describe_db_instances().get("DBInstances", [])
        if inst.get("BackupRetentionPeriod", 0) < 1
    ]
    evidence = _write_evidence(evidence_dir, "aws-rds-backup.json", no_backup)
    if not no_backup:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="RDS backup retention configured",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"RDS without backup: {', '.join(no_backup)}",
        evidence_path=evidence,
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
    evidence = _write_evidence(evidence_dir, "aws-kms-rotation.json", disabled)
    if not disabled:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Customer KMS keys have rotation enabled",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message=f"{len(disabled)} KMS key(s) without auto-rotation",
        evidence_path=evidence,
    )


def _guardduty_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("guardduty", region_name=region)
    detectors = client.list_detectors().get("DetectorIds", [])
    evidence = _write_evidence(evidence_dir, "aws-guardduty.json", detectors)
    if detectors:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="GuardDuty detector enabled",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="GuardDuty not enabled in this region",
        evidence_path=evidence,
    )


def _security_hub_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("securityhub", region_name=region)
    try:
        hubs = client.describe_hub().get("HubArn")
        enabled = bool(hubs)
        data = {"hub_arn": hubs}
    except client.exceptions.ClientError as exc:
        enabled = False
        data = {"error": str(exc)}
    evidence = _write_evidence(evidence_dir, "aws-securityhub.json", data)
    if enabled:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Security Hub enabled",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="Security Hub not enabled",
        evidence_path=evidence,
    )


def _config_recorder_enabled(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("config", region_name=region)
    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    active = [r["name"] for r in recorders if r.get("recordingGroup")]
    evidence = _write_evidence(evidence_dir, "aws-config.json", recorders)
    if active:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message=f"{len(active)} AWS Config recorder(s)",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message="No AWS Config recorder",
        evidence_path=evidence,
    )


def _iam_root_mfa(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("iam", region_name=region)
    summary = client.get_account_summary()["SummaryMap"]
    mfa = summary.get("AccountMFAEnabled", 0)
    root_keys = summary.get("AccountAccessKeysPresent", 0)
    data = {"account_mfa_enabled": mfa, "root_access_keys": root_keys}
    evidence = _write_evidence(evidence_dir, "aws-iam-root.json", data)
    if mfa == 1 and root_keys == 0:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="Root MFA enabled, no root access keys",
            evidence_path=evidence,
        )
    issues = []
    if mfa != 1:
        issues.append("root MFA disabled")
    if root_keys:
        issues.append("root access keys present")
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message="; ".join(issues),
        evidence_path=evidence,
    )


def _iam_password_policy(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    client = boto3.client("iam", region_name=region)
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.FAIL,
            message="No IAM account password policy",
            remediation="Set minimum length 14, require symbols and rotation",
        )
    evidence = _write_evidence(evidence_dir, "aws-iam-password-policy.json", policy)
    ok = (
        policy.get("MinimumPasswordLength", 0) >= 14
        and policy.get("RequireSymbols")
        and policy.get("MaxPasswordAge", 0) > 0
    )
    if ok:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="IAM password policy meets baseline",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.WARN,
        message="IAM password policy below recommended baseline (14+ chars, symbols, max age)",
        evidence_path=evidence,
    )


def _vpc_flow_logs(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    ec2 = boto3.client("ec2", region_name=region)
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    logs = ec2.describe_flow_logs().get("FlowLogs", [])
    covered = {fl.get("ResourceId") for fl in logs if fl.get("FlowLogStatus") == "ACTIVE"}
    missing = [v["VpcId"] for v in vpcs if v["VpcId"] not in covered]
    evidence = _write_evidence(evidence_dir, "aws-vpc-flow-logs.json", {"missing": missing})
    if vpcs and not missing:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="VPC flow logs on all VPCs",
            evidence_path=evidence,
        )
    if not vpcs:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="No VPCs in region",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message=f"VPCs without flow logs: {', '.join(missing)}",
        evidence_path=evidence,
    )


def _ebs_encryption_by_default(check, *, region, config, evidence_dir) -> CheckResult:
    import boto3

    ec2 = boto3.client("ec2", region_name=region)
    try:
        enc = ec2.get_ebs_encryption_by_default()
        enabled = enc.get("EbsEncryptionByDefault", False)
    except Exception as exc:  # noqa: BLE001
        enabled = False
        enc = {"error": str(exc)}
    evidence = _write_evidence(evidence_dir, "aws-ebs-encryption-default.json", enc)
    if enabled:
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.PASS,
            message="EBS encryption by default enabled",
            evidence_path=evidence,
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.FAIL,
        message="EBS encryption by default disabled",
        evidence_path=evidence,
    )
