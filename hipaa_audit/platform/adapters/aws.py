from __future__ import annotations

from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class AwsAdapter(IntegrationAdapter):
    id = "aws"
    name = "Amazon Web Services"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        if not config.get("aws", {}).get("enabled", False):
            return ConnectionResult(False, "AWS integration is disabled — enable it first")
        try:
            import boto3  # noqa: PLC0415
        except ImportError:
            return ConnectionResult(False, "Install aws extras: pip install hipaa-audit[aws]")
        region = config.get("aws", {}).get("region", "us-east-1")
        try:
            identity = boto3.client("sts", region_name=region).get_caller_identity()
            arn = identity.get("Arn", "unknown")
            return ConnectionResult(True, f"Connected as {arn}", {"account": identity.get("Account")})
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(False, f"AWS connection failed: {exc}")
