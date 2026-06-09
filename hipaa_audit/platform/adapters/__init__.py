"""External system adapters (Jamf, Intune, HRIS, etc.)."""

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter

__all__ = ["ConnectionResult", "IntegrationAdapter"]
