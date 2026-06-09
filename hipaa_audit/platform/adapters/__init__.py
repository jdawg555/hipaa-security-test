from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter
from hipaa_audit.platform.adapters.jamf import JamfAdapter
from hipaa_audit.platform.adapters.registry import (
    get_adapter,
    record_connection_test,
    test_integration_connection,
)

__all__ = [
    "ConnectionResult",
    "IntegrationAdapter",
    "JamfAdapter",
    "get_adapter",
    "record_connection_test",
    "test_integration_connection",
]
