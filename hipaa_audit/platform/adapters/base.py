from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ConnectionResult:
    ok: bool
    message: str
    details: dict[str, Any] | None = None


class IntegrationAdapter(ABC):
    """Base class for Vanta-style integration connectors.

    Implement:
    - test_connection: verify credentials work
    - discover (optional): pull inventory for registers
    """

    id: str = ""
    name: str = ""

    @abstractmethod
    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        """Verify the integration can reach the external system."""

    def discover(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Optional: return entities for SaaS/device/vendor registers."""
        return []
