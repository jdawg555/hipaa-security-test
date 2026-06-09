"""Parity matrix, integration registry, and feature scaffolding."""

from hipaa_audit.platform.parity import load_capabilities, load_integrations, parity_report
from hipaa_audit.platform.scaffold import scaffold_integration, scaffold_module

__all__ = [
    "load_capabilities",
    "load_integrations",
    "parity_report",
    "scaffold_integration",
    "scaffold_module",
]
