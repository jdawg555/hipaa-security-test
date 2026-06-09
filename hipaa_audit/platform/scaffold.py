from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hipaa_audit.controls import PACKAGE_ROOT

CHECK_MODULE_TEMPLATE = '''from __future__ import annotations

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
    cfg = config.get("{module_snake}", {{}})
    if not cfg.get("enabled", False):
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.SKIP,
            message="{module_title} checks disabled",
        )
    handler = check.get("handler", "{module_snake}_placeholder")
    if handler == "{module_snake}_placeholder":
        return CheckResult(
            check_id=check["id"],
            title=check.get("title", check["id"]),
            status=CheckStatus.MANUAL,
            message="TODO: implement {module_snake} check",
        )
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", check["id"]),
        status=CheckStatus.ERROR,
        message=f"Unknown handler: {{handler}}",
    )
'''

DOMAIN_TEMPLATE = '''from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_{module_snake}(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {{"items": []}}
    return yaml.safe_load(path.read_text()) or {{"items": []}}


def save_{module_snake}(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))


def assess_{module_snake}(path: Path, config: dict[str, Any]) -> tuple[str, str, list[str]]:
    data = load_{module_snake}(path)
    if not data.get("items"):
        return "manual", "No {module_snake} register — add compliance/{module_snake}.yaml", []
    return "pass", "TODO: implement assessment", []
'''

ADAPTER_TEMPLATE = '''from __future__ import annotations

import os
from typing import Any

from hipaa_audit.platform.adapters.base import ConnectionResult, IntegrationAdapter


class {adapter_class}(IntegrationAdapter):
    id = "{integration_id}"
    name = "{integration_name}"

    def test_connection(self, config: dict[str, Any]) -> ConnectionResult:
        # TODO: verify credentials and API reachability
        missing = [k for k in {env_vars!r} if not os.environ.get(k)]
        if missing:
            return ConnectionResult(False, f"Missing env: {{', '.join(missing)}}")
        return ConnectionResult(False, "TODO: implement connection test")
'''


def _snake(name: str) -> str:
    return name.replace("-", "_").lower()


def _title(name: str) -> str:
    return name.replace("_", " ").replace("-", " ").title()


def scaffold_module(repo_path: Path, module_name: str) -> list[Path]:
    """Scaffold check module + domain loader + example register."""
    snake = _snake(module_name)
    created: list[Path] = []

    check_path = PACKAGE_ROOT / "hipaa_audit" / "checks" / f"{snake}.py"
    if not check_path.exists():
        check_path.write_text(
            CHECK_MODULE_TEMPLATE.format(module_snake=snake, module_title=_title(snake))
        )
        created.append(check_path)

    domain_path = PACKAGE_ROOT / "hipaa_audit" / f"{snake}.py"
    if not domain_path.exists():
        domain_path.write_text(DOMAIN_TEMPLATE.format(module_snake=snake))
        created.append(domain_path)

    example = repo_path / "compliance" / f"{snake}.example.yaml"
    if not example.exists():
        example.parent.mkdir(parents=True, exist_ok=True)
        example.write_text(f"# {snake} register — copy to compliance/{snake}.yaml\n\nitems: []\n")
        created.append(example)

    manifest = repo_path / "platform" / "scaffold_output.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        yaml.dump(
            {
                "type": "module",
                "name": snake,
                "next_steps": [
                    f"Register runner in hipaa_audit/checks/base.py: {snake}",
                    f"Add control check in controls/hipaa-security-rule.yaml",
                    f"Add workspace route in workspace/server.py",
                    f"Update platform/capabilities.yaml",
                    "See docs/architecture/EXTENSION_MODEL.md",
                ],
                "created": [str(p) for p in created],
            },
            sort_keys=False,
        )
    )
    created.append(manifest)
    return created


def scaffold_integration(repo_path: Path, integration_id: str) -> list[Path]:
    """Scaffold integration adapter stub."""
    registry = yaml.safe_load((PACKAGE_ROOT / "platform" / "integrations_registry.yaml").read_text())
    entry = next(
        (i for i in registry.get("integrations", []) if i.get("id") == integration_id),
        None,
    )
    name = entry["name"] if entry else _title(integration_id)
    env_vars = entry.get("env_vars", []) if entry else []

    class_name = "".join(part.capitalize() for part in integration_id.split("_")) + "Adapter"
    adapter_path = PACKAGE_ROOT / "hipaa_audit" / "platform" / "adapters" / f"{integration_id}.py"
    created: list[Path] = []
    if not adapter_path.exists():
        adapter_path.write_text(
            ADAPTER_TEMPLATE.format(
                adapter_class=class_name,
                integration_id=integration_id,
                integration_name=name,
                env_vars=env_vars,
            )
        )
        created.append(adapter_path)

    manifest = repo_path / "platform" / f"scaffold-{integration_id}.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        yaml.dump(
            {
                "type": "integration",
                "id": integration_id,
                "next_steps": [
                    "Implement test_connection() in adapter",
                    f"Add entry to platform/integrations_registry.yaml if missing",
                    "Wire connection test in workspace Integrations page (Phase 2)",
                    "Update docs/roadmap/PARITY.md row",
                ],
                "created": [str(p) for p in created],
            },
            sort_keys=False,
        )
    )
    created.append(manifest)
    return created
