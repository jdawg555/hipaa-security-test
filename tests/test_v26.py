from pathlib import Path
from unittest.mock import patch

import pytest

from hipaa_audit.apps import discover_azure_ad_apps
from hipaa_audit.checks.aws import _regions_to_scan
from hipaa_audit.oauth_connect import authorize_url, new_oauth_state, oauth_available
from hipaa_audit.personnel import sync_workforce_hris


def test_regions_to_scan_single_region():
    assert _regions_to_scan({"region": "us-west-2"}) == ["us-west-2"]


def test_regions_to_scan_explicit_list():
    assert _regions_to_scan({"regions": ["eu-west-1", "us-east-1"]}) == ["eu-west-1", "us-east-1"]


def test_oauth_github_authorize_url():
    secrets = {
        "github_oauth_client_id": "cid",
        "github_oauth_client_secret": "csec",
    }
    assert oauth_available("github", secrets=secrets)
    url = authorize_url(
        "github",
        redirect_uri="http://127.0.0.1:8787/integrations/oauth/github/callback",
        state=new_oauth_state(),
        secrets=secrets,
    )
    assert url and "github.com/login/oauth/authorize" in url
    assert "client_id=cid" in url


def test_sync_workforce_hris(tmp_path):
    ack = tmp_path / "ack.yaml"
    ack.write_text("policies: []\nworkforce: []\nacknowledgments: []\n")
    count = sync_workforce_hris(
        ack,
        [{"id": "EMP100", "email": "a@test.com", "active": True}],
    )
    assert count == 1
    import yaml

    data = yaml.safe_load(ack.read_text())
    assert data["workforce"][0]["id"] == "EMP100"
    assert data["workforce"][0].get("ack_token")


def test_discover_azure_ad_apps_mocked():
    config = {"identity": {"azure": {"enabled": True}}}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"value": [{"displayName": "Salesforce", "appId": "app-1"}]}

    with patch("hipaa_audit.azure_graph.graph_token_from_env", return_value="tok"):
        with patch("httpx.get", return_value=FakeResp()):
            apps = discover_azure_ad_apps(config)
    assert len(apps) == 1
    assert apps[0]["provider"] == "azure_ad"


def test_rippling_adapter_missing_env():
    from hipaa_audit.platform.adapters.rippling import RipplingAdapter

    result = RipplingAdapter().test_connection({})
    assert not result.ok
    assert "RIPPLING_API_TOKEN" in result.message
