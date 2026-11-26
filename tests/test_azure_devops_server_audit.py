from plugins.azure_devops_server.azure_devops_server_cve_2026_109467_audit import (
    AzureDevOpsServerAuditPlugin,
    is_azure_devops_version_vulnerable,
    parse_azure_devops_version,
)


def test_parse_azure_devops_version():
    assert parse_azure_devops_version("Azure DevOps Server 2025 Patch 7") == (2025, 7, "2025 Patch 7")
    assert parse_azure_devops_version("invalid") is None


def test_is_azure_devops_version_vulnerable():
    assert is_azure_devops_version_vulnerable(2025, 8)[0] is True
    assert is_azure_devops_version_vulnerable(2025, 9)[0] is False


def test_azure_devops_run_audit(mocker):
    plugin = AzureDevOpsServerAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-109467"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2025 Patch 6",
            "source": "Azure DevOps Header",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-109467",
        },
    )
    assert plugin.run_audit("10.0.0.13", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2025 Patch 9",
            "source": "Azure DevOps Header",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.13", [443])["status"] == "OK"
