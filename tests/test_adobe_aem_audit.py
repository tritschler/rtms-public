from plugins.adobe_aem.adobe_aem_cve_2026_132877_audit import (
    AdobeAEMAuditPlugin,
    is_adobe_aem_version_vulnerable,
    parse_adobe_aem_version,
)


def test_parse_adobe_aem_version():
    assert parse_adobe_aem_version("Adobe Experience Manager 6.5.26") == (6, 5, 26, "6.5.26")
    assert parse_adobe_aem_version("AEM 6.5.27") == (6, 5, 27, "6.5.27")
    assert parse_adobe_aem_version("") is None


def test_is_adobe_aem_version_vulnerable():
    assert is_adobe_aem_version_vulnerable(6, 5, 26)[0] is True
    assert is_adobe_aem_version_vulnerable(6, 5, 27)[0] is False


def test_adobe_aem_run_audit(mocker):
    plugin = AdobeAEMAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-132877"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4502,
            "service_detected": True,
            "version": "6.5.25",
            "source": "AEM Login",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-132877 and CVE-2026-123266",
        },
    )
    assert plugin.run_audit("10.0.0.14", [4502])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4502,
            "service_detected": True,
            "version": "6.5.27",
            "source": "AEM Login",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.14", [4502])["status"] == "OK"
