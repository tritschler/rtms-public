from plugins.typo3_cms.typo3_cms_cve_2026_119623_audit import (
    Typo3CmsAuditPlugin,
    is_typo3_version_vulnerable,
    parse_typo3_version,
)


def test_parse_typo3_version():
    assert parse_typo3_version("TYPO3 CMS 13.4.39") == (13, 4, 39, "13.4.39")
    assert parse_typo3_version("TYPO3 14.3.12") == (14, 3, 12, "14.3.12")
    assert parse_typo3_version("") is None


def test_is_typo3_version_vulnerable():
    assert is_typo3_version_vulnerable(10, 4, 62)[0] is True
    assert is_typo3_version_vulnerable(11, 5, 56)[0] is True
    assert is_typo3_version_vulnerable(12, 4, 51)[0] is True
    assert is_typo3_version_vulnerable(13, 4, 39)[0] is True
    assert is_typo3_version_vulnerable(14, 3, 11)[0] is True
    assert is_typo3_version_vulnerable(14, 3, 12)[0] is False


def test_typo3_run_audit(mocker):
    plugin = Typo3CmsAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-119623"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "13.4.39",
            "source": "TYPO3 Generator Meta",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-119623",
        },
    )
    assert plugin.run_audit("10.0.0.20", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "13.4.40",
            "source": "TYPO3 Generator Meta",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.20", [443])["status"] == "OK"
