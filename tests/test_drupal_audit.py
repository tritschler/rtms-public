from plugins.drupal.drupal_cve_2026_136716_audit import (
    DrupalCoreAuditPlugin,
    is_drupal_version_vulnerable,
    parse_drupal_version,
)


def test_parse_drupal_version():
    assert parse_drupal_version("Drupal 10.6.23") == (10, 6, 23)
    assert parse_drupal_version("11.4.14") == (11, 4, 14)
    assert parse_drupal_version("") is None


def test_is_drupal_version_vulnerable():
    assert is_drupal_version_vulnerable((10, 6, 22))[0] is True
    assert is_drupal_version_vulnerable((10, 6, 23))[0] is True
    assert is_drupal_version_vulnerable((10, 6, 24))[0] is False
    assert is_drupal_version_vulnerable((11, 3, 23))[0] is True
    assert is_drupal_version_vulnerable((11, 3, 24))[0] is False
    assert is_drupal_version_vulnerable((11, 4, 14))[0] is True
    assert is_drupal_version_vulnerable((11, 4, 15))[0] is False


def test_drupal_run_audit():
    res_v = DrupalCoreAuditPlugin("drupal.local", {"drupal_version": "10.6.22"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-136716" in res_v["cve"]
    assert "CVE-2026-132165" in res_v["cve"]

    res_ok = DrupalCoreAuditPlugin("drupal.local", {"drupal_version": "11.4.15"}).run_audit()
    assert res_ok["status"] == "OK"
