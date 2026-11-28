from plugins.gcp_managed_services.gcp_managed_services_cve_2026_106169_audit import (
    GCPManagedServicesAuditPlugin,
    is_gcp_revision_vulnerable,
    parse_gcp_revision_date,
)


def test_parse_gcp_revision_date():
    assert parse_gcp_revision_date("2026-04-01") == (2026, 4, 1)
    assert parse_gcp_revision_date("2026-09-25") == (2026, 9, 25)
    assert parse_gcp_revision_date("") is None


def test_is_gcp_revision_vulnerable():
    assert is_gcp_revision_vulnerable((2026, 4, 1))[0] is True
    assert is_gcp_revision_vulnerable((2026, 9, 25))[0] is False


def test_gcp_managed_services_run_audit():
    res_v = GCPManagedServicesAuditPlugin("gcp.local", {"revision_date": "2026-04-01"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-106169" in res_v["cve"]
    assert "CVE-2026-85258" in res_v["cve"]
    assert "CVE-2026-110739" in res_v["cve"]

    res_ok = GCPManagedServicesAuditPlugin("gcp.local", {"revision_date": "2026-09-25"}).run_audit()
    assert res_ok["status"] == "OK"
