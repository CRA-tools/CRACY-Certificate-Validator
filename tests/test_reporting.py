"""The reports — console output, and the JSON that serves as evidence."""

import json
import os

from cracy_certval.analysis import build_family_groups, discover_scenarios
from cracy_certval.findings import Classification, Finding, Severity
from cracy_certval.reporting import (
    build_json_report,
    print_family_report,
    serialize_finding,
    write_json_report,
)


def _report(invalid_chains):
    scenarios = discover_scenarios(invalid_chains)
    grouped = build_family_groups(scenarios, invalid_chains)

    return build_json_report(grouped, invalid_chains, "2026-01-01T00:00:00Z")


def test_report_has_the_documented_shape(invalid_chains):
    report = _report(invalid_chains)

    assert set(report) == {"generated_at", "scan_root", "summary", "families"}
    assert report["generated_at"] == "2026-01-01T00:00:00Z"
    assert report["scan_root"] == os.path.abspath(invalid_chains)


def test_family_entries_have_the_documented_shape(invalid_chains):
    for family in _report(invalid_chains)["families"]:
        assert set(family) == {"family", "variants", "results", "summary"}
        assert family["variants"]
        assert family["results"]


def test_result_entries_have_the_documented_shape(invalid_chains):
    fields = {
        "variant", "valid", "classification", "severity", "reason",
        "diagnostics", "chain",
    }

    for family in _report(invalid_chains)["families"]:
        for result in family["results"]:
            assert set(result) == fields


def test_summary_counts_reconcile_with_the_results(invalid_chains):
    """A summary that disagrees with its own detail is not evidence."""
    report = _report(invalid_chains)

    total = 0

    for family in report["families"]:
        assert sum(family["summary"].values()) == len(family["results"])
        total += len(family["results"])

    assert sum(report["summary"].values()) == total


def test_report_is_json_serialisable(tmp_path, invalid_chains):
    path = write_json_report(
        _report(invalid_chains), str(tmp_path / "report.json")
    )

    with open(path, encoding="utf-8") as handle:
        assert json.load(handle)["families"]


def test_chain_is_rendered_as_subject_dns(ordered_chain):
    finding = Finding(
        classification=Classification.VALID,
        severity=Severity.NONE,
        reason="fine",
        path=ordered_chain,
        valid=True,
    )

    assert serialize_finding(finding)["chain"] == [
        "CN=example.com",
        "CN=Intermediate-2",
        "CN=Intermediate-1",
        "CN=RootCA",
    ]


def test_unreadable_certificates_do_not_break_serialisation():
    finding = Finding(
        classification=Classification.CORRUPTED_CERTIFICATE,
        severity=Severity.CRITICAL,
        reason="broken",
        path=[b"not a certificate"],
    )

    assert serialize_finding(finding)["chain"] == ["<unreadable>"]


def test_diagnostics_are_carried_through_verbatim(invalid_chains):
    """The raw OpenSSL output is what makes a classification auditable."""
    report = _report(invalid_chains)

    families = {f["family"]: f for f in report["families"]}
    expired = families[Classification.EXPIRED_LEAF]["results"][0]

    assert expired["diagnostics"]


def test_console_report_names_the_family_and_its_findings(capsys,
                                                          invalid_chains):
    scenarios = discover_scenarios(invalid_chains)
    grouped = build_family_groups(scenarios, invalid_chains)

    family = Classification.ROOT_HASH_MISMATCH
    print_family_report(family, grouped[family])

    out = capsys.readouterr().out

    assert family in out
    assert "SEVERITY" in out.upper()
    assert Severity.CRITICAL in out
    assert "CN=RootCA" in out


def test_console_report_handles_a_bundle_with_no_chain(capsys):
    finding = Finding(
        classification=Classification.CA_BUNDLE,
        severity=Severity.NONE,
        reason="a bundle",
        bundle_count=3,
    )

    print_family_report(Classification.CA_BUNDLE, [finding])

    assert "CA bundle contains 3 certificates" in capsys.readouterr().out
