"""Classification: what the reference validator concludes about a chain."""

import os

import pytest

from cracy_certval.analysis import (
    analyze_scenario,
    build_family_groups,
    classify_failure,
    discover_scenarios,
    find_non_ca_intermediates,
    variant_name,
)
from cracy_certval.findings import Classification, Severity

# Each scenario is expected to produce a specific classification. This
# mapping is the contract between the two halves of the toolkit: it is what
# lets a product's own verdict be compared against a known-good reference.
EXPECTED = {
    "expired_server": Classification.EXPIRED_LEAF,
    "corrupted_server": Classification.CORRUPTED_CERTIFICATE,
    "expired_intermediate/int1": Classification.EXPIRED_INTERMEDIATE,
    "non_ca_intermediate/int1": Classification.NON_CA_INTERMEDIATE,
    "missing_intermediate/int1": Classification.MISSING_INTERMEDIATE,
    "root_hash_mismatch": Classification.ROOT_HASH_MISMATCH,
    "root_hash_not_checked": Classification.ROOT_HASH_NOT_CHECKED,
    "expired_root": Classification.EXPIRED_ROOT,
}


@pytest.mark.parametrize("scenario,classification", sorted(EXPECTED.items()))
def test_every_scenario_is_classified_as_intended(invalid_chains, scenario,
                                                  classification):
    folder = os.path.join(invalid_chains, *scenario.split("/"))

    findings = analyze_scenario(folder, invalid_chains)

    assert findings, f"no findings for {scenario}"
    assert classification in {f.classification for f in findings}


def test_no_scenario_is_reported_as_valid(invalid_chains):
    """Every corrupted chain must be rejected — that is the whole point."""
    for scenario in EXPECTED:
        folder = os.path.join(invalid_chains, *scenario.split("/"))

        for finding in analyze_scenario(folder, invalid_chains):
            assert not finding.valid, f"{scenario} was accepted as valid"


def test_a_pinned_valid_chain_is_valid(valid_chain):
    findings = analyze_scenario(valid_chain, valid_chain)

    assert len(findings) == 1
    assert findings[0].classification == Classification.VALID
    assert findings[0].severity == Severity.NONE
    assert findings[0].valid


def test_a_multi_pem_chain_is_analysed_as_one_scenario(multi_chain):
    """leaf/, intermediates/ and root/ are one chain, not three inputs."""
    scenarios = discover_scenarios(multi_chain)

    assert scenarios == [os.path.abspath(multi_chain)]

    findings = analyze_scenario(multi_chain, multi_chain)

    assert [f.classification for f in findings] == [Classification.VALID]


def test_an_unpinned_valid_chain_is_flagged(tmp_path, ordered_chain):
    """A chain nobody pinned is not trustworthy, however well it verifies."""
    from cracy_certval.chains import write_pem_bundle

    write_pem_bundle(ordered_chain, str(tmp_path / "chain.pem"))

    findings = analyze_scenario(str(tmp_path), str(tmp_path))

    assert [f.classification for f in findings] == [
        Classification.ROOT_HASH_NOT_CHECKED
    ]
    assert findings[0].severity == Severity.HIGH


def test_root_hash_mismatch_is_critical(invalid_chains):
    folder = os.path.join(invalid_chains, "root_hash_mismatch")

    finding = analyze_scenario(folder, invalid_chains)[0]

    assert finding.classification == Classification.ROOT_HASH_MISMATCH
    assert finding.severity == Severity.CRITICAL
    assert "expected" in finding.reason


def test_a_ca_bundle_is_reported_as_such(tmp_path, ordered_chain):
    from cracy_certval.chains import write_pem_bundle

    write_pem_bundle(ordered_chain[1:], str(tmp_path / "ca-bundle.pem"))

    findings = analyze_scenario(str(tmp_path), str(tmp_path))

    assert [f.classification for f in findings] == [Classification.CA_BUNDLE]
    assert findings[0].bundle_count == 3


def test_a_fully_corrupted_bundle_is_critical(tmp_path, leaf):
    from cracy_certval.scenarios import corrupt_cert

    (tmp_path / "broken.pem").write_bytes(corrupt_cert(leaf))

    findings = analyze_scenario(str(tmp_path), str(tmp_path))

    assert [f.classification for f in findings] == [
        Classification.CORRUPTED_CERTIFICATE
    ]
    assert findings[0].severity == Severity.CRITICAL


def test_an_empty_directory_yields_no_findings(tmp_path):
    assert analyze_scenario(str(tmp_path), str(tmp_path)) == []
    assert discover_scenarios(str(tmp_path)) == []


def test_a_single_file_is_analysed_alone(tmp_path, ordered_chain):
    """Pointing at one file must not drag in its neighbours."""
    from cracy_certval.chains import write_pem_bundle

    write_pem_bundle(ordered_chain, str(tmp_path / "chain.pem"))
    write_pem_bundle(ordered_chain[:1], str(tmp_path / "unrelated.pem"))

    scenarios = discover_scenarios(str(tmp_path / "chain.pem"))

    assert scenarios == [os.path.abspath(str(tmp_path / "chain.pem"))]


def test_expiry_is_preferred_over_the_openssl_message(ordered_chain,
                                                      invalid_chains):
    """A property read off the certificate beats a diagnostic string.

    OpenSSL words an expired intermediate and a missing one similarly, so
    classification examines the certificates first.
    """
    from cracy_certval.certs import find_pem_certs

    folder = os.path.join(invalid_chains, "expired_intermediate", "int1")

    with open(os.path.join(folder, "invalid_chain.pem"), "rb") as handle:
        certs = find_pem_certs(handle.read())

    from cracy_certval.chains import build_paths

    path = build_paths(certs)[0]

    classification, severity, reason = classify_failure(
        path, "unable to get local issuer certificate", certs
    )

    assert classification == Classification.EXPIRED_INTERMEDIATE
    assert severity == Severity.HIGH
    assert "Intermediate" in reason


@pytest.mark.parametrize(
    "diagnostics,classification",
    [
        ("unable to load certificate", Classification.CORRUPTED_CERTIFICATE),
        ("certificate signature failure", Classification.INVALID_SIGNATURE),
        ("invalid CA certificate", Classification.NON_CA_INTERMEDIATE),
        ("path length constraint exceeded", Classification.NON_CA_INTERMEDIATE),
        ("unable to get local issuer certificate",
         Classification.MISSING_INTERMEDIATE),
        ("self signed certificate", Classification.SELF_SIGNED),
        ("unable to verify the first certificate",
         Classification.UNTRUSTED_ROOT),
        ("something nobody has seen before", Classification.UNKNOWN_FAILURE),
    ],
)
def test_openssl_diagnostics_are_mapped_onto_the_taxonomy(ordered_chain,
                                                          diagnostics,
                                                          classification):
    # A chain with nothing wrong with its certificates, so classification
    # falls through to the diagnostics table.
    result, _, _ = classify_failure(ordered_chain, diagnostics, ordered_chain)

    assert result == classification


def test_non_ca_intermediates_are_recovered_from_the_bundle(invalid_chains):
    """The defect is in the bundle even though the chain looks incomplete."""
    from cracy_certval.certs import find_pem_certs
    from cracy_certval.chains import build_paths

    folder = os.path.join(invalid_chains, "non_ca_intermediate", "int1")

    with open(os.path.join(folder, "invalid_chain.pem"), "rb") as handle:
        certs = find_pem_certs(handle.read())

    path = build_paths(certs)[0]

    assert find_non_ca_intermediates(path, certs)


@pytest.mark.parametrize(
    "folder,expected",
    [("int1", "INT1"), ("INT12", "INT12"), ("expired_root", "DEFAULT")],
)
def test_variant_names_come_from_the_position_folder(folder, expected):
    assert variant_name(os.path.join("invalid_chain", "x", folder)) == expected


def test_families_are_grouped_by_detected_classification(invalid_chains):
    """A folder's name never decides its family; the analysis does."""
    scenarios = discover_scenarios(invalid_chains)
    grouped = build_family_groups(scenarios, invalid_chains)

    for classification, findings in grouped.items():
        assert all(f.classification == classification for f in findings)
        assert all(f.scenario for f in findings)

    for expected in EXPECTED.values():
        assert expected in grouped
