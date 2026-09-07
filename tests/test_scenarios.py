"""The corruption scenarios themselves."""

import os

import pytest

from cracy_certval.certs import cert_sha256, cert_sha256_safe, is_ca, is_expired
from cracy_certval.chains import find_root
from cracy_certval.invalidate import parse_positions, parse_scenarios
from cracy_certval.scenarios import (
    POSITION_SCENARIOS,
    SCENARIOS,
    apply_scenario,
    corrupt_cert,
    random_fingerprint,
)


def test_every_scenario_has_a_name():
    assert set(SCENARIOS) == {str(n) for n in range(1, 9)}
    assert len(set(SCENARIOS.values())) == len(SCENARIOS)


def test_position_scenarios_are_a_subset():
    assert POSITION_SCENARIOS <= set(SCENARIOS)


def test_corruption_keeps_the_pem_framing(leaf):
    """Destroying the END line would bleed the corrupted block into the next
    certificate; the framing has to survive so the damage stays local."""
    corrupted = corrupt_cert(leaf)

    assert corrupted.startswith(b"-----BEGIN CERTIFICATE-----")
    assert corrupted.rstrip().endswith(b"-----END CERTIFICATE-----")
    assert cert_sha256_safe(corrupted) is None


def test_corruption_of_an_unframed_block_still_breaks_it():
    assert corrupt_cert(b"not a pem file").endswith(b"CORRUPTED")


def test_random_fingerprint_avoids_the_excluded_value(root):
    actual = cert_sha256(root)
    generated = random_fingerprint(excluding=actual)

    assert generated != actual
    assert len(generated) == 64


def test_expired_server_scenario_expires_only_the_leaf(tmp_path,
                                                       ordered_chain, key_dir):
    _, chain, extras = apply_scenario(
        "1", ordered_chain, None, key_dir, str(tmp_path)
    )

    assert is_expired(chain[0])
    assert not any(is_expired(cert) for cert in chain[1:])
    assert extras == {}


def test_non_ca_scenario_strips_the_ca_constraint(tmp_path, ordered_chain,
                                                  key_dir):
    _, chain, _ = apply_scenario(
        "4", ordered_chain, 1, key_dir, str(tmp_path)
    )

    assert not is_ca(chain[1])
    assert not is_expired(chain[1]), "only the CA constraint should differ"


def test_missing_intermediate_scenario_drops_one_link(tmp_path, ordered_chain,
                                                      key_dir):
    _, chain, _ = apply_scenario(
        "5", ordered_chain, 1, key_dir, str(tmp_path)
    )

    assert len(chain) == len(ordered_chain) - 1


def test_root_hash_mismatch_leaves_the_chain_intact(tmp_path, ordered_chain,
                                                    key_dir):
    """Only the pin is wrong — that is the point of the scenario."""
    _, chain, extras = apply_scenario(
        "6", ordered_chain, None, key_dir, str(tmp_path)
    )

    assert [cert_sha256(c) for c in chain] == [
        cert_sha256(c) for c in ordered_chain
    ]
    assert extras["root_hash.txt"].strip() != cert_sha256(find_root(chain))


def test_root_hash_not_checked_emits_no_pin(tmp_path, ordered_chain, key_dir):
    _, chain, extras = apply_scenario(
        "7", ordered_chain, None, key_dir, str(tmp_path)
    )

    assert extras == {}
    assert [cert_sha256(c) for c in chain] == [
        cert_sha256(c) for c in ordered_chain
    ]


def test_expired_root_scenario_expires_the_anchor(tmp_path, ordered_chain,
                                                  key_dir):
    _, chain, _ = apply_scenario(
        "8", ordered_chain, None, key_dir, str(tmp_path)
    )

    root = find_root(chain)

    assert root is not None
    assert is_expired(root)


def test_position_scenarios_reject_an_out_of_range_position(tmp_path,
                                                            ordered_chain,
                                                            key_dir):
    for choice in sorted(POSITION_SCENARIOS):
        for position in (None, 0, len(ordered_chain)):
            with pytest.raises(SystemExit):
                apply_scenario(
                    choice, ordered_chain, position, key_dir, str(tmp_path)
                )


def test_scenario_output_directory_records_the_position(tmp_path,
                                                        ordered_chain,
                                                        key_dir):
    out_dir, _, _ = apply_scenario(
        "5", ordered_chain, 2, key_dir, str(tmp_path)
    )

    assert out_dir == os.path.join(
        str(tmp_path), "missing_intermediate", "int2"
    )


def test_the_source_chain_is_never_modified(tmp_path, ordered_chain, key_dir):
    before = [cert_sha256(cert) for cert in ordered_chain]

    apply_scenario("1", ordered_chain, None, key_dir, str(tmp_path))
    apply_scenario("5", ordered_chain, 1, key_dir, str(tmp_path))

    assert [cert_sha256(cert) for cert in ordered_chain] == before


# Selection parsing

def test_all_selects_every_scenario():
    assert parse_scenarios("all") == list(SCENARIOS)


def test_scenarios_selected_by_number_and_by_name():
    assert parse_scenarios("1,2,5") == ["1", "2", "5"]
    assert parse_scenarios("expired_server,corrupted_server") == ["1", "2"]
    assert parse_scenarios(" EXPIRED_ROOT ") == ["8"]


def test_scenario_selection_is_deduplicated_in_order():
    assert parse_scenarios("2,1,2,expired_server") == ["2", "1"]


@pytest.mark.parametrize("raw", ["", "9", "nonsense", "1,nonsense", ","])
def test_invalid_scenario_selection_is_rejected(raw):
    with pytest.raises(SystemExit):
        parse_scenarios(raw)


def test_positions_are_parsed_and_deduplicated():
    assert parse_positions("2,1,2") == [2, 1]
    assert parse_positions("") == []


@pytest.mark.parametrize("raw", ["a", "1,a", "-1"])
def test_invalid_positions_are_rejected(raw):
    with pytest.raises(SystemExit):
        parse_positions(raw)
