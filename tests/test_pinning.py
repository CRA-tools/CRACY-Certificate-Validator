"""The trust-anchor pin."""

import os

from cracy_certval.certs import cert_sha256
from cracy_certval.pinning import (
    PIN_FILENAME,
    find_pin_file,
    read_pin,
    resolve_pin_path,
    verify_pin,
    write_pin,
)


def test_generated_pin_matches_the_root(valid_chain, root):
    pinned = read_pin(os.path.join(valid_chain, PIN_FILENAME))

    assert pinned == cert_sha256(root)
    assert verify_pin(root, pinned)


def test_pin_does_not_match_another_certificate(valid_chain, leaf):
    pinned = read_pin(os.path.join(valid_chain, PIN_FILENAME))

    assert not verify_pin(leaf, pinned)


def test_pin_is_read_out_of_surrounding_text(tmp_path, root):
    fingerprint = cert_sha256(root)
    path = tmp_path / PIN_FILENAME
    path.write_text(f"# root of trust\nSHA256 = {fingerprint.upper()}\n")

    assert read_pin(str(path)) == fingerprint


def test_pin_file_without_a_digest_reads_as_none(tmp_path):
    path = tmp_path / PIN_FILENAME
    path.write_text("no fingerprint here\n")

    assert read_pin(str(path)) is None


def test_missing_pin_file_reads_as_none(tmp_path):
    assert read_pin(str(tmp_path / "absent.txt")) is None


def test_write_pin_round_trips(tmp_path, root):
    fingerprint = cert_sha256(root)

    assert read_pin(write_pin(str(tmp_path), fingerprint)) == fingerprint


def test_pin_is_found_from_a_nested_scenario(tmp_path, root):
    """A corruption scenario nested under a chain still finds its pin."""
    write_pin(str(tmp_path), cert_sha256(root))

    nested = tmp_path / "non_ca_intermediate" / "int1"
    nested.mkdir(parents=True)

    assert find_pin_file(str(nested)) == str(tmp_path / PIN_FILENAME)


def test_ceiling_stops_the_upward_search(tmp_path, root):
    """The walk must not escape the path the user asked about.

    Without a ceiling, analysing a directory would pick up a pin belonging
    to some unrelated chain further up the filesystem.
    """
    write_pin(str(tmp_path), cert_sha256(root))

    ceiling = tmp_path / "scan_root"
    nested = ceiling / "scenario"
    nested.mkdir(parents=True)

    assert find_pin_file(str(nested), ceiling=str(ceiling)) is None


def test_resolve_pin_path_accepts_the_pin_file_itself(valid_chain):
    pin = os.path.join(valid_chain, PIN_FILENAME)

    assert resolve_pin_path([pin]) == os.path.abspath(pin)


def test_resolve_pin_path_searches_upwards_from_a_bundle(valid_chain,
                                                         bundle_path):
    assert resolve_pin_path([bundle_path]) == os.path.join(
        os.path.abspath(valid_chain), PIN_FILENAME
    )


def test_resolve_pin_path_returns_none_when_unpinned(tmp_path):
    unpinned = tmp_path / "nowhere"
    unpinned.mkdir()

    assert resolve_pin_path([str(unpinned / "absent.pem")]) is None
