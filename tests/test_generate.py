"""Generating baseline chains."""

import os

import pytest

from cracy_certval.certs import cert_sha256, find_pem_certs, is_ca, subject
from cracy_certval.chains import build_paths
from cracy_certval.generate import (
    FORMAT_CHOICES,
    resolve_format,
    resolve_intermediates,
)
from cracy_certval.pinning import PIN_FILENAME, read_pin


def test_single_format_layout(valid_chain):
    assert os.path.isfile(os.path.join(valid_chain, "valid_chain.pem"))
    assert os.path.isfile(os.path.join(valid_chain, PIN_FILENAME))
    assert os.path.isdir(os.path.join(valid_chain, "keys"))
    assert os.path.isdir(os.path.join(valid_chain, "csrs"))


def test_run_directory_is_named_for_its_run(valid_chain):
    assert os.path.basename(valid_chain).startswith("valid_chain_")


def test_keys_are_retained_for_every_certificate(valid_chain):
    """The invalidator needs these keys to re-sign; a chain without them
    could only be corrupted in the ways that need no signature."""
    keys = os.listdir(os.path.join(valid_chain, "keys"))

    assert sorted(keys) == ["ca_1.key", "ca_2.key", "root.key", "server.key"]


def test_bundle_holds_every_certificate(bundle_certs):
    assert len(bundle_certs) == 4


def test_pin_matches_the_generated_root(valid_chain, ordered_chain):
    pinned = read_pin(os.path.join(valid_chain, PIN_FILENAME))

    assert pinned == cert_sha256(ordered_chain[-1])


def test_multi_format_layout(multi_chain):
    leaf_dir = os.path.join(multi_chain, "leaf")
    intermediates_dir = os.path.join(multi_chain, "intermediates")
    root_dir = os.path.join(multi_chain, "root")

    assert os.listdir(leaf_dir) == ["server.pem"]
    assert os.listdir(intermediates_dir) == ["ca_1.pem"]
    assert os.listdir(root_dir) == ["root.pem"]
    assert os.path.isfile(os.path.join(multi_chain, PIN_FILENAME))


def test_flat_chain_has_no_intermediates(flat_chain):
    with open(os.path.join(flat_chain, "valid_chain.pem"), "rb") as handle:
        certs = find_pem_certs(handle.read())

    assert len(certs) == 2

    path = build_paths(certs)[0]

    assert [subject(cert) for cert in path] == ["CN=example.com", "CN=RootCA"]


def test_intermediates_are_cas_and_the_leaf_is_not(ordered_chain):
    assert not is_ca(ordered_chain[0])
    assert all(is_ca(cert) for cert in ordered_chain[1:])


@pytest.mark.parametrize(
    "given,expected",
    [("1", "single"), ("single", "single"), ("2", "multi"), ("multi", "multi"),
     (" SINGLE ", "single")],
)
def test_format_spellings(given, expected):
    assert resolve_format(given) == expected


def test_every_documented_format_spelling_resolves():
    for spelling in FORMAT_CHOICES:
        assert resolve_format(spelling) in {"single", "multi"}


def test_unknown_format_is_rejected():
    with pytest.raises(SystemExit):
        resolve_format("pkcs12")


def test_intermediate_count_must_not_be_negative():
    with pytest.raises(SystemExit):
        resolve_intermediates(-1)


def test_intermediate_count_passes_through():
    assert resolve_intermediates(0) == 0
    assert resolve_intermediates(3) == 3
