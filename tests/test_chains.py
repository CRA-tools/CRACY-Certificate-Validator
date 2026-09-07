"""Reconstructing chains from unordered material, and verifying them."""

from cracy_certval.certs import cert_sha256, subject
from cracy_certval.chains import (
    build_paths,
    chain_is_incomplete,
    find_root,
    verify_chain,
    write_pem_bundle,
)


def test_shuffled_bundle_rebuilds_one_ordered_chain(ordered_chain):
    """The generated bundle is shuffled on purpose; order must be recovered."""
    subjects = [subject(cert) for cert in ordered_chain]

    assert subjects == [
        "CN=example.com",
        "CN=Intermediate-2",
        "CN=Intermediate-1",
        "CN=RootCA",
    ]


def test_paths_are_deduplicated_by_fingerprint(bundle_certs):
    duplicated = list(bundle_certs) + list(bundle_certs)

    assert len(build_paths(duplicated)) == 1


def test_bundle_without_a_leaf_builds_no_path(ordered_chain):
    """A directory of CA certificates is not a chain and yields no path."""
    assert build_paths(ordered_chain[1:]) == []


def test_find_root_returns_the_self_signed_ca(ordered_chain, root):
    assert cert_sha256(find_root(ordered_chain)) == cert_sha256(root)


def test_find_root_falls_back_to_the_highest_ca(ordered_chain):
    """A truncated chain has no anchor, but it does have a highest CA.

    That CA is what a verifier would be asked to trust, so naming it is more
    useful than reporting nothing.
    """
    truncated = ordered_chain[:2]

    assert cert_sha256(find_root(truncated)) == cert_sha256(truncated[-1])


def test_find_root_returns_none_when_no_ca_is_present(leaf):
    assert find_root([leaf]) is None


def test_complete_chain_verifies(ordered_chain):
    verified, diagnostics = verify_chain(ordered_chain)

    assert verified
    assert "OK" in diagnostics


def test_chain_without_intermediates_verifies(flat_chain):
    """A leaf signed directly by the root is a complete chain.

    ``openssl verify`` rejects an empty ``-untrusted`` file, so the option
    has to be omitted entirely when a chain has no intermediates.
    """
    import os

    from cracy_certval.certs import find_pem_certs

    with open(os.path.join(flat_chain, "valid_chain.pem"), "rb") as handle:
        certs = find_pem_certs(handle.read())

    path = build_paths(certs)[0]

    assert len(path) == 2

    verified, diagnostics = verify_chain(path)

    assert verified, diagnostics


def test_truncated_chain_fails_verification(ordered_chain):
    verified, diagnostics = verify_chain(ordered_chain[:2])

    assert not verified
    assert diagnostics


def test_chain_is_incomplete_detects_a_missing_root(ordered_chain):
    assert not chain_is_incomplete(ordered_chain)
    assert chain_is_incomplete(ordered_chain[:-1])
    assert chain_is_incomplete(ordered_chain[:1])


def test_write_pem_bundle_separates_blocks(tmp_path, ordered_chain):
    from cracy_certval.certs import find_pem_certs

    destination = write_pem_bundle(
        ordered_chain, str(tmp_path / "bundle.pem")
    )

    with open(destination, "rb") as handle:
        assert len(find_pem_certs(handle.read())) == len(ordered_chain)
