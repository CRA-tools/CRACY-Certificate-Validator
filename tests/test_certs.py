"""Reading properties back off a single certificate."""

import pytest

from cracy_certval.certs import (
    CorruptedCert,
    cert_sha256,
    cert_sha256_safe,
    common_name,
    find_pem_certs,
    is_ca,
    is_expired,
    is_self_signed,
    issuer,
    not_after,
    public_key,
    subject,
)

GARBAGE = b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"


def test_fingerprint_is_canonical_not_textual(leaf):
    """Re-wrapping the PEM must not change the fingerprint.

    The pin is over the DER, so trailing whitespace or a different line
    ending has to be irrelevant — otherwise a chain would fail its own pin
    after a round trip through a text editor.
    """
    reformatted = leaf.rstrip() + b"\n\n"

    assert cert_sha256(reformatted) == cert_sha256(leaf)


def test_fingerprint_is_64_hex_lowercase(root):
    fingerprint = cert_sha256(root)

    assert len(fingerprint) == 64
    assert fingerprint == fingerprint.lower()
    assert all(c in "0123456789abcdef" for c in fingerprint)


def test_distinct_certificates_have_distinct_fingerprints(leaf, root):
    assert cert_sha256(leaf) != cert_sha256(root)


def test_unparseable_certificate_raises():
    with pytest.raises(ValueError):
        cert_sha256(GARBAGE)


def test_safe_fingerprint_returns_none_instead_of_raising():
    assert cert_sha256_safe(GARBAGE) is None


def test_subject_and_issuer_are_rfc2253_without_label(leaf):
    assert subject(leaf) == "CN=example.com"
    assert issuer(leaf).startswith("CN=Intermediate-")


def test_root_is_its_own_issuer(root):
    assert subject(root) == issuer(root) == "CN=RootCA"


def test_common_name(leaf, root):
    assert common_name(leaf) == "example.com"
    assert common_name(root) == "RootCA"


def test_ca_flag_distinguishes_leaf_from_root(leaf, root):
    assert is_ca(root)
    assert not is_ca(leaf)


def test_self_signed_only_for_root(leaf, root):
    assert is_self_signed(root)
    assert not is_self_signed(leaf)


def test_generated_material_is_not_expired(ordered_chain):
    for cert in ordered_chain:
        assert not is_expired(cert)
        assert not_after(cert) is not None


def test_public_key_is_pem(leaf):
    assert public_key(leaf).startswith(b"-----BEGIN PUBLIC KEY-----")


def test_corrupted_cert_keeps_the_raw_block():
    wrapped = CorruptedCert(GARBAGE)

    assert wrapped.raw == GARBAGE


def test_find_pem_certs_splits_a_bundle(bundle_certs):
    joined = b"".join(bundle_certs)

    assert len(find_pem_certs(joined)) == len(bundle_certs)
