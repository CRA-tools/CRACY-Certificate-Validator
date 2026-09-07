"""Reading real-world certificate material.

The invalidator has to work on whatever a manufacturer actually holds, so
every container OpenSSL can decode has to come back as PEM. These tests
build each container from the generated chain and check it round-trips.
"""

import os

from cracy_certval.certs import cert_sha256
from cracy_certval.loading import (
    CONTAINER_EXTS,
    collect_material,
    discover_chain_files,
    extract_from_file,
    file_contains_certificate,
    find_key_for_cert,
    gather_files,
    load_cert_blocks,
    resolve_base_dir,
    split_certs,
    write_key_dir,
)
from cracy_certval.openssl import openssl_checked


def fingerprints(certs):
    return {cert_sha256(cert) for cert in certs}


def test_pem_bundle_round_trips(bundle_path, ordered_chain):
    certs, keys = extract_from_file(bundle_path)

    assert fingerprints(certs) == fingerprints(ordered_chain)
    assert keys == []


def test_der_certificate_round_trips(tmp_path, leaf):
    path = tmp_path / "leaf.der"
    path.write_bytes(
        openssl_checked(["x509", "-outform", "DER"], leaf)
    )

    certs, _ = extract_from_file(str(path))

    assert fingerprints(certs) == {cert_sha256(leaf)}


def test_pkcs7_bundle_round_trips(tmp_path, bundle_path, ordered_chain):
    path = tmp_path / "chain.p7b"

    openssl_checked(
        ["crl2pkcs7", "-nocrl", "-certfile", bundle_path, "-out", str(path),
         "-outform", "DER"]
    )

    certs, _ = extract_from_file(str(path))

    assert fingerprints(certs) == fingerprints(ordered_chain)


def test_pkcs12_container_round_trips(tmp_path, valid_chain, bundle_path,
                                      leaf):
    """A PKCS#12 carries the key alongside the certificates."""
    path = tmp_path / "chain.p12"

    openssl_checked(
        ["pkcs12", "-export", "-out", str(path),
         "-inkey", os.path.join(valid_chain, "keys", "server.key"),
         "-in", bundle_path,
         "-passout", "pass:"]
    )

    certs, keys = extract_from_file(str(path))

    assert cert_sha256(leaf) in fingerprints(certs)
    assert len(keys) == 1
    assert b"PRIVATE KEY" in keys[0]


def test_a_pkcs12_is_not_mistaken_for_a_bare_der_certificate(tmp_path,
                                                             valid_chain,
                                                             bundle_path):
    """``openssl x509 -inform DER`` will mis-parse a PKCS#12 blob, so the
    composite containers must be probed first."""
    path = tmp_path / "unlabelled.bin"

    openssl_checked(
        ["pkcs12", "-export", "-out", str(path),
         "-inkey", os.path.join(valid_chain, "keys", "server.key"),
         "-in", bundle_path,
         "-passout", "pass:"]
    )

    certs, keys = extract_from_file(str(path))

    assert len(certs) > 1
    assert keys


def test_unrecognised_content_yields_nothing(tmp_path):
    path = tmp_path / "notes.pem"
    path.write_bytes(b"just some text\n")

    assert extract_from_file(str(path)) == ([], [])


def test_a_missing_file_yields_nothing(tmp_path):
    assert extract_from_file(str(tmp_path / "absent.pem")) == ([], [])


def test_directories_are_walked_by_extension(tmp_path, leaf):
    (tmp_path / "chain.pem").write_bytes(leaf)
    (tmp_path / "notes.txt").write_bytes(leaf)

    found = gather_files([str(tmp_path)])

    assert found == [str(tmp_path / "chain.pem")]
    assert all(name.lower().endswith(CONTAINER_EXTS) for name in found)


def test_a_named_file_is_read_whatever_its_extension(tmp_path, leaf):
    path = tmp_path / "chain.unusual"
    path.write_bytes(leaf)

    certs, _ = collect_material([str(path)])

    assert fingerprints(certs) == {cert_sha256(leaf)}


def test_collect_material_walks_a_generated_chain(valid_chain, ordered_chain):
    certs, keys = collect_material([valid_chain])

    assert fingerprints(certs) == fingerprints(ordered_chain)
    assert len(keys) == 4


def test_keys_are_written_out_deduplicated(valid_chain):
    _, keys = collect_material([valid_chain])

    directory, count = write_key_dir(keys + keys)

    try:
        assert count == 4
        assert len(os.listdir(directory)) == 4
    finally:
        import shutil

        shutil.rmtree(directory, ignore_errors=True)


def test_a_key_is_matched_to_its_certificate_by_public_key(valid_chain, leaf,
                                                           key_dir):
    """Matching on the derived public key finds a key under any filename."""
    matched = find_key_for_cert(leaf, key_dir)

    assert matched is not None

    expected = openssl_checked(["x509", "-pubkey", "-noout"], leaf)
    actual = openssl_checked(["pkey", "-in", matched, "-pubout"])

    assert actual == expected


def test_no_key_matches_when_none_is_present(tmp_path, leaf):
    assert find_key_for_cert(leaf, str(tmp_path)) is None
    assert find_key_for_cert(leaf, None) is None


def test_base_dir_finds_the_sibling_keys_directory(valid_chain, bundle_path):
    assert resolve_base_dir([bundle_path]) == os.path.abspath(valid_chain)


def test_base_dir_prefers_the_pin_directory(valid_chain, bundle_path):
    pin = os.path.join(valid_chain, "root_hash.txt")

    assert resolve_base_dir([bundle_path], pin) == valid_chain


# PEM scanning with corruption triage

def test_certificate_files_are_detected(bundle_path, tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("nothing here\n")

    assert file_contains_certificate(bundle_path)
    assert not file_contains_certificate(str(plain))
    assert not file_contains_certificate(str(tmp_path))


def test_discovery_walks_a_multi_pem_layout(multi_chain):
    found = discover_chain_files(multi_chain)

    assert len(found) == 3


def test_corrupted_blocks_are_kept_and_partitioned(tmp_path, ordered_chain,
                                                   leaf):
    from cracy_certval.scenarios import corrupt_cert

    path = tmp_path / "mixed.pem"
    path.write_bytes(b"".join(ordered_chain[1:]) + corrupt_cert(leaf))

    entries = load_cert_blocks([str(path)])
    valid, corrupted = split_certs(entries)

    assert len(entries) == 4
    assert len(valid) == 3
    assert len(corrupted) == 1
    assert corrupted[0].raw.startswith(b"-----BEGIN CERTIFICATE-----")
