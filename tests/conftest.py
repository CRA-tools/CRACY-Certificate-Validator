"""Shared fixtures.

Generating a chain means issuing a 4096-bit root CA, so the fixtures that
produce certificate material are session-scoped: the whole suite works from
one generated chain and one set of corrupted variants.
"""

import shutil

import pytest

from cracy_certval import generate
from cracy_certval.certs import find_pem_certs, is_ca, is_self_signed
from cracy_certval.chains import build_paths
from cracy_certval.invalidate import collect_keys
from cracy_certval.loading import Pkcs12Reader, write_key_dir
from cracy_certval.scenarios import SCENARIOS, apply_scenario, save_chain

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is not installed"
)


def pytest_collection_modifyitems(config, items):
    """Skip the whole suite, with one clear reason, when OpenSSL is absent."""
    if shutil.which("openssl") is not None:
        return

    skip = pytest.mark.skip(reason="openssl is not on PATH")

    for item in items:
        item.add_marker(skip)


@pytest.fixture(scope="session")
def valid_chain(tmp_path_factory):
    """A generated two-intermediate chain, as a single shuffled bundle."""
    parent = tmp_path_factory.mktemp("valid")

    return generate.generate_chain(2, "single", str(parent))


@pytest.fixture(scope="session")
def multi_chain(tmp_path_factory):
    """A generated one-intermediate chain, split across subdirectories."""
    parent = tmp_path_factory.mktemp("multi")

    return generate.generate_chain(1, "multi", str(parent))


@pytest.fixture(scope="session")
def flat_chain(tmp_path_factory):
    """A generated chain with no intermediates at all — leaf and root."""
    parent = tmp_path_factory.mktemp("flat")

    return generate.generate_chain(0, "single", str(parent))


@pytest.fixture(scope="session")
def bundle_path(valid_chain):
    import os

    return os.path.join(valid_chain, "valid_chain.pem")


@pytest.fixture(scope="session")
def bundle_certs(bundle_path):
    """The bundle's certificates in file order — deliberately shuffled."""
    with open(bundle_path, "rb") as handle:
        return find_pem_certs(handle.read())


@pytest.fixture(scope="session")
def ordered_chain(bundle_certs):
    """The reconstructed chain, leaf first, root last."""
    paths = build_paths(bundle_certs)

    assert len(paths) == 1, "the generated bundle should build exactly one path"

    return paths[0]


@pytest.fixture(scope="session")
def leaf(ordered_chain):
    return ordered_chain[0]


@pytest.fixture(scope="session")
def root(ordered_chain):
    cert = ordered_chain[-1]

    assert is_ca(cert) and is_self_signed(cert)

    return cert


@pytest.fixture(scope="session")
def key_dir(valid_chain, bundle_path):
    """A temporary directory of the chain's private keys, normalised to PEM."""
    keys = collect_keys([bundle_path], None, Pkcs12Reader())
    directory, count = write_key_dir(keys)

    assert count > 0, "the generated chain should ship its keys"

    yield directory

    shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(scope="session")
def invalid_chains(tmp_path_factory, ordered_chain, key_dir):
    """Every scenario applied to one chain. Returns the export directory.

    Position scenarios are produced for intermediate 1 only; a second depth
    exercises no additional code path.
    """
    export_dir = str(tmp_path_factory.mktemp("invalid"))

    for choice in SCENARIOS:
        out_dir, chain, extras = apply_scenario(
            choice, ordered_chain, 1, key_dir, export_dir
        )

        save_chain(chain, out_dir)

        for filename, content in extras.items():
            import os

            with open(os.path.join(out_dir, filename), "w") as handle:
                handle.write(content)

    return export_dir
