"""Building chains out of a pile of certificates, and verifying them.

Real-world certificate material rarely arrives as an ordered leaf-to-root
chain: a bundle may be shuffled, may hold several unrelated certificates, or
may be missing a link. :func:`build_paths` therefore reconstructs *every*
candidate path from each end-entity certificate upwards, and the caller
decides what to do with each one. That is what lets the toolkit report *why* a
chain failed rather than only that it did.
"""

import os
import shutil
import tempfile
from collections import defaultdict

from .certs import (
    cert_sha256,
    is_ca,
    is_self_signed,
    issuer,
    subject,
)
from .openssl import openssl


def build_paths(certs: list) -> list:
    """Every distinct leaf-to-highest-issuer path buildable from ``certs``.

    Each path is a list of PEM byte-strings, leaf first. Certificates that
    cannot be parsed are skipped rather than aborting the walk, and paths are
    de-duplicated by their sequence of canonical fingerprints, so an input
    holding the same certificate twice does not produce duplicate results.
    """
    subject_map = defaultdict(list)

    for cert in certs:
        try:
            subject_map[subject(cert)].append(cert)
        except Exception:
            continue

    issuer_subjects = set()

    for cert in certs:
        try:
            issuer_subjects.add(issuer(cert))
        except Exception:
            continue

    # A leaf is a certificate that is not a CA and that nothing else claims
    # as its issuer.
    leaves = []

    for cert in certs:
        try:
            if is_ca(cert):
                continue

            if subject(cert) in issuer_subjects:
                continue

            leaves.append(cert)
        except Exception:
            continue

    paths = []

    def walk(current: bytes, chain: list, visited: set):
        try:
            current_issuer = issuer(current)
        except Exception:
            paths.append(chain + [current])
            return

        parents = subject_map.get(current_issuer, [])

        if not parents:
            paths.append(chain + [current])
            return

        advanced = False

        for parent in parents:
            try:
                if not is_ca(parent):
                    continue

                parent_fp = cert_sha256(parent)

                # Visited fingerprints stop a cross-signed or self-issued
                # certificate from looping forever.
                if parent_fp in visited:
                    continue

                advanced = True

                walk(parent, chain + [current], visited | {parent_fp})
            except Exception:
                continue

        if not advanced:
            paths.append(chain + [current])

    for leaf in leaves:
        try:
            leaf_fp = cert_sha256(leaf)
        except Exception:
            continue

        walk(leaf, [], {leaf_fp})

    unique = []
    seen = set()

    for path in paths:
        try:
            fingerprints = tuple(cert_sha256(c) for c in path)
        except Exception:
            continue

        if fingerprints not in seen:
            seen.add(fingerprints)
            unique.append(path)

    return unique


def find_root(path: list):
    """The trust anchor of ``path``, or ``None`` if it has none.

    A self-signed CA is the root. Failing that, a CA whose issuer is not
    present in the path is the highest certificate available — the chain does
    not reach a self-signed anchor, but that CA is what a verifier would be
    asked to trust.
    """
    subjects = set()

    for cert in path:
        try:
            subjects.add(subject(cert))
        except Exception:
            continue

    for cert in path:
        try:
            if is_ca(cert) and is_self_signed(cert):
                return cert
        except Exception:
            continue

    for cert in path:
        try:
            if is_ca(cert) and issuer(cert) not in subjects:
                return cert
        except Exception:
            continue

    return None


def chain_is_incomplete(path: list) -> bool:
    """Whether ``path`` stops short of a self-signed root CA."""
    if len(path) < 2:
        return True

    try:
        last = path[-1]
        return not (is_ca(last) and is_self_signed(last))
    except Exception:
        return True


def verify_chain(path: list) -> tuple:
    """Verify ``path`` with ``openssl verify -x509_strict``.

    Returns ``(ok, output)``, where ``output`` is the combined OpenSSL
    diagnostics — kept verbatim because it is what makes a classification
    auditable.

    The highest certificate in the path is offered as the only trust anchor,
    so the system trust store cannot influence the result: a chain is judged
    against the material supplied, never against whatever CAs happen to be
    installed on the machine running the tool.
    """
    temp_dir = tempfile.mkdtemp(prefix="cracy_verify_")

    try:
        leaf_path = os.path.join(temp_dir, "leaf.pem")
        inter_path = os.path.join(temp_dir, "inter.pem")
        root_path = os.path.join(temp_dir, "root.pem")

        intermediates = path[1:-1]

        write_pem_bundle(path[:1], leaf_path)
        write_pem_bundle(path[-1:], root_path)

        args = ["verify", "-x509_strict", "-CAfile", root_path]

        # -untrusted rejects a file holding no certificates, so a chain of
        # leaf and root alone must not pass the option at all.
        if intermediates:
            write_pem_bundle(intermediates, inter_path)
            args += ["-untrusted", inter_path]

        result = openssl(args + [leaf_path])

        output = (
            result.stdout.decode(errors="replace")
            + result.stderr.decode(errors="replace")
        ).strip()

        return result.returncode == 0, output

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def write_pem_bundle(certs: list, destination: str) -> str:
    """Concatenate ``certs`` into one PEM file, one certificate per block."""
    with open(destination, "wb") as handle:
        for cert in certs:
            handle.write(cert)

            if not cert.endswith(b"\n"):
                handle.write(b"\n")

    return destination
