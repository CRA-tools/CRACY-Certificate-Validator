"""The trust-anchor pin.

Every chain this toolkit generates ships with a ``root_hash.txt`` holding the
canonical fingerprint of its root certificate::

    SHA256( DER(root_cert) )

This is what separates the two questions the toolkit keeps apart: *is this
chain structurally and cryptographically sound*, and *does it anchor to the
one root actually trusted*. A chain can pass the first and fail the second — a
perfectly valid chain rooted at an unexpected CA — and a correct
implementation must still reject it. Standard tooling cannot express that,
because it trusts whatever authorities the operating system happens to hold.
"""

import os
import re

from .certs import cert_sha256_safe
from .openssl import debug

PIN_FILENAME = "root_hash.txt"

_HEX_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b")


def read_pin(path: str):
    """The fingerprint recorded in a pin file, or ``None``.

    Only the hex digest is significant, so a pin file may carry surrounding
    text — a heading, a comment, a filename — without breaking the check.
    """
    try:
        with open(path) as handle:
            data = handle.read().strip().lower()
    except OSError as exc:
        debug(f"Unable to read pin file {path}: {exc}")
        return None

    match = _HEX_SHA256_RE.search(data)

    return match.group(0) if match else None


def write_pin(directory: str, fingerprint: str) -> str:
    """Write ``fingerprint`` as the pin for the chain in ``directory``."""
    path = os.path.join(directory, PIN_FILENAME)

    with open(path, "w") as handle:
        handle.write(fingerprint + "\n")

    return path


def find_pin_file(start: str, ceiling: str = None):
    """Search upwards from ``start`` for a pin file.

    Walking up means a chain split across ``leaf/``, ``intermediates/`` and
    ``root/`` subdirectories, or a corruption scenario written into a nested
    folder, still finds the pin recorded for the chain it came from.
    ``ceiling`` bounds the walk — it is the last directory examined. Without
    one the walk continues to the filesystem root.
    """
    candidate = os.path.abspath(start)

    if os.path.isfile(candidate):
        candidate = os.path.dirname(candidate)

    if ceiling is not None:
        ceiling = os.path.abspath(ceiling)

        if os.path.isfile(ceiling):
            ceiling = os.path.dirname(ceiling)

    while True:
        guess = os.path.join(candidate, PIN_FILENAME)

        if os.path.isfile(guess):
            return guess

        if candidate == ceiling:
            return None

        parent = os.path.dirname(candidate)

        if parent == candidate:
            return None

        candidate = parent


def resolve_pin_path(paths: list):
    """The pin file for a set of input paths, or ``None``.

    A path pointing straight at a pin file wins; otherwise each input is
    searched upwards in turn.
    """
    for path in paths:
        if os.path.isfile(path) and os.path.basename(path) == PIN_FILENAME:
            return os.path.abspath(path)

    for path in paths:
        if not os.path.exists(path):
            continue

        found = find_pin_file(path)

        if found:
            return found

    return None


def verify_pin(root_cert: bytes, pinned: str) -> bool:
    """Whether ``root_cert`` is the certificate ``pinned`` names."""
    actual = cert_sha256_safe(root_cert)

    if actual is None or pinned is None:
        return False

    return actual == pinned.lower()
