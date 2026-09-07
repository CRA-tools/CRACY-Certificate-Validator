"""Reading certificate and key material off disk.

Two loaders live here, because the two halves of the toolkit need different
things from an input.

The invalidator has to work on *real* material — whatever a manufacturer
actually holds — so it accepts every container OpenSSL can decode (PEM, DER,
PKCS#7, PKCS#12) and normalises all of it to PEM, after which nothing
downstream has to care about format. Keys are handled the same way, and no
assumption is made about the key algorithm, so RSA and EC material behave
identically.

The validator instead scans for PEM certificate blocks and triages them: a
block OpenSSL cannot parse becomes a :class:`~cracy_certval.certs.CorruptedCert`
so that corruption is reported rather than silently skipped.
"""

import getpass
import hashlib
import os
import tempfile

from .certs import (
    CorruptedCert,
    cert_sha256_safe,
    find_pem_certs,
    find_pem_keys,
    public_key,
)
from .openssl import debug, openssl

# Extensions treated as certificate/key containers when walking a directory.
# A file named explicitly on the command line is always attempted, whatever
# it is called.
CONTAINER_EXTS = (
    ".pem", ".crt", ".cert", ".cer", ".der",
    ".p7b", ".p7c", ".p7", ".spc",
    ".p12", ".pfx", ".pkcs12",
    ".key",
)

PKCS12_EXTS = (".p12", ".pfx", ".pkcs12")

_BEGIN_CERT = b"-----BEGIN CERTIFICATE-----"


# Multi-format loading (invalidator)

class Pkcs12Reader:
    """Opens PKCS#12 containers, prompting for a password at most once each.

    A password supplied up front — ``CRACY_P12_PASSWORD``, or
    ``--p12-password`` — is used instead of prompting, which is what keeps an
    unattended run unattended. The environment variable is preferred: an
    argument is visible in the shell history and in the process list.
    """

    def __init__(self, password=None):
        self.password = (
            password if password is not None
            else os.getenv("CRACY_P12_PASSWORD")
        )
        self._settings = {}

    def looks_like_pkcs12(self, path: str) -> bool:
        if path.lower().endswith(PKCS12_EXTS):
            return True

        # Unlabelled container: cheap probe assuming an empty password. An
        # encrypted, unlabelled PKCS#12 cannot be sniffed this way, but such
        # files are vanishingly rare and are handled when named .p12.
        probe = openssl(
            ["pkcs12", "-in", path, "-nokeys", "-noout", "-passin", "pass:"]
        )

        return probe.returncode == 0

    def _settings_for(self, path: str) -> tuple:
        """``(password, use_legacy)`` for one container.

        ``-legacy`` is retried because containers written by older tools use
        algorithms OpenSSL 3 no longer enables by default.
        """
        if path in self._settings:
            return self._settings[path]

        candidates = [("", False), ("", True)]
        prompted = False

        while True:
            for password, legacy in candidates:
                args = [
                    "pkcs12", "-in", path, "-nokeys", "-noout",
                    "-passin", f"pass:{password}",
                ]

                if legacy:
                    args.append("-legacy")

                if openssl(args).returncode == 0:
                    self._settings[path] = (password, legacy)
                    return self._settings[path]

            if prompted:
                raise SystemExit(
                    f"ERROR: could not open PKCS#12 file {path} "
                    f"(wrong password?)"
                )

            if self.password is not None:
                password = self.password
            else:
                password = getpass.getpass(
                    f"Password for {os.path.basename(path)}: "
                )

            candidates = [(password, False), (password, True)]
            prompted = True

    def extract(self, path: str) -> tuple:
        """``(certs, keys)`` as PEM byte-strings from one container."""
        password, legacy = self._settings_for(path)

        def bag(extra):
            args = ["pkcs12", "-in", path, "-passin", f"pass:{password}"]
            args += extra

            if legacy:
                args.append("-legacy")

            result = openssl(args)

            return result.stdout if result.returncode == 0 else b""

        certs = find_pem_certs(bag(["-nokeys"]))
        keys = find_pem_keys(bag(["-nocerts", "-nodes"]))

        return certs, keys


def gather_files(paths: list) -> list:
    """Expand input paths into a sorted list of candidate container files."""
    files = []

    for path in paths:
        if not os.path.exists(path):
            continue

        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                for name in names:
                    if name.lower().endswith(CONTAINER_EXTS):
                        files.append(os.path.join(root, name))
        else:
            files.append(path)

    return sorted(set(files))


def _der_cert_to_pem(data: bytes):
    result = openssl(["x509", "-inform", "DER", "-outform", "PEM"], data)

    if result.returncode == 0 and b"BEGIN CERTIFICATE" in result.stdout:
        return result.stdout

    return None


def _der_key_to_pem(data: bytes):
    result = openssl(["pkey", "-inform", "DER"], data)

    if result.returncode == 0 and b"PRIVATE KEY" in result.stdout:
        return result.stdout

    return None


def _pkcs7_certs(data: bytes, inform: str) -> list:
    result = openssl(["pkcs7", "-print_certs", "-inform", inform], data)

    if result.returncode == 0:
        return find_pem_certs(result.stdout)

    return []


def extract_from_file(path: str, pkcs12: Pkcs12Reader = None) -> tuple:
    """``(certs, keys)`` as PEM byte-strings extracted from one file."""
    pkcs12 = pkcs12 or Pkcs12Reader()

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        debug(f"Unable to read {path}: {exc}")
        return [], []

    # Text container: may hold certificates and/or keys and/or PKCS#7.
    if b"-----BEGIN" in data:
        certs = find_pem_certs(data)
        keys = find_pem_keys(data)

        if b"-----BEGIN PKCS7-----" in data:
            certs += _pkcs7_certs(data, "PEM")

        return certs, keys

    # Binary containers. The composite PKCS#12 container and PKCS#7 bundle
    # are checked BEFORE raw single-object DER, because
    # "openssl x509/pkey -inform DER" will happily mis-parse a PKCS#12 blob
    # as a lone certificate or key.
    if pkcs12.looks_like_pkcs12(path):
        return pkcs12.extract(path)

    pkcs7 = _pkcs7_certs(data, "DER")

    if pkcs7:
        return pkcs7, []

    der_cert = _der_cert_to_pem(data)

    if der_cert:
        return [der_cert], []

    der_key = _der_key_to_pem(data)

    if der_key:
        return [], [der_key]

    debug(f"No recognisable certificate material in {path}")

    return [], []


def collect_material(paths: list, pkcs12: Pkcs12Reader = None) -> tuple:
    """Walk ``paths`` and return ``(certs, keys)`` as PEM byte-strings."""
    pkcs12 = pkcs12 or Pkcs12Reader()

    certs, keys = [], []

    for file_path in gather_files(paths):
        found_certs, found_keys = extract_from_file(file_path, pkcs12)
        certs.extend(found_certs)
        keys.extend(found_keys)

    return certs, keys


def write_key_dir(keys: list) -> tuple:
    """Write de-duplicated PEM keys into a fresh temporary directory.

    Returns ``(directory, count)``. The caller owns the directory and is
    responsible for removing it — it holds private key material.
    """
    key_dir = tempfile.mkdtemp(prefix="cracy_keys_")

    seen = set()
    count = 0

    for key in keys:
        normalised = key if key.endswith(b"\n") else key + b"\n"
        fingerprint = hashlib.sha256(normalised).hexdigest()

        if fingerprint in seen:
            continue

        seen.add(fingerprint)

        with open(os.path.join(key_dir, f"k{count}.key"), "wb") as handle:
            handle.write(normalised)

        count += 1

    return key_dir, count


def find_key_for_cert(cert: bytes, search_dir: str):
    """The key file in ``search_dir`` whose public key matches ``cert``.

    Matching on the derived public key rather than on filename means keys are
    found wherever they came from, in any supported format, for any algorithm.
    """
    if search_dir is None or not os.path.isdir(search_dir):
        return None

    cert_pub = public_key(cert)

    if not cert_pub:
        return None

    for root, _, files in os.walk(search_dir):
        for name in files:
            path = os.path.join(root, name)

            result = openssl(["pkey", "-in", path, "-pubout"])

            if result.returncode == 0 and result.stdout == cert_pub:
                return path

    return None


# PEM scanning with corruption triage (validator)

def file_contains_certificate(path: str) -> bool:
    """Whether a file opens with, or contains, a PEM certificate block."""
    try:
        if not os.path.isfile(path):
            return False

        with open(path, "rb") as handle:
            return _BEGIN_CERT in handle.read(8192)
    except Exception as exc:
        debug(f"Detection failed: {path}: {exc}")
        return False


def discover_chain_files(base: str) -> list:
    """Every file under ``base`` that holds certificate material."""
    if os.path.isfile(base):
        return [base] if file_contains_certificate(base) else []

    discovered = []

    for root, _, files in os.walk(base):
        for name in files:
            full = os.path.join(root, name)

            if file_contains_certificate(full):
                discovered.append(full)

    return discovered


def load_cert_blocks(paths: list) -> list:
    """Every PEM certificate block in ``paths``, corrupted ones included.

    A block OpenSSL can parse is returned as bytes; one it cannot is wrapped
    in :class:`~cracy_certval.certs.CorruptedCert`.
    """
    results = []

    for path in paths:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            debug(f"Load failed {path}: {exc}")
            continue

        for block in find_pem_certs(data):
            if cert_sha256_safe(block) is not None:
                results.append(block)
            else:
                debug(f"Corrupted cert block in {path}")
                results.append(CorruptedCert(block))

    return results


def split_certs(entries: list) -> tuple:
    """Partition loaded blocks into ``(parseable, corrupted)``."""
    valid = [e for e in entries if isinstance(e, bytes)]
    corrupted = [e for e in entries if isinstance(e, CorruptedCert)]

    return valid, corrupted


def resolve_base_dir(paths: list, pin_path: str = None) -> str:
    """The directory a chain's own material lives in.

    Used to find the ``keys/`` directory a generated chain ships with, so the
    invalidator can re-sign certificates without being handed the keys
    explicitly. The pin file's directory is the best answer when there is
    one; otherwise the search walks up looking for a ``keys/`` sibling, and
    falls back to the common ancestor of the inputs.
    """
    if pin_path:
        return os.path.dirname(pin_path)

    for path in paths:
        if not os.path.exists(path):
            continue

        candidate = path if os.path.isdir(path) else os.path.dirname(path)
        candidate = os.path.abspath(candidate)

        while True:
            if os.path.isdir(os.path.join(candidate, "keys")):
                return candidate

            parent = os.path.dirname(candidate)

            if parent == candidate:
                break

            candidate = parent

    existing = [
        os.path.abspath(path if os.path.isdir(path) else os.path.dirname(path))
        for path in paths
        if os.path.exists(path)
    ]

    if existing:
        return os.path.commonpath(existing)

    return os.getcwd()
