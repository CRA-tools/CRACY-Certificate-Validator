"""The eight corruption scenarios.

Each scenario derives a fresh chain from a valid one and introduces exactly
**one** defect. Isolating a single fault per chain is the point: each chain
then exercises one specific check in the system under test, so a gap in that
system's validation logic is directly attributable rather than lost among
several simultaneous problems.

Two scenarios leave the chain itself untouched and attack the trust anchor
instead — ``root_hash_mismatch`` ships a cryptographically valid chain with
the wrong pin, and ``root_hash_not_checked`` ships one with no pin at all.
Those are the cases a conventional verifier cannot fail, and the ones a
correct implementation must still reject.
"""

import hashlib
import os
import tempfile
from copy import deepcopy

from .certs import cert_sha256, common_name
from .chains import find_root, write_pem_bundle
from .loading import find_key_for_cert
from .openssl import openssl_checked

EXPORT_DIR = "invalid_chain"

SCENARIOS = {
    "1": "expired_server",
    "2": "corrupted_server",
    "3": "expired_intermediate",
    "4": "non_ca_intermediate",
    "5": "missing_intermediate",
    "6": "root_hash_mismatch",
    "7": "root_hash_not_checked",
    "8": "expired_root",
}

# Scenarios that operate on a chosen intermediate position.
POSITION_SCENARIOS = {"3", "4", "5"}

# Scenarios may also be selected by name on the command line.
SCENARIO_ALIASES = {name: number for number, name in SCENARIOS.items()}

SCENARIO_MENU = """
Select one or more corruptions (comma-separated, or 'all').
Each selection produces its OWN chain with a single defect:

1. expired_server         (needs leaf + issuing-CA key)
2. corrupted_server       (no key needed)
3. expired_intermediate   (needs intermediate + issuing-CA key)
4. non_ca_intermediate    (needs intermediate + issuing-CA key)
5. missing_intermediate   (no key needed)
6. root_hash_mismatch     (no key needed)
7. root_hash_not_checked  (no key needed)
8. expired_root           (needs root key)
"""

CA_EXTENSIONS = """
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
"""

NON_CA_EXTENSIONS = """
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
"""


def regenerate_certificate(old_cert, signer_cert, signer_key, target_key,
                           days, ca_true):
    """Re-issue a certificate with new validity or CA constraints.

    Keeping the subject CN and the original key, and re-signing with the real
    issuing CA, is what makes an expired or non-CA certificate a *genuine*
    single-defect case: everything about it still verifies except the one
    property being tested.
    """
    if target_key is None:
        raise SystemExit(
            "ERROR: private key for the target certificate was not found "
            "(cannot regenerate). Provide the matching key via keys/, a PEM "
            "key file, or a PKCS#12 bundle."
        )

    if signer_key is None:
        raise SystemExit(
            "ERROR: signer private key was not found "
            "(cannot regenerate). The signing CA's private key must be "
            "available for this scenario."
        )

    with tempfile.TemporaryDirectory(prefix="cracy_resign_") as temp:
        csr = os.path.join(temp, "tmp.csr")
        new_cert = os.path.join(temp, "new.pem")
        ext = os.path.join(temp, "ext.cnf")

        with open(ext, "w") as handle:
            handle.write(CA_EXTENSIONS if ca_true else NON_CA_EXTENSIONS)

        # -key / -CAkey accept RSA and EC keys identically; the signature
        # algorithm follows the signer key type (RSA-PKCS1 or ECDSA) with the
        # requested SHA-256 digest.
        openssl_checked(
            ["req", "-new", "-key", target_key, "-out", csr,
             "-subj", f"/CN={common_name(old_cert)}"]
        )

        openssl_checked(
            ["x509", "-req", "-in", csr,
             "-CA", signer_cert, "-CAkey", signer_key, "-CAcreateserial",
             "-out", new_cert, "-days", str(days), "-sha256",
             "-extfile", ext]
        )

        with open(new_cert, "rb") as handle:
            return handle.read()


def resign(chain, target_index, signer_index, key_dir, days, ca_true):
    """Re-issue ``chain[target_index]``, signed by ``chain[signer_index]``.

    Modifies ``chain`` in place. ``target_index == signer_index`` re-signs a
    self-signed root.
    """
    target_key = find_key_for_cert(chain[target_index], key_dir)
    signer_key = find_key_for_cert(chain[signer_index], key_dir)

    with tempfile.TemporaryDirectory(prefix="cracy_signer_") as temp:
        signer_cert = write_pem_bundle(
            [chain[signer_index]], os.path.join(temp, "signer.pem")
        )

        chain[target_index] = regenerate_certificate(
            old_cert=chain[target_index],
            signer_cert=signer_cert,
            signer_key=signer_key,
            target_key=target_key,
            days=days,
            ca_true=ca_true,
        )


def corrupt_cert(cert: bytes) -> bytes:
    """Mangle a certificate's body, keeping its PEM framing intact.

    Preserving ``-----BEGIN/END CERTIFICATE-----`` localises the corruption
    to a single block: a reader still sees one delimited certificate that
    simply fails to decode, instead of a destroyed END line that bleeds the
    corrupted block into the certificate that follows it.
    """
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"

    begin_index = cert.find(begin)
    end_index = cert.find(end)

    if begin_index == -1 or end_index == -1 or end_index <= begin_index:
        # No recognisable framing; fall back to a raw mangle.
        return cert + b"CORRUPTED"

    body_start = cert.find(b"\n", begin_index)

    if body_start == -1 or body_start >= end_index:
        return cert + b"CORRUPTED"

    body = cert[body_start:end_index]
    middle = len(body) // 2

    # Non-base64 characters in the middle of the body make the DER decode
    # fail while BEGIN/END remain intact.
    corrupted_body = body[:middle] + b"!!CORRUPT!!" + body[middle:]

    return cert[:body_start] + corrupted_body + cert[end_index:]


def random_fingerprint(excluding: str = None) -> str:
    """A fingerprint-shaped value that is not ``excluding``."""
    while True:
        candidate = hashlib.sha256(os.urandom(32)).hexdigest().lower()

        if candidate != excluding:
            return candidate


def save_chain(chain: list, folder: str) -> str:
    """Write a corrupted chain as ``invalid_chain.pem`` inside ``folder``."""
    os.makedirs(folder, exist_ok=True)

    return write_pem_bundle(chain, os.path.join(folder, "invalid_chain.pem"))


def apply_scenario(choice, base_path, position, key_dir,
                   export_dir=EXPORT_DIR):
    """Apply exactly one corruption to a fresh copy of ``base_path``.

    Returns ``(out_dir, chain, extra_files)``, where ``extra_files`` maps a
    filename to its text content and is used by the root-hash scenarios to
    write, or withhold, a pin alongside the chain.
    """
    chain = deepcopy(base_path)
    name = SCENARIOS[choice]
    extras = {}

    if choice == "1":
        # expired_server: the leaf, re-signed with zero days of validity.
        resign(chain, 0, 1, key_dir, days=0, ca_true=False)
        out_dir = os.path.join(export_dir, name)

    elif choice == "2":
        # corrupted_server: the leaf's PEM body, mangled.
        chain[0] = corrupt_cert(chain[0])
        out_dir = os.path.join(export_dir, name)

    elif choice in {"3", "4"}:
        # expired_intermediate / non_ca_intermediate, at a chosen depth.
        if position is None or position <= 0 or position >= len(chain) - 1:
            raise SystemExit("Invalid intermediate position")

        if choice == "3":
            resign(chain, position, position + 1, key_dir,
                   days=0, ca_true=True)
        else:
            resign(chain, position, position + 1, key_dir,
                   days=365, ca_true=False)

        out_dir = os.path.join(export_dir, name, f"int{position}")

    elif choice == "5":
        # missing_intermediate: drop one link and leave the rest intact.
        if position is None or position <= 0 or position >= len(chain) - 1:
            raise SystemExit("Invalid intermediate position")

        del chain[position]
        out_dir = os.path.join(export_dir, name, f"int{position}")

    elif choice == "6":
        # root_hash_mismatch: the chain stays valid; only the pin is wrong.
        root = find_root(chain)

        if root is None:
            raise SystemExit("Root certificate not found")

        extras["root_hash.txt"] = (
            random_fingerprint(excluding=cert_sha256(root)) + "\n"
        )
        out_dir = os.path.join(export_dir, name)

    elif choice == "7":
        # root_hash_not_checked: valid chain, no pin emitted at all.
        out_dir = os.path.join(export_dir, name)

    elif choice == "8":
        # expired_root: the trust anchor itself, re-signed as expired.
        root = find_root(chain)

        if root is None:
            raise SystemExit("Root certificate not found")

        index = chain.index(root)
        resign(chain, index, index, key_dir, days=0, ca_true=True)
        out_dir = os.path.join(export_dir, name)

    else:
        raise SystemExit("Invalid option")

    return out_dir, chain, extras
