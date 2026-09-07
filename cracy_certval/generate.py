"""Build a known-good certificate chain — ``python -m cracy_certval.generate``.

The baseline the rest of the toolkit works from: a self-signed root CA, any
number of intermediate CAs, and a leaf certificate for ``example.com``, plus
the pinned root fingerprint that makes trust-anchor checking possible.

Private keys are kept alongside the certificates on purpose. The invalidator
needs them to re-sign certificates when producing the expiry and CA-constraint
scenarios, so a chain that shipped without them could only be corrupted in the
ways that need no signature. Everything written here is throwaway test
material — it is not key material for anything real.
"""

import argparse
import datetime
import os
import random
import shutil
import tempfile
import uuid

from .certs import cert_sha256
from .chains import write_pem_bundle
from .openssl import openssl_checked, require_openssl
from .pinning import write_pin

ROOT_KEY_BITS = "4096"
CA_KEY_BITS = "2048"
LEAF_KEY_BITS = "2048"

ROOT_DAYS = "3650"
INTERMEDIATE_DAYS = "1200"
LEAF_DAYS = "365"

LEAF_DNS_NAME = "example.com"

# Accepted spellings for the output format; both the menu numbers and the
# readable names map onto the internal choice.
FORMAT_CHOICES = {
    "1": "single",
    "single": "single",
    "2": "multi",
    "multi": "multi",
}

FORMAT_MENU = """
How do you want to generate the valid chain?
1. Single PEM bundle
2. Multiple PEM files
"""

ROOT_EXTENSIONS = (
    "basicConstraints=critical,CA:TRUE\n"
    "keyUsage=critical,keyCertSign,cRLSign\n"
    "subjectKeyIdentifier=hash\n"
    "authorityKeyIdentifier=keyid:always\n"
)

LEAF_EXTENSIONS = (
    "basicConstraints=critical,CA:FALSE\n"
    "keyUsage=critical,digitalSignature,keyEncipherment\n"
    "extendedKeyUsage=serverAuth\n"
    f"subjectAltName=DNS:{LEAF_DNS_NAME}\n"
    "subjectKeyIdentifier=hash\n"
    "authorityKeyIdentifier=keyid,issuer\n"
)


def intermediate_extensions(path_length: int) -> str:
    return (
        f"basicConstraints=critical,CA:TRUE,pathlen:{path_length}\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )


def make_run_dir(parent: str = ".") -> str:
    """A fresh, timestamped directory for one generated chain."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = uuid.uuid4().hex[:4]

    base = os.path.join(parent, f"valid_chain_{timestamp}_{run_id}")

    os.makedirs(base)

    return base


def _write_extension_file(directory: str, name: str, contents: str) -> str:
    path = os.path.join(directory, name)

    with open(path, "w") as handle:
        handle.write(contents)

    return path


def _generate_key(path: str, bits: str) -> None:
    openssl_checked(["genrsa", "-out", path, bits])


def _request(key_path: str, csr_path: str, common_name: str) -> None:
    openssl_checked(
        ["req", "-new", "-key", key_path, "-out", csr_path,
         "-subj", f"/CN={common_name}"]
    )


def _self_sign(csr_path: str, key_path: str, out_path: str,
               days: str, ext_file: str) -> None:
    openssl_checked(
        ["x509", "-req", "-in", csr_path, "-signkey", key_path,
         "-out", out_path, "-days", days, "-sha256", "-extfile", ext_file]
    )


def _sign(csr_path: str, issuer_cert: str, issuer_key: str, out_path: str,
          days: str, ext_file: str) -> None:
    openssl_checked(
        ["x509", "-req", "-in", csr_path,
         "-CA", issuer_cert, "-CAkey", issuer_key, "-CAcreateserial",
         "-out", out_path, "-days", days, "-sha256", "-extfile", ext_file]
    )


def generate_material(intermediate_count: int, base_dir: str,
                      temp: str) -> list:
    """Issue the whole chain, keys and CSRs into ``base_dir``.

    The certificates themselves are left in ``temp``; the caller decides how
    to lay them out. Returns the intermediate certificate paths, root-most
    last.
    """
    keys_dir = os.path.join(base_dir, "keys")
    csrs_dir = os.path.join(base_dir, "csrs")

    os.makedirs(keys_dir, exist_ok=True)
    os.makedirs(csrs_dir, exist_ok=True)

    root_ext = _write_extension_file(temp, "root.ext", ROOT_EXTENSIONS)
    int_ext = _write_extension_file(
        temp, "int.ext", intermediate_extensions(intermediate_count)
    )
    leaf_ext = _write_extension_file(temp, "leaf.ext", LEAF_EXTENSIONS)

    # Root CA
    root_key = os.path.join(keys_dir, "root.key")
    root_csr = os.path.join(csrs_dir, "root.csr")
    root_cert = os.path.join(temp, "root.crt")

    _generate_key(root_key, ROOT_KEY_BITS)
    _request(root_key, root_csr, "RootCA")
    _self_sign(root_csr, root_key, root_cert, ROOT_DAYS, root_ext)

    issuer_cert = root_cert
    issuer_key = root_key

    # Intermediate CAs, each signed by the one above it
    intermediates = []

    for index in range(1, intermediate_count + 1):
        name = f"ca_{index}"

        key = os.path.join(keys_dir, f"{name}.key")
        csr = os.path.join(csrs_dir, f"{name}.csr")
        cert = os.path.join(temp, f"{name}.crt")

        _generate_key(key, CA_KEY_BITS)
        _request(key, csr, f"Intermediate-{index}")
        _sign(csr, issuer_cert, issuer_key, cert, INTERMEDIATE_DAYS, int_ext)

        intermediates.append(cert)

        issuer_cert = cert
        issuer_key = key

    # Leaf
    leaf_key = os.path.join(keys_dir, "server.key")
    leaf_csr = os.path.join(csrs_dir, "server.csr")
    leaf_cert = os.path.join(temp, "server.crt")

    _generate_key(leaf_key, LEAF_KEY_BITS)
    _request(leaf_key, leaf_csr, LEAF_DNS_NAME)
    _sign(leaf_csr, issuer_cert, issuer_key, leaf_cert, LEAF_DAYS, leaf_ext)

    return intermediates


def output_single_pem(base_dir: str, temp: str, intermediates: list) -> str:
    """Write the chain as one bundle, deliberately shuffled.

    Bundles met in the wild are frequently unordered, so shuffling keeps the
    generated material honest: anything consuming this chain has to
    reconstruct the order rather than rely on it.
    """
    certs = (
        [os.path.join(temp, "server.crt")]
        + intermediates
        + [os.path.join(temp, "root.crt")]
    )

    random.shuffle(certs)

    blocks = []

    for path in certs:
        with open(path, "rb") as handle:
            blocks.append(handle.read())

    out = write_pem_bundle(blocks, os.path.join(base_dir, "valid_chain.pem"))

    print(f"Single PEM bundle: {out}")

    return out


def output_multi_pem(base_dir: str, temp: str, intermediates: list) -> dict:
    """Write the chain split across ``leaf/``, ``intermediates/``, ``root/``."""
    dirs = {
        "leaf": os.path.join(base_dir, "leaf"),
        "intermediates": os.path.join(base_dir, "intermediates"),
        "root": os.path.join(base_dir, "root"),
    }

    for directory in dirs.values():
        os.makedirs(directory, exist_ok=True)

    shutil.copy(
        os.path.join(temp, "server.crt"),
        os.path.join(dirs["leaf"], "server.pem"),
    )
    shutil.copy(
        os.path.join(temp, "root.crt"),
        os.path.join(dirs["root"], "root.pem"),
    )

    for index, cert in enumerate(intermediates, 1):
        shutil.copy(cert, os.path.join(dirs["intermediates"], f"ca_{index}.pem"))

    print("Saved certificates at:")
    print(f"  Leaf:          {dirs['leaf']}")
    print(f"  Intermediates: {dirs['intermediates']}")
    print(f"  Root:          {dirs['root']}")

    return dirs


def generate_chain(intermediate_count: int, output_format: str,
                   parent: str = ".") -> str:
    """Generate one complete chain and its pin. Returns the run directory."""
    require_openssl()

    base_dir = make_run_dir(parent)
    temp = tempfile.mkdtemp(prefix="cracy_generate_")

    try:
        intermediates = generate_material(intermediate_count, base_dir, temp)

        if output_format == "single":
            output_single_pem(base_dir, temp, intermediates)
        else:
            output_multi_pem(base_dir, temp, intermediates)

        root_path = os.path.join(temp, "root.crt")

        with open(root_path, "rb") as handle:
            root_pem = handle.read()

        write_pin(base_dir, cert_sha256(root_pem))

    finally:
        shutil.rmtree(temp, ignore_errors=True)

    print("Root hash pinned (SHA256 DER canonical)")
    print(f"Valid chain generated in: {base_dir}")

    return base_dir


# Command line

HELP_DESCRIPTION = """\
Generate a valid certificate chain (root CA, N intermediates, leaf) plus a
pinned root hash. Any input supplied on the command line is not prompted
for; supply them all and the run is fully non-interactive.\
"""

HELP_EPILOG = """\
inputs (prompted only when the option is omitted):
  -n N                      number of intermediates, 0 or more
  -f FORMAT                 1 | single  single PEM bundle
                                        (valid_chain.pem, shuffled)
                            2 | multi   multiple PEM files
                                        (leaf/ intermediates/ root/)

examples:
  cracy-cert-generate                   prompt for both inputs
  cracy-cert-generate -n 2              prompt for the format only
  cracy-cert-generate -n 2 -f single    no prompts

output:
  valid_chain_<timestamp>_<id>/  certs, keys/, csrs/, root_hash.txt

environment:
  DEBUG_CERT_CHAIN=1    print the openssl commands being run
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="cracy-cert-generate",
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-n", "--intermediates",
        type=int,
        default=None,
        metavar="N",
        help="Number of intermediate CAs (0 or more); prompted for if omitted",
    )

    parser.add_argument(
        "-f", "--format",
        dest="fmt",
        default=None,
        metavar="FORMAT",
        help=(
            "Output format: 1/single (one PEM bundle) or "
            "2/multi (leaf/ intermediates/ root/); prompted for if omitted"
        ),
    )

    return parser.parse_args(argv)


# Each resolver takes the command-line value and only falls back to a prompt
# when it is None, so a fully specified invocation never blocks.

def resolve_intermediates(value):
    if value is None:
        try:
            value = int(input("Enter number of intermediates: ").strip())
        except ValueError:
            raise SystemExit(
                "ERROR: number of intermediates must be an integer"
            )

    if value < 0:
        raise SystemExit("ERROR: number of intermediates cannot be negative")

    return value


def resolve_format(value):
    if value is None:
        print(FORMAT_MENU)
        value = input("Enter option: ")

    choice = FORMAT_CHOICES.get(value.strip().lower())

    if choice is None:
        raise SystemExit("ERROR: Invalid option")

    return choice


def main(argv=None):
    args = parse_args(argv)

    intermediate_count = resolve_intermediates(args.intermediates)
    output_format = resolve_format(args.fmt)

    generate_chain(intermediate_count, output_format)


if __name__ == "__main__":
    main()
