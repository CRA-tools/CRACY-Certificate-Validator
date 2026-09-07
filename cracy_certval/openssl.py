"""The one place this toolkit talks to OpenSSL.

Every certificate operation is delegated to the system ``openssl`` binary, so
the cryptography rests on a mature, widely reviewed engine rather than on
bespoke logic. Two calling styles are needed and both live here:

* :func:`openssl` never raises — the caller inspects the return code. Used
  wherever a failure is itself a result (a certificate that will not parse, a
  chain that fails to verify).
* :func:`openssl_checked` raises :class:`OpenSSLError` — used where a failure
  means the run cannot sensibly continue, such as generating a key.

Setting ``DEBUG_CERT_CHAIN=1`` prints every command that is run.
"""

import os
import shutil
import subprocess
import sys

DEBUG = os.getenv("DEBUG_CERT_CHAIN", "0") == "1"


class OpenSSLError(RuntimeError):
    """An ``openssl`` invocation that was expected to succeed did not."""


def debug(msg):
    # stderr, so that a --json-only run stays valid, pipeable JSON even
    # with debugging switched on.
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def require_openssl():
    """Fail early, with a clear message, when ``openssl`` is not installed."""
    if shutil.which("openssl") is None:
        raise SystemExit(
            "ERROR: the 'openssl' command was not found on PATH. "
            "This toolkit delegates all certificate operations to OpenSSL "
            "3.0 or later; install it and try again."
        )


def openssl(args, data=None):
    """Run ``openssl <args>`` and return the CompletedProcess. Never raises.

    ``data`` is fed to stdin. Both streams are captured as bytes.
    """
    cmd = ["openssl"] + [str(a) for a in args]
    debug("RUN: " + " ".join(cmd))

    return subprocess.run(cmd, input=data, capture_output=True, check=False)


def openssl_checked(args, data=None):
    """Run ``openssl <args>``, raising :class:`OpenSSLError` on failure."""
    result = openssl(args, data)

    if result.returncode != 0:
        raise OpenSSLError(
            "openssl " + " ".join(str(a) for a in args) + " failed: "
            + result.stderr.decode(errors="replace").strip()
        )

    return result.stdout
