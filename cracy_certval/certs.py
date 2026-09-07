"""Inspection of a single certificate.

A certificate is passed around this toolkit as its raw PEM byte-string, and
every property is read back out of it through OpenSSL. Answers are cached by
canonical fingerprint, so repeatedly asking for the subject of the same
certificate — which path building does a great deal of — costs one subprocess.

A PEM block that OpenSSL cannot parse at all is wrapped in
:class:`CorruptedCert` rather than discarded, so that a corrupted certificate
can be reported as the finding it is instead of vanishing from the analysis.
"""

import hashlib
import re
from datetime import datetime, timezone

from .openssl import debug, openssl

# PEM framing for certificates and for private keys of any algorithm
# (RSA / EC / PKCS#8 "PRIVATE KEY" / ENCRYPTED PRIVATE KEY).
PEM_CERT_RE = rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
PEM_KEY_RE = (
    rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    rb".*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
)

# Keyed by SHA256 of the raw PEM bytes, so a certificate that cannot be
# parsed is never used as a cache key.
_FINGERPRINT_CACHE = {}
_TEXT_CACHE = {}
_DN_CACHE = {}


class CorruptedCert:
    """A PEM block OpenSSL cannot parse.

    Carried through the pipeline as a distinct type so every function that
    receives a certificate can recognise it and short-circuit cleanly.
    """

    def __init__(self, raw: bytes):
        self.raw = raw


def find_pem_certs(data: bytes) -> list:
    """Every PEM certificate block in ``data``, in order."""
    return re.findall(PEM_CERT_RE, data, re.DOTALL)


def find_pem_keys(data: bytes) -> list:
    """Every PEM private key block in ``data``, in order."""
    return re.findall(PEM_KEY_RE, data, re.DOTALL)


def to_der(cert: bytes):
    """The certificate's DER encoding, or ``None`` if it will not parse."""
    result = openssl(["x509", "-outform", "DER"], cert)

    if result.returncode != 0:
        return None

    return result.stdout


def cert_sha256(cert: bytes) -> str:
    """The canonical fingerprint ``SHA256(DER(cert))``, lowercase hex.

    Hashing the DER rather than the file means the fingerprint is independent
    of PEM line wrapping, trailing newlines and surrounding text — the same
    certificate always yields the same pin. Raises :class:`ValueError` for a
    certificate OpenSSL cannot parse.
    """
    raw_key = hashlib.sha256(cert).hexdigest()

    if raw_key not in _FINGERPRINT_CACHE:
        der = to_der(cert)

        if der is None:
            raise ValueError("Invalid certificate — OpenSSL cannot parse DER")

        _FINGERPRINT_CACHE[raw_key] = hashlib.sha256(der).hexdigest().lower()

    return _FINGERPRINT_CACHE[raw_key]


def cert_sha256_safe(cert: bytes):
    """:func:`cert_sha256`, or ``None`` for an unparseable certificate."""
    try:
        return cert_sha256(cert)
    except Exception:
        return None


def openssl_text(cert: bytes) -> str:
    """``openssl x509 -text`` output for the certificate."""
    key = cert_sha256(cert)

    if key not in _TEXT_CACHE:
        result = openssl(["x509", "-noout", "-text"], cert)

        if result.returncode != 0:
            raise ValueError(result.stderr.decode(errors="replace"))

        _TEXT_CACHE[key] = result.stdout.decode(errors="replace")

    return _TEXT_CACHE[key]


def get_dn(cert: bytes, field: str) -> str:
    """The ``subject`` or ``issuer`` distinguished name, in RFC 2253 form."""
    key = f"{cert_sha256(cert)}:{field}"

    if key not in _DN_CACHE:
        result = openssl(
            ["x509", "-noout", f"-{field}", "-nameopt", "RFC2253"], cert
        )

        if result.returncode != 0:
            raise ValueError(result.stderr.decode(errors="replace"))

        value = result.stdout.decode(errors="replace").strip()

        # Strip the "subject="/"issuer=" label OpenSSL prefixes.
        if "=" in value:
            value = value.split("=", 1)[1].strip()

        _DN_CACHE[key] = value

    return _DN_CACHE[key]


def subject(cert: bytes) -> str:
    return get_dn(cert, "subject")


def issuer(cert: bytes) -> str:
    return get_dn(cert, "issuer")


def common_name(cert: bytes) -> str:
    """The subject CN, or ``"Unknown"`` when the DN carries none."""
    match = re.search(r"CN=([^,]+)", subject(cert))

    return match.group(1) if match else "Unknown"


def is_ca(cert: bytes) -> bool:
    """Whether basic constraints assert ``CA:TRUE``."""
    try:
        return "CA:TRUE" in openssl_text(cert)
    except Exception:
        return False


def is_self_signed(cert: bytes) -> bool:
    try:
        return subject(cert) == issuer(cert)
    except Exception:
        return False


def not_after(cert: bytes):
    """Expiry as an aware UTC datetime, or ``None`` if it cannot be read."""
    result = openssl(["x509", "-noout", "-enddate"], cert)

    if result.returncode != 0:
        return None

    text = result.stdout.decode(errors="replace").strip()

    if "=" not in text:
        return None

    value = text.split("=", 1)[1].strip()

    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except Exception:
        debug(f"Unparseable notAfter: {value!r}")
        return None


def is_expired(cert: bytes) -> bool:
    """Whether the certificate's ``notAfter`` is in the past.

    An unreadable expiry is not treated as expired; the chain verification
    stage reports that certificate on its own terms instead.
    """
    expiry = not_after(cert)

    if expiry is None:
        return False

    return datetime.now(timezone.utc) > expiry


def public_key(cert: bytes) -> bytes:
    """The certificate's public key in PEM form, for matching against keys."""
    return openssl(["x509", "-pubkey", "-noout"], cert).stdout
