"""CRACY Certificate Validator — a toolkit for testing certificate-validation logic.

Three cooperating programs, all driven through the system ``openssl`` binary:

* :mod:`cracy_certval.generate`   build a known-good chain with a pinned root hash
* :mod:`cracy_certval.invalidate` derive isolated single-defect chains from it
* :mod:`cracy_certval.validate`   classify any chain, with a severity and a reason

The shared machinery lives in :mod:`cracy_certval.certs` (single-certificate
inspection), :mod:`cracy_certval.chains` (path building and verification),
:mod:`cracy_certval.pinning` (the trust-anchor pin) and
:mod:`cracy_certval.loading` (multi-format certificate and key input).
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
