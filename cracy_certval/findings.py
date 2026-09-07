"""What a result looks like.

The validator does not answer "valid or not". It answers with a named
classification, a severity, a human-readable reason, and the raw OpenSSL
diagnostics behind the verdict — which is the difference between a terse
error and something that can be filed as evidence, diffed across builds, or
shown to an auditor.
"""

from dataclasses import dataclass, field


class Severity:
    """How serious a classification is.

    ``CRITICAL`` is reserved for failures that defeat trust itself: a
    corrupted or forged certificate, an expired trust anchor, or a chain that
    verifies perfectly but anchors to the wrong root. ``HIGH`` covers the
    chain defects a correct verifier is expected to catch.
    """

    NONE = "NONE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Classification:
    """The defect taxonomy — one name per way a chain can be wrong.

    The invalidator's scenarios and these classifications are two views of
    the same taxonomy: every scenario is expected to produce a specific
    classification, which is what lets a product's own verdict be compared
    against a known-good reference.
    """

    VALID = "VALID"
    STRUCTURALLY_VALID = "STRUCTURALLY_VALID"
    EXPIRED_LEAF = "EXPIRED_LEAF"
    EXPIRED_INTERMEDIATE = "EXPIRED_INTERMEDIATE"
    EXPIRED_ROOT = "EXPIRED_ROOT"
    NON_CA_INTERMEDIATE = "NON_CA_INTERMEDIATE"
    MISSING_INTERMEDIATE = "MISSING_INTERMEDIATE"
    CORRUPTED_CERTIFICATE = "CORRUPTED_CERTIFICATE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    SELF_SIGNED = "SELF_SIGNED"
    UNTRUSTED_ROOT = "UNTRUSTED_ROOT"
    ROOT_HASH_MISMATCH = "ROOT_HASH_MISMATCH"
    ROOT_HASH_NOT_CHECKED = "ROOT_HASH_NOT_CHECKED"
    CA_BUNDLE = "CA_BUNDLE"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


@dataclass
class Finding:
    """One verdict about one candidate chain."""

    classification: str
    severity: str
    reason: str
    diagnostics: str = ""
    valid: bool = False

    # The chain this verdict is about, leaf first, as PEM byte-strings. Empty
    # when no chain could be built at all.
    path: list = field(default_factory=list)

    # Set once the finding is attributed to the scenario it came from.
    variant: str = "DEFAULT"
    scenario: str = ""

    # Only meaningful for CA_BUNDLE, where there is no chain to show.
    bundle_count: int = None
