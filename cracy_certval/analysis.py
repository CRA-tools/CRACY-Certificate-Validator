"""Classifying a chain: what is wrong with it, and how serious that is.

Analysis runs in two stages, deliberately kept apart.

**Structural integrity** asks whether the chain is well-formed and
cryptographically sound: does it reach a self-signed root, is every
certificate signed by its issuer, is anything expired, is any intermediate
missing its CA constraint.

**Trust anchoring** asks the separate question of whether the root the chain
arrives at is the root that was actually expected. A chain can pass the first
stage and fail this one — and that case, ``ROOT_HASH_MISMATCH``, is the most
dangerous failure the toolkit can detect, because conventional verification
reports it as perfectly valid.

The stages stay in that order for a reason: trust anchoring is only
meaningful once the chain has verified, so a structural failure is reported
as itself rather than being masked by a pin result.
"""

import os
import re
from collections import defaultdict

from .certs import (
    cert_sha256_safe,
    is_ca,
    is_expired,
    is_self_signed,
    issuer,
    subject,
)
from .chains import build_paths, chain_is_incomplete, find_root, verify_chain
from .findings import Classification, Finding, Severity
from .loading import (
    discover_chain_files,
    file_contains_certificate,
    load_cert_blocks,
    split_certs,
)
from .pinning import find_pin_file, read_pin, verify_pin

# Diagnostics OpenSSL emits, mapped onto the taxonomy. Order matters: the
# first matching entry wins, most specific first.
_OUTPUT_SIGNATURES = (
    (
        ("unable to load certificate",),
        Classification.CORRUPTED_CERTIFICATE,
        Severity.CRITICAL,
        "Certificate data is corrupted",
    ),
    (
        ("certificate signature failure",),
        Classification.INVALID_SIGNATURE,
        Severity.CRITICAL,
        "Signature verification failed",
    ),
    (
        ("invalid ca certificate", "path length constraint"),
        Classification.NON_CA_INTERMEDIATE,
        Severity.HIGH,
        "Intermediate is not a valid CA certificate",
    ),
    (
        ("unable to get local issuer", "unable to get issuer"),
        Classification.MISSING_INTERMEDIATE,
        Severity.HIGH,
        "Missing intermediate certificate",
    ),
    (
        ("self signed certificate",),
        Classification.SELF_SIGNED,
        Severity.HIGH,
        "Self-signed certificate not trusted",
    ),
    (
        ("unable to verify the first certificate",),
        Classification.UNTRUSTED_ROOT,
        Severity.HIGH,
        "Root certificate is not trusted",
    ),
)


def find_non_ca_intermediates(path: list, all_certs: list) -> list:
    """Certificates that would complete ``path`` but are not CAs.

    When a chain stops short, the reason is often present in the bundle: an
    intermediate that was re-issued with ``CA:FALSE`` cannot be used as a
    link, so path building steps over it and the chain looks merely
    incomplete. Looking for the unresolved issuer among the non-CA
    certificates recovers the real defect, which is a different and more
    specific finding than a missing intermediate.
    """
    path_subjects = set()

    for cert in path:
        try:
            path_subjects.add(subject(cert))
        except Exception:
            continue

    unresolved_issuers = set()

    for cert in path:
        try:
            name = issuer(cert)

            if name not in path_subjects:
                unresolved_issuers.add(name)
        except Exception:
            continue

    non_ca = []

    for cert in all_certs:
        try:
            name = subject(cert)

            if name in unresolved_issuers and not is_ca(cert):
                non_ca.append((cert, name))
        except Exception:
            continue

    return non_ca


def classify_failure(path: list, diagnostics: str, all_certs: list) -> tuple:
    """Name the defect behind a failed verification.

    Certificate properties are examined before OpenSSL's message is
    consulted, because a property is unambiguous where the message often is
    not: OpenSSL reports an expired intermediate and a missing one with
    similar wording, but expiry can simply be read off the certificate.
    Returns ``(classification, severity, reason)``.
    """
    if is_expired(path[0]):
        return (
            Classification.EXPIRED_LEAF,
            Severity.HIGH,
            "Leaf certificate is expired",
        )

    expired_intermediates = []

    for cert in path[1:-1]:
        if is_expired(cert):
            try:
                expired_intermediates.append(subject(cert))
            except Exception:
                expired_intermediates.append("<unknown>")

    if expired_intermediates:
        return (
            Classification.EXPIRED_INTERMEDIATE,
            Severity.HIGH,
            "Expired intermediates: " + ", ".join(expired_intermediates),
        )

    root = find_root(path)

    if root is not None and is_expired(root):
        return (
            Classification.EXPIRED_ROOT,
            Severity.CRITICAL,
            "Root certificate is expired",
        )

    non_ca = find_non_ca_intermediates(path, all_certs)

    if non_ca:
        subjects = ", ".join(dn for _, dn in non_ca)
        return (
            Classification.NON_CA_INTERMEDIATE,
            Severity.HIGH,
            f"Intermediate(s) missing CA:TRUE constraint: {subjects}",
        )

    if len(path) == 1:
        return (
            Classification.MISSING_INTERMEDIATE,
            Severity.HIGH,
            "No intermediate or root certificate found for leaf",
        )

    try:
        last = path[-1]

        if not is_self_signed(last) and not is_ca(last):
            return (
                Classification.MISSING_INTERMEDIATE,
                Severity.HIGH,
                "Chain is incomplete — root or intermediate certificate "
                "missing",
            )
    except Exception:
        pass

    text = diagnostics.lower()

    for needles, classification, severity, reason in _OUTPUT_SIGNATURES:
        if any(needle in text for needle in needles):
            return classification, severity, reason

    return (
        Classification.UNKNOWN_FAILURE,
        Severity.UNKNOWN,
        "Unclassified validation failure",
    )


def _incomplete_finding(path: list, valid_certs: list, reason: str) -> Finding:
    """A chain that does not reach a root — as specifically as possible."""
    non_ca = find_non_ca_intermediates(path, valid_certs)

    if non_ca:
        subjects = ", ".join(dn for _, dn in non_ca)

        return Finding(
            path=path,
            diagnostics="Chain incomplete — non-CA intermediate detected",
            classification=Classification.NON_CA_INTERMEDIATE,
            severity=Severity.HIGH,
            reason=f"Intermediate(s) missing CA:TRUE constraint: {subjects}",
        )

    return Finding(
        path=path,
        diagnostics="Chain incomplete — missing intermediate/root",
        classification=Classification.MISSING_INTERMEDIATE,
        severity=Severity.HIGH,
        reason=reason,
    )


def check_structural_integrity(path: list, valid_certs: list) -> Finding:
    """Stage 1 — is the chain well-formed and cryptographically sound?"""
    if len(path) == 1:
        return _incomplete_finding(
            path,
            valid_certs,
            "No intermediate or root certificate found for leaf",
        )

    if chain_is_incomplete(path):
        return _incomplete_finding(
            path,
            valid_certs,
            "Chain terminated before reaching a trusted root CA",
        )

    verified, diagnostics = verify_chain(path)

    if not verified:
        classification, severity, reason = classify_failure(
            path, diagnostics, valid_certs
        )

        return Finding(
            path=path,
            diagnostics=diagnostics,
            classification=classification,
            severity=severity,
            reason=reason,
        )

    return Finding(
        path=path,
        valid=True,
        diagnostics=diagnostics,
        classification=Classification.STRUCTURALLY_VALID,
        severity=Severity.NONE,
        reason="Chain is structurally and cryptographically valid",
    )


def check_trust_anchor(structural: Finding, pin_file: str,
                       pinned_hash: str) -> Finding:
    """Stage 2 — is the root it reaches the root that was expected?"""
    path = structural.path
    diagnostics = structural.diagnostics

    if pin_file is None:
        return Finding(
            path=path,
            diagnostics=diagnostics,
            classification=Classification.ROOT_HASH_NOT_CHECKED,
            severity=Severity.HIGH,
            reason=(
                "Chain is cryptographically valid but no root_hash.txt was "
                "found; root certificate identity is not pinned"
            ),
        )

    root_cert = find_root(path)

    if root_cert is None or pinned_hash is None:
        return Finding(
            path=path,
            diagnostics=diagnostics,
            classification=Classification.ROOT_HASH_MISMATCH,
            severity=Severity.CRITICAL,
            reason=(
                "Root hash could not be verified "
                "(root certificate unextractable or hash file unreadable)"
            ),
        )

    if verify_pin(root_cert, pinned_hash):
        return Finding(
            path=path,
            valid=True,
            diagnostics=diagnostics,
            classification=Classification.VALID,
            severity=Severity.NONE,
            reason="No issue — chain valid and root hash matches",
        )

    actual = cert_sha256_safe(root_cert) or "<unknown>"

    return Finding(
        path=path,
        diagnostics=diagnostics,
        classification=Classification.ROOT_HASH_MISMATCH,
        severity=Severity.CRITICAL,
        reason=(
            f"Root hash mismatch — "
            f"expected {pinned_hash[:16]}…, got {actual[:16]}…"
        ),
    )


def _corrupted_block_finding(count: int, context: str) -> Finding:
    return Finding(
        diagnostics=f"{count} corrupted PEM block(s) were {context}",
        classification=Classification.CORRUPTED_CERTIFICATE,
        severity=Severity.CRITICAL,
        reason=(
            f"{count} certificate block(s) in the bundle could not be "
            f"parsed by OpenSSL"
        ),
    )


def _ca_bundle_findings(valid_certs: list, corrupted_count: int) -> list:
    """A trust bundle is not a chain, and is reported as what it is.

    Forcing chain construction over a directory of CA certificates would
    produce a stream of misleading "missing intermediate" findings, so the
    input is named a CA bundle instead.
    """
    self_signed = sum(1 for cert in valid_certs if is_self_signed(cert))

    findings = [
        Finding(
            valid=not corrupted_count,
            diagnostics=(
                f"Parsed {len(valid_certs)} CA certificate(s); "
                f"{self_signed} are self-signed"
            ),
            classification=Classification.CA_BUNDLE,
            severity=Severity.NONE if not corrupted_count else Severity.HIGH,
            reason=(
                "Input is a CA certificate bundle and does not contain an "
                "end-entity certificate chain"
            ),
            bundle_count=len(valid_certs),
        )
    ]

    if corrupted_count:
        findings.append(
            _corrupted_block_finding(corrupted_count, "found in the CA bundle")
        )

    return findings


def analyze_scenario(folder: str, search_root: str) -> list:
    """Every finding for one scenario — a directory or a single file."""
    entries = load_cert_blocks(discover_chain_files(folder))

    if not entries:
        return []

    valid_certs, corrupted_certs = split_certs(entries)
    corrupted_count = len(corrupted_certs)

    if not valid_certs:
        return [
            Finding(
                diagnostics=(
                    "All certificate blocks in this scenario are corrupted"
                ),
                classification=Classification.CORRUPTED_CERTIFICATE,
                severity=Severity.CRITICAL,
                reason=(
                    f"{corrupted_count} corrupted PEM block(s) — OpenSSL "
                    "cannot parse any certificate in the bundle"
                ),
            )
        ]

    if all(is_ca(cert) for cert in valid_certs):
        return _ca_bundle_findings(valid_certs, corrupted_count)

    paths = build_paths(valid_certs)

    if not paths:
        return [
            Finding(
                diagnostics="No leaf certificate found in bundle",
                classification=(
                    Classification.CORRUPTED_CERTIFICATE if corrupted_count
                    else Classification.MISSING_INTERMEDIATE
                ),
                severity=(
                    Severity.CRITICAL if corrupted_count else Severity.HIGH
                ),
                reason=(
                    "Bundle contains no end-entity (CA:FALSE) certificate"
                    + (
                        " — some blocks are corrupted" if corrupted_count
                        else ""
                    )
                ),
            )
        ]

    pin_file = find_pin_file(folder, search_root)
    pinned_hash = read_pin(pin_file) if pin_file else None

    findings = []

    for path in paths:
        structural = check_structural_integrity(path, valid_certs)

        if structural.valid:
            findings.append(
                check_trust_anchor(structural, pin_file, pinned_hash)
            )
        else:
            findings.append(structural)

    # Corruption that path building stepped over is still a finding, unless
    # some chain already reported it.
    if corrupted_count and not any(
        f.classification == Classification.CORRUPTED_CERTIFICATE
        for f in findings
    ):
        findings.append(
            _corrupted_block_finding(
                corrupted_count, "skipped during chain building"
            )
        )

    return findings


# Scenario discovery and grouping

# Subdirectory names emitted by the generator's multi-PEM mode. When a single
# chain is split across these sibling folders, the common parent must be
# analysed as ONE scenario, not three independent ones. These exact names
# never collide with the invalidator's scenario folders (expired_root,
# root_hash_mismatch, intN, ...), so the collapse is safe.
MULTIPEM_SUBDIRS = {"leaf", "intermediates", "root"}


def discover_scenarios(base: str) -> list:
    """Every directory under ``base`` that holds a chain to analyse."""
    if os.path.isfile(base):
        # Analyse exactly the file supplied. Returning its parent directory
        # would unintentionally include unrelated PEM files stored beside it.
        return [os.path.abspath(base)] if file_contains_certificate(base) else []

    holding_certs = set()

    for root, _, files in os.walk(base):
        for name in files:
            if file_contains_certificate(os.path.join(root, name)):
                holding_certs.add(os.path.abspath(root))
                break

    scenarios = set()

    for directory in holding_certs:
        if os.path.basename(directory).lower() in MULTIPEM_SUBDIRS:
            scenarios.add(os.path.dirname(directory))
        else:
            scenarios.add(directory)

    return sorted(scenarios)


def variant_name(scenario_path: str) -> str:
    """A label for which depth of a scenario this is — ``INT1``, ``INT2``."""
    match = re.match(r"(int\d+)", os.path.basename(scenario_path), re.IGNORECASE)

    return match.group(1).upper() if match else "DEFAULT"


def build_family_groups(scenarios: list, search_root: str) -> dict:
    """Analyse every scenario, then group findings by classification.

    Grouping on the *detected* classification rather than on the directory
    name is what keeps the report honest: a folder called
    ``expired_intermediate`` appears under that heading only if the analysis
    independently reaches that conclusion. Directory names contribute the
    variant label alone.
    """
    grouped = defaultdict(list)

    for scenario in scenarios:
        absolute = os.path.abspath(scenario)

        for finding in analyze_scenario(scenario, search_root):
            finding.variant = variant_name(absolute)
            finding.scenario = absolute
            grouped[finding.classification].append(finding)

    return dict(grouped)
