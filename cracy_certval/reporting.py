"""Turning findings into a console report and into filable evidence.

The JSON report is the reason this exists. Unstructured console text cannot
be diffed between builds, attached to technical documentation, or fed into
CI, so every finding is also emitted as a structured record carrying its
classification, severity, reason, chain and the raw OpenSSL diagnostics
behind the verdict.
"""

import json
import os
from collections import Counter

from .certs import subject
from .findings import Classification

CONSOLE_WIDTH = 70


def serialize_finding(finding) -> dict:
    """One finding as a JSON-safe record.

    The chain is rendered as subject DNs: a report is meant to be read, and a
    list of PEM blobs would be neither readable nor diffable.
    """
    chain = []

    for cert in finding.path:
        try:
            chain.append(subject(cert))
        except Exception:
            chain.append("<unreadable>")

    return {
        "variant": finding.variant,
        "valid": finding.valid,
        "classification": finding.classification,
        "severity": finding.severity,
        "reason": finding.reason,
        "diagnostics": finding.diagnostics.strip(),
        "chain": chain,
    }


def build_json_report(grouped: dict, search_root: str,
                      generated_at: str) -> dict:
    """The full report across all families.

    Schema::

        {
          "generated_at": "<ISO-8601 timestamp>",
          "scan_root": "<absolute path>",
          "summary": {"<CLASSIFICATION>": <total count>, ...},
          "families": [
            {
              "family": "<name>",
              "variants": ["INT1", "INT2", ...],
              "results": [<serialized finding>, ...],
              "summary": {"<CLASSIFICATION>": <count>, ...}
            },
            ...
          ]
        }
    """
    families = []
    totals = Counter()

    for family, findings in grouped.items():
        counts = Counter(finding.classification for finding in findings)
        totals += counts

        families.append(
            {
                "family": family,
                "variants": _variants(findings),
                "results": [serialize_finding(f) for f in findings],
                "summary": dict(counts),
            }
        )

    return {
        "generated_at": generated_at,
        "scan_root": os.path.abspath(search_root),
        "summary": dict(totals),
        "families": families,
    }


def write_json_report(report: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    return path


def _variants(findings: list) -> list:
    return list(dict.fromkeys(finding.variant for finding in findings))


def print_family_report(family: str, findings: list) -> None:
    """The console report for one classification family."""
    print("\n" + "=" * CONSOLE_WIDTH)
    print(f"ATTACK FAMILY: {family.upper()}")
    print("=" * CONSOLE_WIDTH)

    variants = _variants(findings)

    print("\nVariants:")

    for variant in variants:
        print(f"  - {variant}")

    print(f"\nTotal Variants: {len(variants)}")

    print("\n" + "-" * CONSOLE_WIDTH)
    print("SUMMARY")
    print("-" * CONSOLE_WIDTH)

    for classification, count in Counter(
        finding.classification for finding in findings
    ).items():
        print(f"\n  {classification}: {count} variant(s)")

    print("\n" + "-" * CONSOLE_WIDTH)
    print("DETAILED ANALYSIS")
    print("-" * CONSOLE_WIDTH)

    for finding in findings:
        _print_finding(finding)

    print("\n" + "=" * CONSOLE_WIDTH)


def _print_finding(finding) -> None:
    print(f"\n[{finding.variant}]")
    print(f"  Result:         {'VALID' if finding.valid else 'INVALID'}")
    print(f"  Classification: {finding.classification}")
    print(f"  Severity:       {finding.severity}")
    print(f"  Reason:         {finding.reason}")

    if finding.path:
        print("\n  Chain:")

        for cert in finding.path:
            try:
                print(f"    -> {subject(cert)}")
            except Exception:
                print("    -> [UNREADABLE]")
    elif finding.classification == Classification.CA_BUNDLE:
        print(
            "\n  Chain:          (not applicable - CA bundle contains "
            f"{finding.bundle_count} certificates)"
        )
    else:
        print("\n  Chain:          (none — bundle fully corrupted or empty)")

    print("\n  Diagnostics:")

    diagnostics = finding.diagnostics.strip() or "No diagnostics available"

    print("    " + diagnostics.replace("\n", "\n    "))
