"""Analyse and classify chains — ``python -m cracy_certval.validate``.

The reference validator. It establishes what the correct verdict for a chain
*is*, so a product's own behaviour can be checked against a trusted baseline
and any disagreement recorded as a finding.

It differs from a bare ``openssl verify`` in three ways that matter for that
job: it reconstructs the chain from an unordered bundle instead of requiring
a prepared one, it classifies any failure into a named category with a
severity instead of stopping at the first terse message, and it checks the
root against a pinned fingerprint that is independent of the system trust
store.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .analysis import build_family_groups, discover_scenarios
from .openssl import require_openssl
from .reporting import build_json_report, print_family_report, write_json_report

HELP_DESCRIPTION = """\
Analyse certificate chains: rebuild each chain, verify it with OpenSSL,
check its root against the pinned root_hash.txt, and classify any failure
with a severity and a reason.\
"""

HELP_EPILOG = """\
examples:
  cracy-cert-validate invalid_chain           console report
  cracy-cert-validate invalid_chain --json    also write a JSON report
  cracy-cert-validate chain.pem --json-only   JSON on stdout, pipeable

output:
  <target>_cert_report_<timestamp>.json   default JSON destination

environment:
  DEBUG_CERT_CHAIN=1    print the openssl commands being run
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="cracy-cert-validate",
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Chain/scenario path (prompted interactively if omitted)",
    )

    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Also write a JSON report alongside the console output",
    )

    parser.add_argument(
        "--json-out",
        metavar="FILE",
        default=None,
        help=(
            "Path for the JSON output file "
            "(default: <target_basename>_cert_report_<timestamp>.json)"
        ),
    )

    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Suppress console output and emit only the JSON report",
    )

    return parser.parse_args(argv)


def resolve_target(target):
    if not target:
        target = input("Enter chain/scenario path: ").strip()

    if not target:
        raise SystemExit("ERROR: No input provided")

    if not os.path.exists(target):
        raise SystemExit(f"ERROR: Path not found: {target}")

    return target


def default_json_path(target: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(os.path.abspath(target))

    return f"{base}_cert_report_{timestamp}.json"


def main(argv=None):
    require_openssl()

    args = parse_args(argv)

    target = resolve_target(args.target)

    scenarios = discover_scenarios(target)

    if not scenarios:
        raise SystemExit(
            "ERROR: No certificate scenarios found under the given path"
        )

    grouped = build_family_groups(scenarios, target)

    emit_json = args.json or args.json_only or (args.json_out is not None)
    emit_console = not args.json_only

    if emit_console:
        print(f"\nFound {len(scenarios)} scenario(s)")

        for family, findings in grouped.items():
            print_family_report(family, findings)

    if not emit_json:
        return

    report = build_json_report(
        grouped, target, datetime.now(timezone.utc).isoformat()
    )

    # Under --json-only with no explicit destination, keep stdout clean for
    # the payload and skip writing a stray file.
    if not args.json_only or args.json_out is not None:
        path = write_json_report(
            report, args.json_out or default_json_path(target)
        )

        notice = f"\nJSON report saved to: {path}"

        # The notice goes to stderr under --json-only so stdout stays valid,
        # pipeable JSON.
        print(notice, file=sys.stderr if args.json_only else sys.stdout)

    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
