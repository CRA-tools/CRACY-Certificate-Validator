# CRACY Certificate Validator

A toolkit for testing whether a product correctly **rejects** broken certificate chains. It
generates certificate chains that are valid in every respect except one deliberately introduced
defect, and independently establishes what the correct verdict for each one should be.

Everything runs locally, offline, through the system `openssl` command. No certificate or key
material leaves the machine.

## What it does

A product's ability to validate X.509 chains underpins every security control layered on top of it:
TLS server and mutual authentication, signed firmware updates, device identity. A device that
silently accepts an expired, malformed or wrongly-rooted chain undermines all of them.

The toolkit is a harness for proving that it does not. It works in three steps:

1. **Generate** a clean baseline chain — a self-signed root CA, any number of intermediate CAs, a
   leaf certificate — with the root's fingerprint pinned in a `root_hash.txt`.
2. **Invalidate** that chain into a battery of variants, each carrying exactly **one** defect drawn
   from a taxonomy of commonly overlooked validation failures.
3. **Validate** each variant with the reference validator, which classifies it into that same
   taxonomy with a severity and a reason, and records the result as a JSON report.

The invalidated chains are the primary work product. They are what you present to the product under
test, exactly as it would encounter them in normal operation — during a firmware update, or a TLS
handshake. A correctly implemented product must reject every one of them; accepting even a single
one is a finding. The generator and the reference validator exist to create that material and to
establish independently what the correct verdict is, so the product's actual behaviour can be
compared against a trusted baseline.

Isolating a single defect per chain is what makes a failure attributable. Each chain exercises one
specific check, so a gap in the product's validation logic points at a named check rather than
disappearing among several simultaneous problems.

For the full background — what the toolkit is for, how it compares with scanners and command-line
primitives, and worked output — see the [user guide](docs/certval_user_guide.md).

## Why it exists

The tools manufacturers reach for to check certificates each fall short of what compliance evidence
needs. Live TLS checkers validate whatever a socket happens to serve at that moment, and cannot
touch the PEM bundles, PKCS#7 packages and PKCS#12 containers exchanged between teams or embedded in
firmware before anything is served over a network. Bare `openssl verify` validates offline files but
was designed as a building block, not a compliance instrument: it stops at the first problem and
prints one terse line, leaving the operator to guess whether the cause was a missing intermediate, a
non-CA intermediate, an expired certificate or an untrusted root, with no indication of severity.

Trust anchoring is the deeper gap. Standard tooling trusts whatever authorities are installed in the
operating system's certificate store, so a structurally perfect chain terminating at the wrong —
but publicly trusted — root passes, even though it is not the identity the product should accept.
And unstructured console output cannot be filed as machine-readable evidence, diffed across builds,
or attached to a compliance report without manual transcription. There is also no accessible,
reproducible way to generate the specific defective chains needed to prove a product rejects them,
so certificate handling tends to be tested ad hoc and rarely documented.

## The pinned root hash

Each generated chain ships with a `root_hash.txt` holding the canonical fingerprint of its root:

```
SHA256( DER(root_cert) )
```

This is the *trust anchor pin*, and it is what lets the toolkit keep two questions apart:

- Is this chain structurally and cryptographically sound?
- Does it anchor to the one root actually trusted?

A chain can pass the first and fail the second. A perfectly valid chain whose root fingerprint does
not match the pinned value is reported as `ROOT_HASH_MISMATCH` at **CRITICAL** severity — the most
dangerous case the toolkit can detect, precisely because conventional verification reports it as
valid. The `root_hash_mismatch` scenario exists to test exactly that.

Hashing the DER rather than the file means the pin is independent of PEM line wrapping and trailing
whitespace, so a chain still matches its own pin after a round trip through a text editor.

## Privacy and scope

The toolkit performs **no network connections whatsoever**. Every operation is carried out on local
files, and nothing is fetched or reported anywhere, which makes it safe to use on confidential
material and inside air-gapped environments.

The generators create certificate material and write it only to local files. In typical use the
operator then transfers that output — most often the invalidated chains — to the product under test
in order to run the assessment. That transfer is a deliberate action taken by the operator, not
something the toolkit performs.

Results support demonstrating conformity with a number of CRA essential requirements:

- **Full** (within the certificate and trust scope) — integrity (ER13) and regular testing of
  security properties (VH5).
- **Partial** — secure distribution of updates (VH11) and no known exploitable vulnerabilities
  (ER2).
- **Supporting** — access control (ER10), confidentiality (ER12), secure transfer of data (ER25) and
  documenting performed tests (DR5).

The [ER and measure mapping](docs/CRACY_Certificate_Validator_ER_mapping.md) is the authoritative
version, with the full requirement-by-requirement table and a second table mapping the assessment
onto the CRACY REPO measures.

Three limits shape how the Full rating should be read. The toolkit checks the chain and the pinned
root, not certificate lifecycle status: it performs **no revocation checking** (no CRL, OCSP or OCSP
stapling), so a chain that is otherwise valid but has since been revoked still passes. It checks
trust anchoring and structure, not server identity: it does **not** compare the leaf against an
expected hostname or SAN. And it relies on OpenSSL's strict-mode defaults for algorithm strength
rather than independently flagging weak keys or superseded hashes such as RSA-1024 or SHA-1. Full
means full coverage of the certificate and trust mechanism specifically, not a general statement
about integrity or testing maturity.

Part of the CRACY compliance assessment suite. Free and open source, available in the CRACY and CRA
Cluster tools GitHub at https://github.com/CRA-tools.

---

## Prerequisites

- **OpenSSL 3.0 or later**, on your `PATH`. All certificate parsing, signature verification and DER
  hashing is delegated to it.
- **Python 3.9 or later**. No third-party Python packages are needed — the toolkit uses only the
  standard library.
- **Git**, to clone the repository.
- A writable working directory, since chains and pins are written as files.

Check what you have with `openssl version`, `python --version` and `git --version`. Linux is the
supported platform.

## Setup

### Step 1: Clone the repository

```
git clone https://github.com/CRA-tools/CRACY-Certificate-Validator.git
cd CRACY-Certificate-Validator
```

> Prefer SSH? Use `git clone git@github.com:CRA-tools/CRACY-Certificate-Validator.git` instead.
> No account is needed to clone over HTTPS.

### Step 2: Create and activate a virtual environment

(A virtual environment is an isolated space for the project, so it does not interfere with other
Python software on your computer.)

```
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
```

You only need to create it once.

### Step 3: Install the toolkit

```
pip install .
```

This puts three commands on your `PATH`: `cracy-cert-generate`, `cracy-cert-invalidate` and
`cracy-cert-validate`.

> **Prefer not to install anything?** You don't have to. From the project folder, every command is
> also available as a module — `python -m cracy_certval.generate`,
> `python -m cracy_certval.invalidate`, `python -m cracy_certval.validate` — with identical
> arguments. The examples below use the short command names.

---

## Typical workflow

```bash
# 1. Generate a valid 2-intermediate chain
cracy-cert-generate -n 2 -f single
#    -> creates valid_chain_20260720_143012_ab12/

# 2. Produce every corruption scenario from it
cracy-cert-invalidate valid_chain_20260720_143012_ab12/ -s all -p 1,2
#    -> populates invalid_chain/

# 3. Analyse the results
cracy-cert-validate invalid_chain --json
#    -> console report + JSON file classifying each broken chain
```

In a real assessment, step 1 is replaced by a chain relevant to the product's own use case — the
chain that signs its firmware updates, or authenticates its TLS endpoint. Point the invalidator at
that instead, and it will confirm the chain is genuinely valid before corrupting it.

Every command prompts only for inputs that were **not** supplied on the command line, so a fully
specified invocation runs unattended — which is what makes the toolkit usable from CI. Add `-h` to
any of them for the full option list.

---

## The commands

### 1. `cracy-cert-generate` — build a known-good chain

Generates a complete, valid chain: a self-signed root CA, a configurable number of intermediate CAs,
and a leaf (server) certificate for `example.com`.

```bash
cracy-cert-generate                  # prompt for both inputs
cracy-cert-generate -n 2             # prompt only for the output format
cracy-cert-generate -n 2 -f single    # fully non-interactive
```

| Input | Option | Values |
|-------|--------|--------|
| Number of intermediates | `-n`, `--intermediates` | `0` or more |
| Output format | `-f`, `--format` | `1`/`single` or `2`/`multi` |

The two output formats are:

1. **Single PEM bundle** (`1`/`single`) — all certificates concatenated into one `valid_chain.pem`,
   deliberately shuffled to mimic the unordered bundles met in practice.
2. **Multiple PEM files** (`2`/`multi`) — split across `leaf/`, `intermediates/` and `root/`
   subdirectories.

Output lands in a fresh `valid_chain_<timestamp>_<id>/` directory containing the certificates in the
chosen format, `keys/` with all private keys, `csrs/` with the signing requests, and `root_hash.txt`
with the pinned root fingerprint.

The private keys are retained because the invalidator needs them to re-sign certificates when
producing the expiry and CA-constraint scenarios. A chain that shipped without them could only be
corrupted in the ways that need no signature.

### 2. `cracy-cert-invalidate` — corrupt a valid chain

Takes an existing valid chain and produces one or more *isolated* broken chains, each containing
exactly one defect.

```bash
cracy-cert-invalidate                                            # prompt for everything
cracy-cert-invalidate valid_chain_20260720_143012_ab12/          # prompt for the scenarios
cracy-cert-invalidate valid_chain_20260720_143012_ab12/ -s all -p 1,2
cracy-cert-invalidate chain.pem -s corrupted_server,root_hash_mismatch
```

| Input | Option | Values |
|-------|--------|--------|
| Certificate path(s) | positional | one or more files/directories |
| Scenario(s) | `-s`, `--scenarios` | comma-separated numbers or names, or `all` |
| Intermediate position(s) | `-p`, `--positions` | comma-separated numbers; `-p ''` targets none |

`-p` is only relevant to scenarios 3, 4 and 5, and is prompted for only when one of those is
selected. Invalid selections are rejected up front, before the chain is built, so a typo fails
immediately.

The command first rebuilds and validates the input chain — using `root_hash.txt` if present — before
corrupting it.

**Corruption scenarios:**

| # | Scenario | Needs a private key? |
|---|----------|----------------------|
| 1 | `expired_server` — re-signs the leaf with a 0-day validity | leaf + issuing-CA key |
| 2 | `corrupted_server` — mangles the leaf's PEM body, keeping BEGIN/END framing | no |
| 3 | `expired_intermediate` — re-signs a chosen intermediate as expired | intermediate + issuing-CA key |
| 4 | `non_ca_intermediate` — re-signs an intermediate with `CA:FALSE` | intermediate + issuing-CA key |
| 5 | `missing_intermediate` — deletes a chosen intermediate from the chain | no |
| 6 | `root_hash_mismatch` — chain stays valid, but `root_hash.txt` is wrong | no |
| 7 | `root_hash_not_checked` — valid chain emitted with no pin file | no |
| 8 | `expired_root` — re-signs the root as expired | root key |

Scenarios 3, 4 and 5 operate on a specific intermediate **position**, so different depths of the
chain can be targeted. Each result is written under `invalid_chain/<scenario_name>/`, with position
scenarios adding an `int<N>/` subfolder. A scenario that needs a key it cannot find is skipped with
a `[skip]` notice rather than failing the run.

**Input formats accepted:** PEM, DER, PKCS#7 (`.p7b`/`.p7c`) and PKCS#12 (`.p12`/`.pfx`). Keys in
PEM, DER, PKCS#8 and PKCS#12 form are all normalised to PEM, and RSA and EC keys are handled
identically — so the invalidator can work on real-world material rather than only on purpose-built
input.

An encrypted PKCS#12 input is prompted for its password. To keep such a run unattended, set
`CRACY_P12_PASSWORD` in the environment (preferred) or pass `--p12-password`. The environment
variable is the safer of the two: an argument is visible in the shell history and the process list.

### 3. `cracy-cert-validate` — analyse and classify chains

The reference validator. It scans a path for certificate scenarios, builds every candidate chain,
verifies each with `openssl verify -x509_strict`, checks the root against `root_hash.txt`, and
classifies any failure.

```bash
cracy-cert-validate <path>                      # console report
cracy-cert-validate <path> --json               # also write a JSON report
cracy-cert-validate <path> --json-out report.json
cracy-cert-validate <path> --json-only          # only JSON, on stdout, pipeable
```

If no path is given, it prompts for one.

**What it detects.** Each analysed chain is classified as one of:

- `VALID` / `STRUCTURALLY_VALID` — passes verification, and the root pin where one exists
- `EXPIRED_LEAF`, `EXPIRED_INTERMEDIATE`, `EXPIRED_ROOT`
- `NON_CA_INTERMEDIATE` — an intermediate missing the `CA:TRUE` constraint
- `MISSING_INTERMEDIATE` — the chain does not reach a trusted root
- `CORRUPTED_CERTIFICATE` — a PEM block OpenSSL cannot parse
- `INVALID_SIGNATURE`, `SELF_SIGNED`, `UNTRUSTED_ROOT`
- `ROOT_HASH_MISMATCH` — chain valid but the root does not match the pin (CRITICAL)
- `ROOT_HASH_NOT_CHECKED` — chain valid but no `root_hash.txt` was found
- `CA_BUNDLE` — the input is a trust bundle, not an end-entity chain
- `UNKNOWN_FAILURE` — an unclassified verification failure

Each result carries a **severity** (`NONE`/`HIGH`/`CRITICAL`/`UNKNOWN`), a human-readable reason,
the chain by subject DN, and the raw OpenSSL diagnostics behind the verdict.

**Scenario discovery.** The validator walks the given path, treating each directory that contains
certificate files as a scenario. It folds the multi-PEM `leaf/`, `intermediates/`, `root/` layout
back into a single scenario, and locates the nearest `root_hash.txt` by walking up the tree. Results
are grouped by their **detected** classification in both the console report and the JSON output —
directory names contribute only a variant label such as `INT1`, never the family itself, so a folder
named `expired_intermediate` appears under that heading only if the analysis independently reaches
that conclusion.

**Debug output** for any command: set `DEBUG_CERT_CHAIN=1` to print every OpenSSL command being run.
It goes to stderr, so `--json-only` output stays valid JSON.

---

## Understanding the results

The validator reports a classification rather than a bare pass or fail, because "invalid" is not
actionable and "expired intermediate at position 2, HIGH" is.

The JSON report is what makes a run filable as evidence. Its shape is:

```json
{
  "generated_at": "<ISO-8601 timestamp>",
  "scan_root": "<absolute path>",
  "summary": { "<CLASSIFICATION>": 3 },
  "families": [
    {
      "family": "ROOT_HASH_MISMATCH",
      "variants": ["DEFAULT"],
      "summary": { "ROOT_HASH_MISMATCH": 1 },
      "results": [
        {
          "variant": "DEFAULT",
          "valid": false,
          "classification": "ROOT_HASH_MISMATCH",
          "severity": "CRITICAL",
          "reason": "Root hash mismatch — expected 3ddae1c249011789…, got ebd352507a6a073c…",
          "diagnostics": "/tmp/cracy_verify_x1y2/leaf.pem: OK",
          "chain": ["CN=example.com", "CN=Intermediate-2", "CN=Intermediate-1", "CN=RootCA"]
        }
      ]
    }
  ]
}
```

The per-family summaries reconcile with their own results, and the top-level summary with all of
them, so a report cannot disagree with itself. `diagnostics` holds the raw OpenSSL output verbatim —
it is what lets somebody else check the verdict rather than take it on trust.

> **Note:** results reflect the material supplied, not the behaviour of any particular product. The
> validator establishes what a correct verdict is; comparing a product's actual verdict against it
> is the assessment. See the [ER and measure mapping](docs/CRACY_Certificate_Validator_ER_mapping.md)
> for the CRA essential requirements these results support.

---

## Project layout

```
cracy_certval/           the toolkit package
├── openssl.py           the one place this toolkit talks to OpenSSL
├── certs.py             inspection of a single certificate (fingerprint, DNs, CA, expiry)
├── chains.py            path building from unordered material, and verification
├── pinning.py           the trust-anchor pin
├── loading.py           PEM/DER/PKCS#7/PKCS#12 input, and corruption triage
├── findings.py          Finding, Severity, Classification — what a result looks like
├── generate.py          build a known-good chain          (cracy-cert-generate)
├── scenarios.py         the eight corruption scenarios
├── invalidate.py        corrupt a valid chain             (cracy-cert-invalidate)
├── analysis.py          classification and the two-stage analysis engine
├── reporting.py         console report and JSON report
└── validate.py          analyse and classify chains       (cracy-cert-validate)
tests/                   pytest suite
docs/                    user guide, CRA ER and CRACY REPO measure mapping
.github/workflows/       CI: runs the test suite on push and pull request
```

The three commands are thin: each one resolves its inputs, then calls the shared core. Analysis runs
in two deliberately separate stages — structural integrity first, then trust anchoring — because
only that separation can express a chain that verifies perfectly and is still not to be trusted.

## Running the tests

With the virtual environment activated:

```
pip install -r requirements-dev.txt
python -m pytest
```

The suite generates real certificate material with OpenSSL and runs the whole pipeline end to end,
including a check that every corruption scenario is classified as intended — the contract between
the invalidator and the reference validator. It also runs each command as a subprocess with stdin
closed, so a stray prompt fails the suite instead of hanging it. Everything is written to temporary
directories; nothing is left in the working tree.

## Updating to the latest version

Inside the project folder:

```
git pull
pip install .
```

## Licence

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) for the full text.
[NOTICE](NOTICE) records the attribution requirements; this repository redistributes no third-party
code or data, and invokes OpenSSL as an external command rather than bundling it.

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue,
please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.
