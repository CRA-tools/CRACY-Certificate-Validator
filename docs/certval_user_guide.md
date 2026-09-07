# CRACY Certificate Validator

*Prove your device correctly rejects broken certificate chains*

## Purpose

A product's ability to correctly validate X.509 certificate chains is a core part of demonstrating CRA conformance: a device that accepts a badly-formed, expired, or untrusted certificate chain silently undermines every security control layered on top of it. Current certificate and TLS validation tools leave SMEs poorly served: live endpoint checkers verify only what a socket happens to serve at that moment, not the certificate bundles exchanged during integration, audit, or firmware signing, while command-line primitives such as a bare OpenSSL invocation validate offline material but stop at the first error, emit cryptic diagnostics, trust whatever authorities happen to be in the system store, and produce nothing an auditor can file as evidence.

Because the toolkit's entire function is to test certificate-chain and trust-anchor validation, its strongest and most direct alignment is with the integrity and testing requirements, with further supporting evidence for confidentiality, access control and secure data transfer.

The CRACY Certificate Validation Assessment Toolkit is a harness for assessing whether a third-party certificate-validation implementation correctly rejects malformed or untrustworthy certificate chains. Its central component generates deliberately invalidated chains, each carrying exactly one defect drawn from a taxonomy of commonly overlooked validation failures: an expired leaf, intermediate, or root; a corrupted certificate; an intermediate lacking CA constraints; an incomplete chain with a missing intermediate; and trust-anchor pinning faults, such as a mismatched or unchecked root fingerprint. Isolating a single defect per chain means each test exercises one specific check in the system under test, making any gap in the target's validation logic directly attributable. The generator accepts chains in a range of standard formats (PEM, DER, PKCS#7, and PKCS#12) and supports both RSA and ECC keys, so it can operate on real-world certificate material rather than only purpose-built inputs.

The toolkit is completed by two supporting utilities. The first is a chain generator that produces clean, well-formed baseline chains of arbitrary depth, each with a pinned root fingerprint, to serve as raw material. The second is an independent, known-good reference validator that classifies each chain into the same defect taxonomy and assigns an associated severity. The reference validator establishes the expected verdict for every generated chain, so the third party's results can be compared against a trusted baseline and any disagreement flagged as a finding. Together the three components form a repeatable pipeline (generate, invalidate, adjudicate) in which the invalidated chains are the primary work product, and the generator and reference validator exist to create and independently verify them.

In practice, an assessment starts from a chain relevant to the PDE's own use case, for example the chain used to sign its firmware updates or to authenticate a TLS endpoint. That chain is first confirmed valid using the reference validator, then deliberately invalidated in one or more of the ways described above. Each resulting chain is then presented to the PDE's own certificate-validation logic exactly as the PDE would encounter it in normal operation, for instance during a firmware update or a TLS handshake, and a correctly implemented PDE must reject every one of them; acceptance of even a single invalidated chain is a finding. The suite is free and open-source (FOSS), and will be made available in the CRACY and CRA Cluster tools GitHub, available at https://github.com/CRA-tools.

### What is Certificate and PKI Trust Validation?

Every product with digital elements that authenticates a peer, establishes a TLS session, or verifies a signed firmware image relies on X.509 certificates. A certificate binds an identity (a subject) to a public key, and is itself signed by a certificate authority. Trust is established by building a chain from an end-entity (leaf) certificate, through one or more intermediate CAs, up to a self-signed root CA that the verifier has decided to trust in advance. Validating that chain means confirming that every certificate is well-formed, unexpired, correctly signed by its issuer, permitted to act in its role, and ultimately anchored to a root the verifier genuinely trusts.

The CRA makes the secure handling of such trust decisions compulsory for PDEs. A manufacturer must be able to show that its product accepts genuine chains and rejects defective or malicious ones. To be useful for CRA compliance, a certificate-validation assessment should be complete (checking structure, cryptography, validity and trust anchoring, not just one of these), precise (saying exactly why a chain failed and how serious that is), and defensible (producing evidence that can be shown to an auditor or a customer).

### Motivation of the Compliance Assessment Tool

Tools that manufacturers currently reach for to check certificates generally follow one of two approaches, and each falls short of the requirements above. Live TLS checkers, whether an online grader or a scripted probe against a running service, validate whatever a socket happens to serve at that moment and cannot validate the PEM bundles, PKCS#7 packages and PKCS#12 containers exchanged between teams or embedded in firmware before anything is served over a network. Command-line primitives such as a bare OpenSSL verify invocation validate offline files but were designed as building blocks, not compliance instruments: they stop at the first problem and print a single terse diagnostic, leaving the operator to guess whether the cause was a missing intermediate, a non-CA intermediate, an expired certificate, or an untrusted root, with no indication of severity.

A further problem is trust anchoring. Standard tooling trusts whatever authorities are installed in the operating system's certificate store, so a structurally perfect chain that terminates at the wrong, but publicly trusted, root will pass even though it is not the identity the product should accept, and there is no simple way to pin trust to one specific expected root. Compounding this, command-line output is unstructured text that cannot be filed as machine-readable evidence, diffed across builds, or attached to a compliance report without manual transcription, and there is no accessible, reproducible way to generate the specific defective chains needed to prove that a product's own validation code rejects them, so certificate handling testing tends to be ad hoc and rarely documented.

The CRACY Certificate Validator suite addresses these gaps around a central capability: generating, on demand, a battery of certificate chains that are valid in every respect except one deliberately introduced defect. These invalidated chains are the actual test material used to assess a PDE's own certificate-validation logic; the suite's other two components exist to support that core capability, confirming that the starting chain is genuinely valid before it is invalidated, and independently establishing what a correct verdict for each invalidated chain should be, so that the PDE's actual behaviour can be checked against that reference.

## How It Works

Under the hood, the reference validator orchestrates OpenSSL to perform the actual cryptographic verification, so its classifications rest on a mature, widely-trusted engine rather than bespoke logic. Around that core, it adds three capabilities that a bare OpenSSL invocation lacks: it reconstructs the chain from an unordered bundle automatically, it classifies any failure into a named category with a severity, and it verifies the root against a pinned SHA-256 fingerprint that is independent of the system trust store. This is what allows it to serve as a trustworthy source of the expected verdict for every chain the invalidator produces.

The suite operates as three cooperating programs, built around the invalidator. The valid-chain generator builds a complete, trusted reference PKI, a 4096-bit root CA, one or more intermediate CAs, and a leaf server certificate, and pins the root by writing its canonical SHA-256 (DER) fingerprint to a root_hash.txt file. The invalid-chain generator then derives isolated single-defect variants from that valid chain: an expired server, a corrupted server, an expired or non-CA intermediate, a missing intermediate, a root-hash mismatch, an unchecked root hash, or an expired root; it is these chains, not any output of the validator, that are presented to the PDE under test. The reference validator can then be run over the same material, loading any bundle, building every candidate path, running structural and cryptographic verification, and checking the pinned root hash, purely to confirm independently what the correct verdict for each chain should be.

Rather than trusting a chain merely because it verifies cryptographically, the suite treats two questions as separate for any chain a PDE might be given: is it structurally and cryptographically sound, and does it anchor to the one root actually trusted? A chain can pass the first and fail the second; a perfectly valid chain whose root fingerprint does not match the pinned value should still be rejected as a critical trust failure by a correctly implemented PDE, precisely the case the root_hash_mismatch scenario is designed to catch.

The tool needs no network connectivity and can run completely offline: every operation is carried out on local files, and no certificate or key material ever leaves the machine through the tool itself, making the suite safe to use on confidential material and inside air-gapped environments. This applies most directly to the reference validator, which performs no network connections and issues no certificates of its own; the bundled generators are the components that create certificate material, and they write it only to local files. In typical use, the operator then takes that output, most often the invalidated chains, and transfers or uploads it to the PDE under test to actually run the assessment; that transfer is a deliberate action taken by the operator, not something the tool performs or automates itself.

### Requirements

The suite requires OpenSSL 3.0 or later as the underlying cryptographic engine, available on the system PATH, since all certificate parsing, signature verification and DER hashing is delegated to it; and Python 3.9 or later to run all three programs, with no third-party Python packages required beyond the standard library. A writable working directory is also needed, since the valid-chain generator writes a root_hash.txt pin alongside the certificates it produces, and the invalid generator and validator read it back automatically to enforce trust anchoring.

The suite accepts certificate material in the standard forms OpenSSL can decode: the invalid-chain generator reads PEM, DER, PKCS#7 (.p7b/.p7c) and PKCS#12 (.p12/.pfx) containers, and handles RSA and ECC keys identically, while the validator scans files or whole directories for PEM certificate blocks, so it can be pointed at a single bundle, a multi-file layout, or an entire tree of scenarios in one run. The tool is currently supported on Linux only, and performs no network connections whatsoever.

### Installation

The CRACY Certificate Validator can be downloaded from its repository, which also contains a README with installation and usage instructions. The suite consists of three commands, cracy-cert-generate, cracy-cert-invalidate and cracy-cert-validate; after cloning or extracting the repository, confirming that python3 --version and openssl version both succeed is the only setup needed, since the toolkit has no third-party dependencies and needs no compilation step.

The CRACY Certificate Validator suite is operated entirely from the command line, and each of its three programs accepts its inputs as command-line options or interactive prompts, so a run can be scripted end to end or walked through step by step. The three steps below mirror the generate, invalidate, adjudicate workflow set out in the tool description above.

### Command Overview and Help

All three programs accept their inputs as command-line options as well as interactive prompts; a prompt fires only for an input that was not supplied on the command line, so a fully-specified invocation runs with no prompts at all, which suits scripted or CI use.

Running cracy-cert-validate with the -h (or --help) flag prints a summary of its options: an optional target argument giving the chain or scenario path to analyse (prompted for interactively if omitted), --json (or -j) to also write a JSON report alongside the console output, --json-out FILE to write the JSON report to a specific file, and --json-only to suppress the console output and emit only the JSON report so the result can be piped directly into another process.

cracy-cert-generate accepts -n (or --intermediates) for the number of intermediate CAs, and -f (or --format) for the output format, given as 1 or single for a single PEM bundle, or 2 or multi for separate files; either option can be left out and the tool will prompt for it.

cracy-cert-invalidate accepts one or more certificate paths as positional arguments, -s (or --scenarios) to select one or more corruption scenarios by comma-separated number or name, or all, and -p (or --positions) to select intermediate positions by comma-separated number, where an empty value means none; any of these can be omitted and supplied at a prompt instead. A --p12-password option is also available for unattended runs against a password-protected PKCS#12 file, though the CRACY_P12_PASSWORD environment variable is the preferred way to supply it, since a password given directly on the command line is visible in shell history and the process list.

```
usage: cracy-cert-generate [-h] [-n N] [-f FORMAT]
usage: cracy-cert-invalidate [-h] [-s LIST] [-p LIST]
                             [--p12-password PASSWORD]
                             [PATH ...]
usage: cracy-cert-validate [-h] [target] [--json] [--json-out FILE] [--json-only]
```

### Interpreting the Results

The validator reports a classification rather than a simple pass/fail flag. A chain that passes verification and matches its pinned root is STRUCTURALLY_VALID or VALID; a failing chain is classified into one of several named families, EXPIRED_LEAF, EXPIRED_INTERMEDIATE, EXPIRED_ROOT, NON_CA_INTERMEDIATE, MISSING_INTERMEDIATE, CORRUPTED_CERTIFICATE, INVALID_SIGNATURE, SELF_SIGNED, UNTRUSTED_ROOT, ROOT_HASH_MISMATCH, ROOT_HASH_NOT_CHECKED, or UNKNOWN_FAILURE, each carrying a severity of NONE, HIGH, CRITICAL, or UNKNOWN. ROOT_HASH_MISMATCH is always CRITICAL, since a chain that verifies cryptographically but anchors to the wrong root is the most dangerous failure mode the toolkit can detect. Every result also carries a human-readable reason, the certificate chain by subject DN, and the raw OpenSSL diagnostics behind the verdict, and results are grouped by classification family in both the console report and the JSON output.

### Log Output and Evidence

The generator and invalidator write their certificate material, keys, and a root_hash.txt pin to timestamped run directories, giving every generated chain and every corruption scenario a permanent, dated record. Adding --json to a validator invocation writes a structured report file alongside the console output, capturing the same classification, severity, reason and chain detail in a machine-readable form suitable for CRA Technical Documentation. Setting DEBUG_CERT_CHAIN=1 in the environment additionally prints every OpenSSL command the suite runs, for troubleshooting or independent verification of its checks.

### Example Output

Validating a chain with a mismatched root and requesting a JSON report produces a structured, citable finding:

```
$ cracy-cert-validate ./invalid_chain/root_hash_mismatch --json

{
  "valid": false,
  "classification": "ROOT_HASH_MISMATCH",
  "severity": "CRITICAL",
  "reason": "Root hash mismatch - expected 3ddae1c249011789...,
             got ebd352507a6a073c...",
  "diagnostics": "/tmp/tmpfxwd8vo5/leaf.pem: OK",
  "chain": ["CN=example.com", "CN=Intermediate-3", "CN=Intermediate-2",
            "CN=Intermediate-1", "CN=RootCA"]
}
// nested under a top-level summary and a families/variants structure
// that groups every result examined in the run
```

## CRA Requirements Addressed

This tool's results directly support demonstrating conformity with the following CRA essential requirements:

| Code | Requirement |
| --- | --- |
| ER13 | Integrity |
| VH5 | Regular testing |
| VH11 | Secure distribution of updates |
| ER2 | No known exploitable vulnerabilities |
| ER10 | Access control |
| ER12 | Confidentiality |
| ER25 | Secure transfer of data |
| DR5 | Document performed tests |

*The suite's four steps walk a chain from baseline to evidence: confirming a reference chain is genuinely valid, deriving the single-defect variants that matter for testing, checking each variant against the reference validator to establish the correct verdict, and recording that verdict as a citable JSON artefact. This gives the assessment its Full rating against ER13 and VH5 within a specific, well-defined mechanism: certificate-chain integrity and trust anchoring. Three points shape how that rating should be read. The toolkit checks the chain and the pinned root, not certificate lifecycle status: it performs no revocation checking (no CRL, OCSP or OCSP stapling), so a chain that is otherwise valid but has since been revoked would still pass. It checks trust anchoring and structure, not server identity: it does not compare the leaf against an expected hostname or SAN, so verifying that binding is a separate step outside this tool's scope. And it relies on OpenSSL's own strict-mode defaults for algorithm strength, trusting that engine's judgement rather than independently flagging weak keys or superseded hashes such as RSA-1024 or SHA-1. The Full rating is best understood, then, as full coverage of the certificate and trust mechanism specifically, the tool's actual subject matter, rather than a general statement about integrity or testing maturity beyond it.*

## CRACY REPO Measure Mapping

Beyond the CRA essential requirements above, this tool's results also contribute to the following measures in the CRACY REPO's PDE compliance rating:

| Measure | Question | Default score | Justification |
| --- | --- | --- | --- |
| 1. USUA | Q2: Artifact signing + verification | 4 | The tool verifies that the certificate validation logic is implemented correctly. |
| 12. DISB | Q2: Secure/verified boot | 3 | Verification of the certificate validation logic contributes to the verification of the secure boot process which typically relies on such logic. |
| 15. CARC | Q2: Standards strategy and mapping | 4 | The suite's four steps and eight invalidation scenarios are explicitly mapped to CRA essential requirements (ER2, ER10, ER12, ER13, VH11). |

---

**Part of the CRACY compliance assessment suite, free and open source, available in the CRACY and CRA Cluster tools GitHub.**
