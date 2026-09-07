# Certificate Validation Tool — CRA Essential Requirements Mapping

**Source of requirements:** CRACY D2.1 *Essential Requirements Translation* (Annex I / II / VII of the
Cyber Resilience Act, Regulation (EU) 2024/2847).
**Requirement families:** `ER` = essential requirements for PDEs (Part I, Annex I) · `VH` = vulnerability
handling (Part II, Annex I) · `DR` = documentary requirements (Annexes II & VII).

---

## 1. What the tool does

A three-command toolkit (driven entirely through the system `openssl` binary) for **testing how a PDE's
certificate-validation / trust logic behaves against broken, expired, misconfigured or tampered PKI chains**:

- **`cracy-cert-generate`** — builds a known-good chain (self-signed root CA, N intermediates, leaf),
  RSA 4096 (root) / 2048 (intermediates + leaf), SHA-256, with a pinned trust anchor
  `root_hash.txt = SHA256(DER(root_cert))`.
- **`cracy-cert-invalidate`** — produces isolated **single-fault** broken chains (expired leaf /
  intermediate / root, corrupted leaf, non-CA intermediate, missing intermediate, root-hash mismatch,
  root-hash not checked).
- **`cracy-cert-validate`** — discovers chains, verifies each with `openssl verify -x509_strict`,
  checks the root against the pinned hash, **classifies every failure with a severity**
  (`NONE`/`HIGH`/`CRITICAL`), and emits a structured **JSON report** (classification, severity, reason,
  raw diagnostics, chain by subject DN).

**Security properties it validates:** chain construction to a trust anchor · cryptographic signature
verification · certificate expiry (leaf, intermediate, root, checked independently) · CA basic-constraints
(`CA:TRUE`) · chain completeness · corrupted/tampered-DER detection · **trust-anchor pinning** (rejects a
chain that verifies against an unexpected root).

The tool is therefore a **security-testing and test-evidence generator** for the certificate / trust
component of a PDE — the mechanism that underpins TLS server/mutual authentication, signed firmware and
update verification, and device identity.

---

## 2. Coverage at a glance

| Requirement | Title | Coverage |
|-------------|-------|----------|
| **ER13** | Integrity (verify integrity/authenticity, detect tampering, report corruption) | **Full** (cert/trust mechanism) |
| **VH5** | Regular testing of security properties | **Full** (cert/trust mechanism) |
| **VH11** | Secure distribution of updates (verify integrity & authenticity; verify abuse) | **Partial** |
| **ER2** | No known exploitable vulnerabilities (test security properties, document results) | **Partial** |
| **ER10** | Access control (cryptographic authentication) | **Supporting** |
| **ER12** | Confidentiality (reviewed/evaluated crypto for network & security functions) | **Supporting** |
| **ER25** | Secure transfer of data | **Supporting** |
| **DR5** | Document performed tests | **Supporting** |

Legend — **Full**: the tool directly and substantially satisfies/verifies the requirement (within the
certificate/trust scope). **Partial**: it addresses part of the requirement. **Supporting**: it produces
evidence or exercises a mechanism that contributes to the requirement.

---

## 3. Requirement-by-requirement

### ER13 — Integrity  *(Part I, (2)(f) Annex I)* — **Full (cert/trust scope)**
> *Protect the integrity of stored, transmitted or processed data, commands, programs, configurations
> against manipulation not authorised by the user; verify its own integrity; if cryptography is used to
> ensure integrity, use best practices; report on corruptions (ER14).*

This is the tool's core alignment. Certificate-chain verification **is** a cryptographic
integrity/authenticity mechanism, and the tool tests that it works:

- **Tamper detection** — the `corrupted_server` scenario mangles a certificate's DER body while keeping
  the PEM framing; the validator classifies it `CORRUPTED_CERTIFICATE` (CRITICAL). This verifies the PDE
  detects manipulation of a signed artefact.
- **Signature / authenticity verification** — `openssl verify -x509_strict` confirms each certificate is
  correctly signed by its issuer; failures surface as `INVALID_SIGNATURE` (CRITICAL).
- **Trust-anchor pinning** — the distinctive check: a chain that is cryptographically valid but roots to an
  unexpected CA is flagged `ROOT_HASH_MISMATCH` (CRITICAL). This directly exercises resistance to
  substitution/unauthorised-issuer attacks on integrity.
- **"Report on corruptions" (ER14)** — every failure is reported with a machine-readable classification,
  severity and diagnostics, satisfying the reporting facet.

### VH5 — Regular testing  *(Part II, (3) Annex I)* — **Full (cert/trust scope)**
> *Draft and implement a process to test whether the security properties of the PDE are implemented
> correctly; test regularly; tests must cover the assessment criteria of the PDE requirements.*

The toolkit is a **repeatable, automatable test harness** for one concrete security property:

- The generator + corruptor produce a **defined, reproducible set of negative test cases** (one defect
  each) plus a positive baseline — a documented test procedure.
- The validator runs the assessment and produces pass/fail-with-severity results; `--json-only` makes it
  pipeable into CI or a regression suite for *regular* re-testing.
- Each scenario is a named assessment criterion (expiry, CA constraint, completeness, corruption, trust
  pin) against which the PDE's validation logic is checked.

### VH11 — Secure distribution of updates  *(Part II, (7) Annex I)* — **Partial**
> *Implement a mechanism for the secure installation of updates, including verifying the integrity and
> authenticity of the update package; verify whether the update mechanism can be abused.*

Signed-update verification almost always relies on a certificate/trust chain. The tool exercises exactly
that verification path:

- It confirms the verifier **rejects tampered, expired, non-CA, incomplete or wrongly-rooted material** —
  i.e. that integrity and authenticity of a signed package would be enforced.
- The `root_hash_mismatch` / `root_hash_not_checked` scenarios test **abuse resistance** — whether a valid
  chain rooted to the wrong (attacker) anchor, or an unpinned chain, would slip through.

Partial because the tool tests the *verification logic*; it does not itself distribute updates or verify the
transport/rollout mechanism.

### ER2 — No known exploitable vulnerabilities  *(Part I, (2)(a) Annex I)* — **Partial**
> *Make the PDE available without known exploitable vulnerabilities; test that security properties work
> correctly; document the results of the test.*

The tool **tests that a security property (certificate/trust validation) works correctly and documents the
result** (the JSON report). By proving the PDE correctly rejects broken chains before release, it helps
demonstrate the absence of a class of exploitable trust-validation flaws (e.g. accepting expired or
unauthorised certificates). Partial — it addresses one property, not the PDE's full vulnerability posture.

### ER10 — Access control  *(Part I, (2)(d) Annex I)* — **Supporting**
> *Protect from unauthorised access by appropriate control mechanisms; implement best-practice cryptography
> to authenticate users; do not send authentication data in clear text.*

Certificate-based authentication (mutual TLS, device/server identity) is a cryptographic access-control
mechanism. The tool verifies the trust-chain component of that mechanism — correct chaining to a trusted,
pinned anchor and valid leaf usage (`extendedKeyUsage=serverAuth`). Supporting rather than full: it does not
assess passwords, brute-force protection, or clear-text transmission.

### ER12 — Confidentiality  *(Part I, (2)(e) Annex I)* — **Supporting**
> *Protect the confidentiality of stored/transmitted data (e.g. encryption); implement reviewed or evaluated
> implementations to deliver network and security functionalities.*

Confidential channels (TLS) depend on a correctly validated certificate chain and trust anchor. The tool
verifies that trust component behaves correctly, contributing to the "reviewed/evaluated network and security
functionality" facet. It does not test encryption at rest or in transit directly.

### ER25 — Secure transfer of data  *(Part I, (2)(m) Annex I)* — **Supporting**
> *Where data can be transferred to other products/systems, ensure it is done securely (subject to ER12,
> ER13, ER14).*

Secure transfer relies on authenticated, integrity-protected channels; validating the certificate/trust
chain that authenticates the peer is a prerequisite the tool exercises.

### DR5 — Document performed tests  *(Annex VII, point 7)* — **Supporting**
> *Document the results, methods and decisions following from tests performed.*

The JSON report (`generated_at`, scan root, per-chain classification, severity, reason, raw OpenSSL
diagnostics, chain by subject DN, grouped summaries) is **directly usable as documented test evidence** for
the technical documentation.

---

## 4. Gaps / not covered (flag against the CRA)

Honest limits to record when using this tool as compliance evidence:

- **No revocation checking** — no CRL, OCSP or OCSP-stapling. A revoked-but-unexpired certificate would pass.
  Relevant to ER10/ER12/ER13 best-practice trust validation.
- **No hostname / SAN matching** — the leaf is not checked against an expected identity, so it does not
  fully verify server-identity binding.
- **No key-strength or signature-algorithm-strength policy** — key sizes and SHA-256 are fixed at
  *generation* but the validator does not independently reject weak keys (e.g. RSA-1024) or weak hashes
  (e.g. SHA-1); it trusts OpenSSL `-x509_strict` defaults. Relevant to the "best-practice cryptography"
  facets of ER12/ER13.
- **Scope is the certificate/trust mechanism only** — it does not test the PDE's wider integrity,
  confidentiality or access-control implementation.

These gaps mean the tool provides **strong, specific evidence for the certificate/trust portion** of ER13,
VH5 and VH11, and should be combined with other tooling (e.g. the CRACY cryptography assessment and the port
scanner) for broader coverage.

---

## 5. CRACY REPO measure mapping

Beyond the CRA essential requirements above, this tool's results contribute to
the following measures in the CRACY REPO's PDE compliance rating.

| Measure | Question | Default score | Justification |
| --- | --- | --- | --- |
| 1. USUA | Q2: Artifact signing + verification | 4 | The tool verifies that the certificate validation logic is implemented correctly. |
| 12. DISB | Q2: Secure/verified boot | 3 | Verification of the certificate validation logic contributes to the verification of the secure boot process which typically relies on such logic. |
| 15. CARC | Q2: Standards strategy and mapping | 4 | The suite's four steps and eight invalidation scenarios are explicitly mapped to CRA essential requirements (ER2, ER10, ER12, ER13, VH11). |
