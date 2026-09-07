# Contributing

Thanks for considering a contribution. This toolkit tells manufacturers whether their products
correctly reject broken certificate chains, so a correction to a classification is as valuable as a
code change — and a wrong verdict is the most damaging defect it can have.

## Getting set up

```
git clone https://github.com/CRA-tools/CRACY-Certificate-Validator.git
cd CRACY-Certificate-Validator
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e .
python -m pytest
```

Python 3.9 or later and OpenSSL 3.0 or later are required. There are no third-party runtime
dependencies, and adding one needs a good reason: the toolkit is meant to run on an air-gapped
machine with nothing but Python and OpenSSL.

## Where things live

| To change | Edit |
|---|---|
| A corruption scenario, or add one | `cracy_certval/scenarios.py` |
| How a failure is classified, or its severity | `cracy_certval/analysis.py` |
| The classification taxonomy or severity levels | `cracy_certval/findings.py` |
| How chains are rebuilt from unordered material | `cracy_certval/chains.py` |
| What a certificate property means | `cracy_certval/certs.py` |
| The trust-anchor pin | `cracy_certval/pinning.py` |
| Accepting a new input container format | `cracy_certval/loading.py` |
| The console or JSON report | `cracy_certval/reporting.py` |
| A command's options or prompts | `generate.py`, `invalidate.py`, `validate.py` |

`tests/test_analysis.py` holds the mapping from each corruption scenario to the classification it is
expected to produce. That mapping is the contract between the two halves of the toolkit: it is what
lets a product's own verdict be compared against a known-good reference, so a change that breaks it
is a change to the contract and needs saying so explicitly.

## Adding a corruption scenario

A new scenario needs four things:

1. An entry in `SCENARIOS` in `cracy_certval/scenarios.py`, and a branch in `apply_scenario`.
2. A line in `SCENARIO_MENU` and in the `-h` epilog in `cracy_certval/invalidate.py`.
3. An entry in `EXPECTED` in `tests/test_analysis.py`, naming the classification the reference
   validator should reach.
4. A row in the scenario table in `README.md`.

Keep it to **one** defect. The value of a scenario is that a failure it provokes is attributable to
a single check; a chain with two problems tests nothing in particular. If the scenario needs a
private key to re-sign, say so in the table and let it be skipped when the key is absent, rather
than failing the run.

## Changing a classification

A classification is a claim about what correct behaviour is, so a change to one should say which
part of the certificate path validation rules supports it, and what a product doing the right thing
would do. Severity matters too: `CRITICAL` is reserved for failures that defeat trust itself — a
corrupted or forged certificate, an expired trust anchor, or a chain that verifies perfectly but
anchors to the wrong root.

Where a property can be read off the certificate, read it rather than matching on OpenSSL's message.
OpenSSL words an expired intermediate and a missing one similarly, which is why classification
examines certificates before it consults diagnostics.

## Pull requests

- Add or update tests for what you change. The suite runs in about ten seconds.
- Run `python -m pytest` before opening the PR; CI runs it on Python 3.9, 3.11 and 3.13.
- Never commit certificate or key material, or a generated report. `.gitignore` covers the usual
  extensions, but check `git status` before committing — a private key generated for testing is
  still a private key once it is in the history.
- Keep the diff focused, and match the surrounding style.
- Describe the user-visible effect: what someone running the toolkit would now see.

## Reporting problems

Bugs and suggestions: open an issue. Security problems: see [SECURITY.md](SECURITY.md) — please do
not open a public issue for those.

## Licence

Contributions are accepted under the Apache License 2.0, the licence of this project.
