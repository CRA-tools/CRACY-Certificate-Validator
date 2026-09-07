"""The command-line interfaces.

The contract these tests defend is that a fully specified invocation never
prompts: every subprocess here runs with stdin closed, so any prompt would
fail the test rather than hang it. That is what makes the toolkit usable from
CI.
"""

import json
import os
import subprocess
import sys

import pytest

from cracy_certval.pinning import PIN_FILENAME

MODULES = [
    "cracy_certval.generate",
    "cracy_certval.invalidate",
    "cracy_certval.validate",
]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_module(module, *args, cwd=None):
    """Run one CLI with stdin closed, so a prompt cannot go unnoticed."""
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)

    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.mark.parametrize("module", MODULES)
def test_help_is_available(module):
    result = run_module(module, "-h")

    assert result.returncode == 0
    assert "usage:" in result.stdout


@pytest.mark.parametrize("module", MODULES)
def test_a_missing_input_fails_instead_of_hanging(module):
    """With no arguments and no stdin there is nothing to prompt with."""
    result = run_module(module)

    assert result.returncode != 0


def test_generate_runs_unattended(tmp_path):
    result = run_module(
        "cracy_certval.generate", "-n", "1", "-f", "single", cwd=str(tmp_path)
    )

    assert result.returncode == 0, result.stderr

    runs = list(tmp_path.glob("valid_chain_*"))

    assert len(runs) == 1
    assert (runs[0] / "valid_chain.pem").is_file()
    assert (runs[0] / PIN_FILENAME).is_file()


def test_the_whole_pipeline_runs_unattended(tmp_path):
    """Generate, invalidate, validate — the workflow the tool exists for."""
    generated = run_module(
        "cracy_certval.generate", "-n", "2", "-f", "single", cwd=str(tmp_path)
    )

    assert generated.returncode == 0, generated.stderr

    chain = next(tmp_path.glob("valid_chain_*"))

    invalidated = run_module(
        "cracy_certval.invalidate", chain.name, "-s", "all", "-p", "1",
        cwd=str(tmp_path),
    )

    assert invalidated.returncode == 0, invalidated.stderr
    assert "Done — 8 chain(s) generated" in invalidated.stdout

    validated = run_module(
        "cracy_certval.validate", "invalid_chain", "--json-only",
        cwd=str(tmp_path),
    )

    assert validated.returncode == 0, validated.stderr

    report = json.loads(validated.stdout)

    assert report["summary"]

    # --json-only keeps stdout valid JSON; status lines go to stderr.
    assert not list(tmp_path.glob("*_cert_report_*.json"))


def test_validate_writes_a_report_beside_the_console_output(tmp_path,
                                                            invalid_chains):
    result = run_module(
        "cracy_certval.validate", invalid_chains, "--json", cwd=str(tmp_path)
    )

    assert result.returncode == 0, result.stderr
    assert "ATTACK FAMILY" in result.stdout

    reports = list(tmp_path.glob("*_cert_report_*.json"))

    assert len(reports) == 1

    with open(reports[0], encoding="utf-8") as handle:
        assert json.load(handle)["families"]


def test_validate_writes_a_named_report(tmp_path, invalid_chains):
    destination = tmp_path / "evidence.json"

    result = run_module(
        "cracy_certval.validate", invalid_chains,
        "--json-out", str(destination),
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(destination.read_text())["summary"]


def test_validate_rejects_a_path_that_does_not_exist(tmp_path):
    result = run_module(
        "cracy_certval.validate", str(tmp_path / "absent"),
    )

    assert result.returncode != 0
    assert "Path not found" in result.stderr


def test_invalidate_rejects_an_unknown_scenario_before_working(valid_chain):
    """A typo must fail immediately, not after the chain has been built."""
    result = run_module(
        "cracy_certval.invalidate", valid_chain, "-s", "nonsense",
    )

    assert result.returncode != 0
    assert "Invalid option(s): nonsense" in result.stderr
    assert "building chain" not in result.stdout


def test_invalidate_accepts_scenarios_by_name(tmp_path, valid_chain):
    result = run_module(
        "cracy_certval.invalidate", valid_chain,
        "-s", "corrupted_server,root_hash_mismatch",
        cwd=str(tmp_path),
    )

    assert result.returncode == 0, result.stderr

    export = tmp_path / "invalid_chain"

    assert (export / "corrupted_server" / "invalid_chain.pem").is_file()
    assert (export / "root_hash_mismatch" / PIN_FILENAME).is_file()


def test_debug_environment_variable_shows_the_openssl_commands(valid_chain):
    env_result = subprocess.run(
        [sys.executable, "-m", "cracy_certval.validate", valid_chain,
         "--json-only"],
        env=dict(os.environ, PYTHONPATH=REPO_ROOT, DEBUG_CERT_CHAIN="1"),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert env_result.returncode == 0
    assert "[DEBUG] RUN: openssl" in env_result.stderr

    # Debug output must not contaminate the JSON payload on stdout.
    assert json.loads(env_result.stdout)["summary"]
