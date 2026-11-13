"""Synthetic observation protocol only: no shell, compiler or proof process."""
import unittest
from unittest.mock import patch

from receipt import MARK, REQUIRED_FILES, REQUIRED_TREES, STAGES, identify, summarize, validate_binding


SOURCE = "/checkout/scripts/kani-regression.sh"


def event(command="echo done", rc=0, suite="", kind="DEBUG", source=SOURCE):
    return MARK + b"\0".join(str(x).encode() for x in (kind, rc, source, 1, command, suite, "kani")) + b"\0"


def command(stage):
    if stage.startswith("unit:"):
        return "cargo test -p " + stage.split(":")[1]
    if stage.startswith("suite:"):
        return "cargo run -p compiletest --quiet -- --suite $suite --mode $mode"
    return {"cbmc": "check-cbmc-version.py --major ${CBMC_MAJOR}", "kissat": "check_kissat_version.sh", "fmt": '${SCRIPT_DIR}/kani-fmt.sh --check', "build-dev": "cargo build-dev", "compiletest-config": "cargo run -p compiletest -- --dry-run", "build-cov": "cargo build -p kani-cov", "firecracker-codegen": '"$SCRIPT_DIR"/codegen-firecracker.sh', "cargo-smoke": 'cargo kani --manifest-path "$FEATURES_MANIFEST_PATH" --harness trivial_success', "cargo-clean": 'cargo clean --manifest-path "$FEATURES_MANIFEST_PATH"', "warnings-build": 'RUSTFLAGS="-D warnings" cargo build --features cprover'}[stage]


def successful():
    data = b""
    for stage in STAGES:
        data += event(command(stage), suite=stage.split(":")[-1] if stage.startswith("suite:") else "")
        data += b"test result: ok. 2 passed; 0 failed; 0 ignored\n"
    return data + event(kind="EXIT")


class ReceiptTests(unittest.TestCase):
    def test_success_complete_order_counts(self):
        result = summarize(successful(), 0)
        self.assertEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")
        self.assertEqual(list(result["stages"]), STAGES)
        self.assertEqual(result["formal_proof_credit"], "NOT_ESTABLISHED")

    def test_relative_source_from_exact_invocation(self):
        result = summarize(successful().replace(SOURCE.encode(), b"scripts/kani-regression.sh"), 0)
        self.assertEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")

    def test_error_original_exit_and_not_run(self):
        data = event("cargo build-dev") + b"error: network\n" + event(rc=37, kind="EXIT")
        result = summarize(data, 37)
        self.assertEqual(result["script_exit"], 37)
        self.assertEqual(result["stages"]["build-dev"]["exit"], 37)
        self.assertEqual(result["stages"]["suite:kani"]["status"], "NOT_RUN")

    def test_timeout_and_signal_not_success(self):
        for rc, termination in ((-15, {"kind": "TimeoutExpired"}), (-9, {"kind": "SIGKILL"})):
            result = summarize(event("cargo build-dev"), rc, termination)
            self.assertEqual(result["stages"]["build-dev"]["status"], "INCOMPLETE")
            self.assertEqual(result["termination"], termination)
            self.assertEqual(result["script_exit"], rc)

    def test_partial_missing_null_wrong_type_not_success(self):
        for data in (b"", b"null", b"[]", MARK + b"DEBUG\0", event("cargo build-dev", rc="null")):
            self.assertEqual(summarize(data, 0)["status"], "INCOMPLETE_OR_FAILED")

    def test_counts_missing_and_failed_rejected(self):
        for replacement in (b"no counts", b"test result: FAILED. 1 passed; 1 failed"):
            result = summarize(successful().replace(b"test result: ok. 2 passed; 0 failed; 0 ignored", replacement), 0)
            self.assertEqual(result["status"], "INCOMPLETE_OR_FAILED")

    def test_source_mismatch_and_duplicate_rejected(self):
        self.assertNotEqual(summarize(successful().replace(SOURCE.encode(), b"/wrong/script"), 0)["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")
        self.assertTrue(summarize(event("cargo build-dev") + successful(), 0)["problems"])

    def test_no_false_attribution_of_child_script(self):
        data = event("cargo build-dev") + event("cargo test -p kani", source="/child/script") + event(rc=8, kind="EXIT")
        result = summarize(data, 8)
        self.assertEqual(result["stages"]["build-dev"]["exit"], 8)
        self.assertEqual(result["stages"]["unit:kani"]["status"], "NOT_RUN")

    def test_stage_classifier(self):
        for stage in STAGES:
            self.assertEqual(identify(command(stage), stage.split(":")[-1]), stage)

    def test_binding_missing_null_wrong_type_not_run(self):
        for value in (None, [], {}, {"schema": "kani3300-gate-binding-v1", "state": "NOT_RUN_C1_PENDING"}):
            with self.assertRaises(ValueError):
                validate_binding(value, source=False)

    def test_binding_rejects_incomplete_and_bad_identities(self):
        binding = {"schema": "kani3300-gate-binding-v1", "state": "C1_FROZEN", "m3_accepted": True, "export_sha": "a" * 40, "export_tree": "b" * 40, "files": {p: "c" * 64 for p in REQUIRED_FILES}, "subtrees": {p: "d" * 40 for p in REQUIRED_TREES}}
        validate_binding(binding, source=False)
        for change in ({"files": {}}, {"subtrees": None}, {"export_sha": "z" * 40}):
            with self.assertRaises(ValueError):
                validate_binding(dict(binding, **change), source=False)
        with patch("receipt.git", return_value="f" * 40):
            with self.assertRaisesRegex(ValueError, "source-stage-target mismatch"):
                validate_binding(binding)


if __name__ == "__main__":
    unittest.main()
