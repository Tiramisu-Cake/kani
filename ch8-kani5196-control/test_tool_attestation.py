# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import tool_attestation as att


class ToolAttestationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tool = self.root / "tool"
        self.tool.mkdir()
        for rel in att.PIN_FILES:
            path = self.tool / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        (self.tool / "kani-dependencies").write_text(
            'CBMC_MAJOR="6"\nCBMC_MINOR="11"\nCBMC_VERSION="6.11.0"\nKISSAT_VERSION="4.0.1"\n',
            encoding="utf-8",
        )
        (self.tool / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "nightly-2026-11-19"\n', encoding="utf-8"
        )
        (self.tool / "scripts").mkdir()
        (self.tool / "target/kani/bin").mkdir(parents=True)
        self.paths = {
            "rustc": self.root / "rustc",
            "kissat": self.root / "kissat",
            "launcher": self.tool / "scripts/kani",
            "driver": self.tool / "target/kani/bin/kani-driver",
            "compiler": self.tool / "target/kani/bin/kani-compiler",
            "cbmc": self.root / "cbmc",
            "goto-instrument": self.root / "goto-instrument",
        }
        for path in self.paths.values():
            path.write_bytes(("executable:" + path.name).encode())
            path.chmod(0o755)

    def patches(self, *, cbmc_version="6.11.0 (cbmc-6.11.0)"):
        def run(argv, deadline, **kwargs):
            if argv[:3] == ["rustup", "which", "rustc"]:
                return str(self.paths["rustc"])
            if argv[0] == str(self.paths["rustc"]):
                return "rustc 1.95.0-nightly (abc123 2026-11-19)\nhost: x86_64-unknown-linux-gnu"
            if argv[0] == str(self.paths["kissat"]):
                return "4.0.1"
            if argv[0] == str(self.paths["launcher"]):
                return "using rustc 1.95.0-nightly (abc123 2026-11-19)"
            if argv[0] == str(self.paths["cbmc"]):
                return cbmc_version
            if argv[0] == str(self.paths["goto-instrument"]):
                return "6.11.0 (goto-instrument-6.11.0)"
            raise AssertionError(f"unexpected command: {argv}")

        def git(tool, *args, deadline):
            if args == ("rev-parse", "HEAD"):
                return att.TOOL_SHA
            if args == ("rev-parse", "HEAD^{tree}"):
                return att.TOOL_TREE
            if args == ("status", "--porcelain", "--untracked-files=no"):
                return ""
            raise AssertionError(args)

        def which(name):
            if name == "kissat":
                return str(self.paths["kissat"])
            if name == "cbmc":
                return str(self.paths["cbmc"])
            if name == "goto-instrument":
                return str(self.paths["goto-instrument"])
            return None

        return (
            mock.patch.object(att, "_run", side_effect=run),
            mock.patch.object(att, "_git", side_effect=git),
            mock.patch.object(att.shutil, "which", side_effect=which),
        )

    def test_attests_tool_files_and_runtime_resolution(self):
        p1, p2, p3 = self.patches()
        with p1, p2, p3:
            receipt = att.attest(self.tool, time.monotonic() + 5)
        self.assertEqual(receipt["status"], "COMPLETE")
        self.assertEqual(set(receipt["pins"]), set(att.PIN_FILES))
        self.assertEqual(receipt["binaries"]["kani_driver"]["path"], str(self.paths["driver"]))
        self.assertEqual(receipt["binaries"]["kani_compiler"]["path"], str(self.paths["compiler"]))
        self.assertEqual(receipt["lookup_contract"]["cbmc"], "PATH lookup: cbmc")
        self.assertEqual(receipt["lookup_contract"]["cbmc_pinned_version"], "6.11.0")

    def test_rejects_cbmc_version_drift(self):
        p1, p2, p3 = self.patches(cbmc_version="6.10.0 (cbmc-6.10.0)")
        with p1, p2, p3, self.assertRaisesRegex(att.AttestationError, "CBMC version mismatch"):
            att.attest(self.tool, time.monotonic() + 5)

    def test_deadline_is_enforced_before_attestation(self):
        with self.assertRaisesRegex(att.AttestationError, "deadline exhausted"):
            att.attest(self.tool, time.monotonic() - 1)


if __name__ == "__main__":
    unittest.main()
