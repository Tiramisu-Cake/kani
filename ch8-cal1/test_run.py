"""Offline request, runner and reporting tests with synthetic verifier children."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import report
import request as spec
import results
import run
import tool_attestation as tool


_FROZEN_ROWS = spec.load()["roster"]
ROOTS = {row["id"]: (row["selector"].rsplit("::", 1)[-1], row["expected_outcome"])
         for row in _FROZEN_ROWS}
COMPLETED = {"status": "COMPLETED", "stop_reason": "EXITED", "exit_code": 0, "reaped": True,
             "sampler_valid": True, "stdout_complete": True, "stderr_complete": True,
             "max_verifier_children": 0}

# Exact copy of the appended Wide N12/N14 module of Std 93d0c4a18d; the source gate reads the pinned blob in CI.
WIDE_N12_N14_MODULE_FIXTURE = (Path(__file__).resolve().parent / "wide_n12_n14_module.fixture").read_text(encoding="utf-8")
# Exact copy of the appended N32 pilot module of Std 88d05a138c; the source gate reads the pinned blob in CI.
N32_MODULE_FIXTURE = (Path(__file__).resolve().parent / "n32_pilot_module.fixture").read_text(encoding="utf-8")
N32_MODULE_LINE = 1943
# Exact copy of the appended N32 closure module of Std 650d8aa728; the source gate reads the pinned blob in CI.
N32_CLOSURE_MODULE_FIXTURE = (Path(__file__).resolve().parent / "n32_closure_module.fixture").read_text(encoding="utf-8")
N32_CLOSURE_MODULE_LINE = 2594

# Exact copy of the appended N10 module; the source gate reads the pinned blob in CI.
N10_MODULE_FIXTURE = (
    '#[cfg(kani_smallsort_rev2_gen_stable_n10_wide_witness)]\n'
    'mod n10_wide_witness {\n'
    '    use super::super::super::UnstableSmallSortTypeImpl;\n'
    '    use super::{Wide, kani, same_wide, wide_less};\n'
    '\n'
    '    const LEFT: Wide = Wide { key: 2, tag: 16, payload: 0x1111_2222_3333_4444 };\n'
    '    const RIGHT: Wide = Wide { key: 3, tag: 17, payload: 0xaaaa_bbbb_cccc_dddd };\n'
    '\n'
    '    const fn input_record(key: u64, tag: u64) -> Wide {\n'
    '        Wide { key, tag, payload: 0x8000_0000_0000_0100 + tag }\n'
    '    }\n'
    '\n'
    '    const INPUT: [Wide; 12] = [\n'
    '        LEFT,\n'
    '        input_record(1, 0),\n'
    '        input_record(0, 1),\n'
    '        input_record(1, 2),\n'
    '        input_record(0, 3),\n'
    '        input_record(0, 4),\n'
    '        input_record(1, 5),\n'
    '        input_record(0, 6),\n'
    '        input_record(1, 7),\n'
    '        input_record(0, 8),\n'
    '        input_record(0, 9),\n'
    '        RIGHT,\n'
    '    ];\n'
    '\n'
    '    // Indices in INPUT, including its left canary at index zero.\n'
    '    const EXPECTED: [Wide; 10] = [\n'
    '        INPUT[2], INPUT[4], INPUT[5], INPUT[7], INPUT[9], INPUT[10], INPUT[1], INPUT[3], INPUT[6],\n'
    '        INPUT[8],\n'
    '    ];\n'
    '\n'
    '    const CORRUPTED: [Wide; 10] = [\n'
    '        INPUT[2], INPUT[4], INPUT[7], INPUT[5], INPUT[9], INPUT[10], INPUT[1], INPUT[3], INPUT[6],\n'
    '        INPUT[8],\n'
    '    ];\n'
    '\n'
    '    fn observe(v: &[Wide; 12], expected: &[Wide; 10]) -> (bool, bool, bool) {\n'
    '        let mut exact = same_wide(v[1], expected[0]);\n'
    '        let mut ordered = true;\n'
    '        let mut stable = true;\n'
    '        for i in 1..10 {\n'
    '            let (a, b) = (v[i], v[i + 1]);\n'
    '            exact &= same_wide(b, expected[i]);\n'
    '            ordered &= a.key <= b.key;\n'
    '            stable &= a.key != b.key || a.tag < b.tag;\n'
    '        }\n'
    '        (ordered, exact, stable)\n'
    '    }\n'
    '\n'
    '    #[kani::proof]\n'
    '    #[kani::unwind(36)]\n'
    '    fn gen_n10_wide_witness_literal_corrupt() {\n'
    '        let mut v = INPUT;\n'
    '        let mut less = wide_less;\n'
    '        <Wide as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..11], &mut less);\n'
    '        kani::cover(true, "AFTER_WIDE_N10_RETURN");\n'
    '\n'
    '        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n'
    '        kani::assert(ordered, "GEN_N10_WIDE_BEFORE_ORDER");\n'
    '        kani::assert(exact, "GEN_N10_WIDE_BEFORE_RECORDS_BY_TAG");\n'
    '        kani::assert(stable, "GEN_N10_WIDE_BEFORE_STABLE_EQUAL_KEYS");\n'
    '        kani::assert(\n'
    '            v[3].key == 0 && v[4].key == 0 && v[3].tag == 4 && v[4].tag == 6,\n'
    '            "GEN_N10_WIDE_BEFORE_SWAP_PAIR",\n'
    '        );\n'
    '        kani::assert(same_wide(v[0], LEFT) && same_wide(v[11], RIGHT), "GEN_N10_WIDE_BEFORE_FRAME");\n'
    '        kani::cover(\n'
    '            v[3].key == v[4].key && v[3].tag < 5 && v[4].tag >= 5,\n'
    '            "GEN_N10_WIDE_WITNESS_CROSS_HALF_TIE",\n'
    '        );\n'
    '\n'
    '        let left = v[3];\n'
    '        v[3] = v[4];\n'
    '        v[4] = left;\n'
    '        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n'
    '        kani::assert(ordered, "GEN_N10_WIDE_AFTER_ORDER");\n'
    '        kani::assert(exact, "GEN_N10_WIDE_AFTER_RECORDS_BY_TAG");\n'
    '        kani::assert(same_wide(v[0], LEFT) && same_wide(v[11], RIGHT), "GEN_N10_WIDE_AFTER_FRAME");\n'
    '        kani::assert(stable, "GEN_N10_WIDE_STABLE_EQUAL_KEYS");\n'
    '    }\n'
    '}\n'
)

# Exact copy of the appended N12 module; the source gate reads the pinned blob in CI.
N12_MODULE_FIXTURE = (
    '#[cfg(kani_smallsort_rev2_gen_stable_n12_wide_witness)]\n'
    'mod n12_wide_witness {\n'
    '    use super::super::super::UnstableSmallSortTypeImpl;\n'
    '    use super::{Wide, kani, same_wide, wide_less};\n'
    '\n'
    '    const LEFT: Wide = Wide { key: 2, tag: 16, payload: 0x1111_2222_3333_4444 };\n'
    '    const RIGHT: Wide = Wide { key: 3, tag: 17, payload: 0xaaaa_bbbb_cccc_dddd };\n'
    '\n'
    '    const fn input_record(key: u64, tag: u64) -> Wide {\n'
    '        Wide { key, tag, payload: 0x8000_0000_0000_0100 + tag }\n'
    '    }\n'
    '\n'
    '    const INPUT: [Wide; 14] = [\n'
    '        LEFT,\n'
    '        input_record(1, 0),\n'
    '        input_record(0, 1),\n'
    '        input_record(1, 2),\n'
    '        input_record(0, 3),\n'
    '        input_record(0, 4),\n'
    '        input_record(0, 5),\n'
    '        input_record(1, 6),\n'
    '        input_record(0, 7),\n'
    '        input_record(1, 8),\n'
    '        input_record(0, 9),\n'
    '        input_record(0, 10),\n'
    '        input_record(0, 11),\n'
    '        RIGHT,\n'
    '    ];\n'
    '\n'
    '    // Indices in INPUT, including its left canary at index zero.\n'
    '    const EXPECTED: [Wide; 12] = [\n'
    '        INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[8], INPUT[10], INPUT[11], INPUT[12],\n'
    '        INPUT[1], INPUT[3], INPUT[7], INPUT[9],\n'
    '    ];\n'
    '\n'
    '    const CORRUPTED: [Wide; 12] = [\n'
    '        INPUT[2], INPUT[4], INPUT[5], INPUT[8], INPUT[6], INPUT[10], INPUT[11], INPUT[12],\n'
    '        INPUT[1], INPUT[3], INPUT[7], INPUT[9],\n'
    '    ];\n'
    '\n'
    '    fn observe(v: &[Wide; 14], expected: &[Wide; 12]) -> (bool, bool, bool) {\n'
    '        let mut exact = same_wide(v[1], expected[0]);\n'
    '        let mut ordered = true;\n'
    '        let mut stable = true;\n'
    '        for i in 1..12 {\n'
    '            let (a, b) = (v[i], v[i + 1]);\n'
    '            exact &= same_wide(b, expected[i]);\n'
    '            ordered &= a.key <= b.key;\n'
    '            stable &= a.key != b.key || a.tag < b.tag;\n'
    '        }\n'
    '        (ordered, exact, stable)\n'
    '    }\n'
    '\n'
    '    #[kani::proof]\n'
    '    #[kani::unwind(36)]\n'
    '    fn gen_n12_wide_witness_literal_corrupt() {\n'
    '        let mut v = INPUT;\n'
    '        let mut less = wide_less;\n'
    '        <Wide as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..13], &mut less);\n'
    '        kani::cover(true, "AFTER_WIDE_N12_RETURN");\n'
    '\n'
    '        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n'
    '        kani::assert(ordered, "GEN_N12_WIDE_BEFORE_ORDER");\n'
    '        kani::assert(exact, "GEN_N12_WIDE_BEFORE_RECORDS_BY_TAG");\n'
    '        kani::assert(stable, "GEN_N12_WIDE_BEFORE_STABLE_EQUAL_KEYS");\n'
    '        kani::assert(\n'
    '            v[4].key == 0 && v[5].key == 0 && v[4].tag == 5 && v[5].tag == 7,\n'
    '            "GEN_N12_WIDE_BEFORE_SWAP_PAIR",\n'
    '        );\n'
    '        kani::assert(same_wide(v[0], LEFT) && same_wide(v[13], RIGHT), "GEN_N12_WIDE_BEFORE_FRAME");\n'
    '        kani::cover(\n'
    '            v[4].key == v[5].key && v[4].tag < 6 && v[5].tag >= 6,\n'
    '            "GEN_N12_WIDE_WITNESS_CROSS_HALF_TIE",\n'
    '        );\n'
    '\n'
    '        let left = v[4];\n'
    '        v[4] = v[5];\n'
    '        v[5] = left;\n'
    '        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n'
    '        kani::assert(ordered, "GEN_N12_WIDE_AFTER_ORDER");\n'
    '        kani::assert(exact, "GEN_N12_WIDE_AFTER_RECORDS_BY_TAG");\n'
    '        kani::assert(same_wide(v[0], LEFT) && same_wide(v[13], RIGHT), "GEN_N12_WIDE_AFTER_FRAME");\n'
    '        kani::assert(stable, "GEN_N12_WIDE_STABLE_EQUAL_KEYS");\n'
    '    }\n'
    '}\n'
)


FAKE_REAL_CBMC = {"path": "/opt/cbmc/bin/cbmc", "sha256": "0" * 64, "bytes": 1, "identity": [1, 2, 1, 3]}


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.frozen = spec.load()
        self.slots = run.expected_slots(self.frozen)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.std = self.state / "std"
        self.tool = self.state / "tool"
        # Runner tests use an inert relay install; test_relay.py exercises the real relay.
        self.relay_installs = []
        self.enterContext(patch.object(run.stdout_relay, "resolve_real", return_value=FAKE_REAL_CBMC))
        self.enterContext(patch.object(run.stdout_relay, "install", side_effect=self.fake_relay_install))

    def fake_relay_install(self, directory, real, *, config):
        root = Path(directory) / "relay"
        for name in ("bin", "spill", "journal"):
            (root / name).mkdir(parents=True)
        self.relay_installs.append(Path(directory).name)
        return {"path_prefix": str(root / "bin"), "journal_dir": str(root / "journal"), "spill_dir": str(root / "spill"),
                "receipt": {"mode": config["mode"], "slot": config["slot"], "path_prefix": str(root / "bin"),
                            "real_cbmc": real}}

    def read_receipt(self, slot):
        return spec.read(self.state / "artifact" / "slots" / slot / "receipt.json")

    def synthetic_slots(self, count=2):
        base = self.frozen["roster"][0]
        slots = []
        for index in range(count):
            if index == count - 1:
                row = deepcopy(self.frozen["roster"][-1])
            else:
                row = deepcopy(base)
                row["id"] = f"SYNTHETIC-N12-WIDE-WITNESS-{index + 1}"
                row["selector"] = spec.N12_WITNESS_PREFIX + f"synthetic_{index + 1}"
            slots.append((row["id"], "singleton", [row], base["seconds"]))
        return slots

    def list_document(self, *, consumer_enabled=True):
        standard = "standard-harnesses"
        contract = "contract-harnesses"
        provider = "smallsort/verify/rev2_provider_cost.rs"
        binding = "smallsort/verify/rev2_s13_binding.rs"
        geometries = "smallsort/verify/rev2_s13_geometries.rs"
        document = {
            "file-version": "0.1",
            standard: {provider: [p for k, p in spec.PROVIDER_DISCOVERY if k == standard],
                       binding: [p for k, p in spec.BINDING_DISCOVERY if k == standard],
                       geometries: [p for k, p in spec.GEOMETRIES_DISCOVERY if k == standard],
                       "smallsort/verify/rev2_n32_consumer.rs": [p for k, p in spec.CONSUMER_DISCOVERY if k == standard],
                       "smallsort/verify/rev2_n18_n19_providers.rs": [p for k, p in spec.N18_N19_PROVIDERS_DISCOVERY if k == standard],
                       "smallsort/verify/rev2_n18_n19_consumer.rs": [p for k, p in spec.N18_N19_CONSUMER_DISCOVERY if k == standard],
                       "smallsort/verify/rev2_n22_n25_consumer.rs": [p for k, p in spec.N22_N25_CONSUMER_DISCOVERY if k == standard],
                       "smallsort/verify/cal1.rs": ["core::example::inherited_proof"]},
            contract: {provider: [p for k, p in spec.PROVIDER_DISCOVERY if k == contract],
                       geometries: [p for k, p in spec.GEOMETRIES_DISCOVERY if k == contract],
                       "smallsort/verify/rev2_n18_n19_providers.rs": [p for k, p in spec.N18_N19_PROVIDERS_DISCOVERY if k == contract]},
        }
        inherited_file = f"smallsort/verify/{spec.N20_N21_PROVIDERS_MODULE}.rs"
        for bucket in (standard, contract):
            document[bucket][inherited_file] = [
                selector for kind, selector in spec.N20_N21_PROVIDERS_DISCOVERY if kind == bucket
            ]
            document[bucket][spec.U64_N20_N21_FILE] = [
                row["selector"] for row in self.frozen["source_bindings"]["u64_n20_n21_roster"]
                if ("contract-harnesses" if row["check"] else "standard-harnesses") == bucket
            ]
            document[bucket][spec.U64_N18_N19_FILE] = [
                selector for kind, selector in spec.U64_N18_N19_HISTORICAL_DISCOVERY if kind == bucket
            ]
            document[bucket][spec.U64_N22_N25_PROVIDERS_FILE] = [
                row["selector"] for row in self.frozen["source_bindings"]["u64_n22_n25_roster"]
                if ("contract-harnesses" if row["check"] else "standard-harnesses") == bucket
            ]
            document[bucket][spec.U64_N26_N32_PROVIDERS_FILE] = [
                row["selector"] for row in self.frozen["source_bindings"]["u64_n26_n32_providers_roster"]
                if ("contract-harnesses" if row["check"] else "standard-harnesses") == bucket
            ]
        document[contract][f"smallsort/verify/{spec.MERGE_PAIR_FIXED_MODULE}.rs"] = [
            selector for _, selector in spec.MERGE_PAIR_FIXED_DISCOVERY
        ]
        document[standard][f"smallsort/verify/{spec.N20_N21_CONSUMER_MODULE}.rs"] = [
            selector for _, selector in spec.N20_N21_CONSUMER_DISCOVERY
        ]
        for bucket in (standard, contract):
            document[bucket][spec.N22_N25_PROVIDERS_FILE] = [
                selector for kind, selector in spec.N22_N25_PROVIDERS_DISCOVERY if kind == bucket
            ]
        for bucket in (standard, contract):
            document[bucket][spec.N26_N31_HALVES_FILE] = [
                selector for kind, selector in spec.N26_N31_HALVES_DISCOVERY if kind == bucket
            ]
        document[standard][spec.COPY_BACK_FILE] = [
            selector for kind, selector in spec.COPY_BACK_DISCOVERY if kind == standard
        ]
        targets = (spec.N22_N25_PROVIDER_CHECKS | spec.N26_N31_HALVES_CHECKS | spec.MERGE_CHECKS |
                   spec.U64_N22_N25_PROVIDER_CHECKS | spec.U64_N20_N21_CHECKS | spec.U64_N18_N19_CHECKS)
        document[contract][spec.MERGE_FILE] = list(spec.MERGE_CHECKS)
        document[standard][spec.HISTORICAL_CONSUMER_FILE] = [selector for _, selector in spec.HISTORICAL_CONSUMER_DISCOVERY]
        document[standard][spec.U64_N13_FILE] = [selector for _, selector in spec.U64_N13_DISCOVERY]
        document[standard][spec.U64_N14_N17_FILE] = [selector for _, selector in spec.U64_N14_N17_DISCOVERY]
        targets |= spec.PROVIDER_CHECKS
        document[standard][spec.U64_N26_N32_CONSUMER_FILE] = [
            row["selector"] for row in self.frozen["source_bindings"]["u64_n26_n32_consumer_roster"]]
        for kind, selector in spec.PILOT_DISCOVERY:
            bucket = standard if kind == "standard-harnesses" else contract
            document[bucket].setdefault(spec.PILOT_MODULE_FILE, []).append(selector)
        for kind, selector in spec.FIX1_DISCOVERY:
            document[kind].setdefault(spec.PILOT_MODULE_FILE, []).append(selector)
        for kind, selector in (spec.CLOSE_DISCOVERY + spec.WIDE_WITNESS_DISCOVERY + spec.N10_WITNESS_DISCOVERY
                               + spec.N12_WITNESS_DISCOVERY + spec.WIDE_N12_N14_DISCOVERY + spec.N32_DISCOVERY):
            document[kind].setdefault(spec.CLOSE_MODULE_FILE, []).append(selector)
        targets |= spec.PILOT_CHECKS | spec.FIX1_CHECKS | spec.WIDE_N12_N14_CHECKS | spec.N32_CHECKS
        if consumer_enabled:
            for kind, selector in spec.N32_CLOSURE_DISCOVERY:
                document[kind].setdefault(spec.CLOSE_MODULE_FILE, []).append(selector)
        document["contracts"] = [
            {"function": definition, "file": file, "harnesses": [selector]}
            for selector, (definition, file) in targets.items()
        ]
        document[standard]["smallsort/verify/rev2_n17.rs"] = [
            selector for kind, selector in spec.N17_DISCOVERY if kind == standard
        ]
        return document

    def test_frozen_slots_and_cold_argv(self):
        self.assertEqual([key for key, _, _, _ in self.slots], list(ROOTS))
        self.assertEqual(tuple(ROOTS), spec.SLOT_IDS)
        self.assertEqual(spec.SLOT_IDS, ("GEN-N32-U64-S8-L48-FULL", "GEN-N32-STABLE-U64-WITNESS-CORRUPT",
                                         "GEN-N32-WIDE-WITNESS-CORRUPT"))
        prefix = "slice::sort::shared::smallsort::verify::rev2_gen_stable_n16_pilot::n32_closure::"
        self.assertEqual(spec.N32_CLOSURE_PREFIX, prefix)
        self.assertEqual(spec.TYPE_SLOT_IDS, {"STABLE_U64": spec.SLOT_IDS[:2], "GENERAL_WIDE": spec.SLOT_IDS[2:]})
        rows = self.frozen["roster"]
        self.assertEqual([row["expected_outcome"] for row in rows], ["VERIFIED", "FAILED", "FAILED"])
        self.assertEqual([(row["expected_failure"] or {}).get("label") for row in rows],
                         [None, "GEN_N32_STABLE_U64_MULTIPLICITY", "GEN_N32_WIDE_STABLE_EQUAL_KEYS"])
        self.assertEqual([(row["expected_failure"] or {}).get("line") for row in rows], [None, 2724, 2829])
        # Coordinator decision 2026-11-28: only the Wide control runs behind the relay, with an explicit label.
        self.assertEqual([row["stdout_delivery"] for row in rows], ["STOCK_PIPE", "STOCK_PIPE", "STDOUT_RELAY"])
        self.assertEqual(self.frozen["stdout_relay"]["slot"], "GEN-N32-WIDE-WITNESS-CORRUPT")
        self.assertEqual(spec.RELAY_SLOT_ID, spec.N32_WIDE_WITNESS_SLOT_ID)
        self.assertEqual([row["check"] for row in rows], [None] * 3)
        for row, asserts, covers in zip(rows, (6, 9, 8), (4, 2, 3)):
            self.assertIsNone(row["check_evidence"])
            self.assertFalse(row["native_evidence"]["copy_back"])
            self.assertEqual(len(row["native_evidence"]["required_properties"]), 6)
            self.assertEqual((len(row["required_assertions"]), len(row["covers"])), (asserts, covers))
        self.assertEqual([prop["function"] for prop in rows[1]["native_evidence"]["required_properties"]],
                         ["ptr::copy_nonoverlapping::<u64>"] * 6)
        self.assertEqual({prop["function"] for prop in rows[2]["native_evidence"]["required_properties"]},
                         {f"ptr::copy_nonoverlapping::<{spec.PILOT_PREFIX}Wide>"})
        self.assertEqual(rows[0]["covers"][-1], spec.U64_COMPARATOR_LABEL)
        self.assertEqual(rows[1]["covers"], [spec.U64_COMPARATOR_LABEL, "AFTER_STABLE_N32_RETURN"])
        self.assertEqual(rows[2]["covers"], [spec.FIX1_WIDE_COMPARATOR_LABEL, "AFTER_WIDE_N32_RETURN",
                                             "GEN_N32_WIDE_WITNESS_CROSS_HALF_TIE"])
        # Reached sites only: S8 sort4 and merge; both controls add the fill copy, never a shift or gap guard.
        self.assertEqual([site["line"] for site in rows[0]["native_evidence"]["copy_sites"]],
                         [832, 833, 834, 835, 885, 918])
        for row in rows[1:]:
            self.assertEqual([(site["line"], site["column"]) for site in row["native_evidence"]["copy_sites"]],
                             [(832, 9), (833, 9), (834, 9), (835, 9), (329, 17), (885, 9), (918, 9)])
        self.assertEqual(len(spec.CFG), 35)
        self.assertEqual(spec.CFG[-1], spec.N32_CLOSURE_CFG)
        self.assertEqual(spec.N32_PILOT_ROW_CFG, spec.CFG[:34])
        self.assertTrue(all(row["cfg"] == spec.CFG for row in rows))
        self.assertEqual(self.frozen["source_bindings"]["n32_closure_roster"], rows)
        historical = self.frozen["source_bindings"]
        self.assertEqual(spec.roster_digest(historical["n32_pilot_roster"]), spec.N32_PILOT_ROSTER_DIGEST)
        self.assertTrue(all(row["cfg"] == spec.N32_PILOT_ROW_CFG for row in historical["n32_pilot_roster"]))
        self.assertEqual(spec.roster_digest(historical["wide_n12_n14_roster"]), spec.WIDE_N12_N14_ROSTER_DIGEST)
        self.assertEqual(spec.roster_digest(historical["n12_wide_witness_roster"] + historical["wide_witness_roster"]),
                         spec.N12_WIDE_WITNESS_N16_ROSTER_DIGEST)
        self.assertEqual(spec.roster_digest(historical["wide_witness_roster"]), spec.WIDE_WITNESS_ROSTER_DIGEST)
        self.assertEqual(spec.roster_digest(historical["n10_wide_witness_roster"]), spec.N10_WITNESS_ROSTER_DIGEST)
        self.assertEqual(len(historical["pilot_close_roster"]), 7)
        self.assertEqual(self.frozen["architecture"], "x86_64")
        self.assertEqual(self.frozen["cbmc_version"], "6.11.0")
        self.assertEqual(self.frozen["solver"], "cadical")
        inherited_env = {"RUSTFLAGS": "other", "CARGO_ENCODED_RUSTFLAGS": "other", "KANI_JOBS": "8", "KANI_FLAGS": "other"}
        paths = set()
        with patch.dict(os.environ, inherited_env):
            for key, mode, (row,), seconds in self.slots:
                self.assertEqual((row["selector"], row["replace"], row["expected_outcome"]),
                                 (prefix + ROOTS[key][0], [], ROOTS[key][1]))
                self.assertEqual(row["selector"], spec.N32_CLOSURE_SELECTORS[key])
                self.assertTrue(row["required_assertions"])
                self.assertTrue(row["native_evidence"]["coordinates"])
                self.assertTrue(row["geometry"])
                self.assertTrue(row["covers"])
                self.assertEqual((mode, seconds, row["cfg"], row["object_bits"], row["unwind"]),
                                 ("singleton", spec.slot_seconds(), spec.CFG, 12, 36))
                directory = self.state / key
                argv = run.verify_argv(self.std, self.tool, directory, row, self.frozen)
                self.assertEqual(argv[argv.index("--harness") + 1], row["selector"])
                self.assertTrue({"--exact", "--jobs=1", "--no-assert-contracts", "--output-format=regular"} <= set(argv))
                self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
                self.assertFalse({"uninit-checks", "validity-checks", "--no-default-checks", "--harness-timeout"}
                                 & set(argv))
                env = run.frozen_env(directory, row["cfg"], jobs=1)
                self.assertEqual(env["RUSTFLAGS"], " ".join(f"--cfg={flag}" for flag in spec.CFG))
                self.assertEqual(env["KANI_JOBS"], "1")
                self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
                self.assertNotIn("KANI_FLAGS", env)
                isolated = {argv[argv.index(flag) + 1] for flag in ("--target-dir", "--export-json")}
                isolated.update((env["TMPDIR"], env["CARGO_TARGET_DIR"]))
                self.assertTrue(isolated.isdisjoint(paths))
                paths.update(isolated)
        self.assertEqual(len(paths), 4 * len(self.slots))

    def test_n32_closure_argv_and_env_follow_the_stock_n32_pilot(self):
        """The stock argv of the plain right S8 of pilot run 46146034746 up to selector, slot path and the new cfg."""
        tool, std = Path("/home/runner/work/kani/kani/tool"), Path("/home/runner/work/kani/kani/std")
        old = Path("/home/runner/work/_temp/ch8-rev2-gen-stable-n32-pilot/work")
        new = Path("/home/runner/work/_temp/ch8-rev2-gen-stable-n32-closure/work")
        s8_selector = spec.N32_PREFIX + "gen_n32_u64_s8_r48_full"
        s8_slot = "GEN-N32-U64-S8-R48-FULL"
        s8_argv = [str(tool / "scripts/kani"), "verify-std", "-Z", "unstable-options", "-Z", "function-contracts",
                   "-Z", "mem-predicates", "-Z", "float-lib", "-Z", "c-ffi", "-Z", "loop-contracts",
                   "-Z", "quantifiers", "-Z", "stubbing", "--no-assert-contracts", "--harness", s8_selector,
                   "--exact", "--jobs=1", "--output-format=regular", "-Z", "export-json", "--export-json",
                   str(old / s8_slot / "export.json"), "--verbose", "--target-dir",
                   str(old / s8_slot / "kani-target"), str(std / "library"), "--cbmc-args", "--object-bits", "12"]
        pilot_rustflags = " ".join(f"--cfg={flag}" for flag in spec.CFG[:34])
        self.assertEqual(spec.CFG[33], spec.N32_PILOT_CFG)
        for row in self.frozen["roster"]:
            argv = run.verify_argv(std, tool, new / row["id"], row, self.frozen)
            normalized = [item.replace(str(new / row["id"]), str(old / s8_slot)).replace(row["selector"], s8_selector)
                          for item in argv]
            self.assertEqual(normalized, s8_argv)
            env = run.frozen_env(new / row["id"], row["cfg"], jobs=1)
            self.assertEqual(env["RUSTFLAGS"], pilot_rustflags + f" --cfg={spec.N32_CLOSURE_CFG}")
            # The frozen env never carries the relay; only measure_slot prefixes PATH for the relay slot.
            self.assertNotIn("relay", env.get("PATH", ""))
        # The real CBMC argv the relay must observe is the stock argv of the pilot plain roots.
        self.assertEqual(self.frozen["stdout_relay"]["expected_cbmc_argv"], spec.EXPECTED_CBMC_ARGV)

    def test_new_u64_provider_rows_require_typed_copy_groups(self):
        provider_rows = self.frozen["source_bindings"]["u64_n26_n32_providers_roster"]
        checks = [row for row in provider_rows if row["check"] is not None]
        plain = [row for row in provider_rows if row["check"] is None]
        self.assertEqual((len(checks), len(plain)), (10, 8))
        for row in plain:
            self.assertEqual(len(row["native_evidence"]["required_properties"]), 11)
        bad = deepcopy(provider_rows)
        next(row for row in bad if row["check"] is None)["native_evidence"]["required_properties"].pop()
        with self.assertRaisesRegex(ValueError, "both typed-copy property groups"):
            results._validate_rows(bad)
        bad = deepcopy(provider_rows)
        next(row for row in bad if row["check"] is not None)["check_evidence"]["properties"].pop()
        with self.assertRaisesRegex(ValueError, "scoped assigns and six typed-copy properties"):
            results._validate_rows(bad)

    def test_frozen_pin_limits_and_roster_mutations(self):
        for key, value in (("tool", ["1" * 40, "2" * 40]), ("base", ["3" * 40, "4" * 40]),
                           ("overlay", [spec.OVERLAY[0], "4" * 40]), ("u64_n13_overlay", list(spec.OVERLAY)),
                           ("close_overlay", list(spec.FIX1_OVERLAY)),
                           ("u64_n14_n17_overlay", list(spec.OVERLAY)), ("fix3_overlay", list(spec.CAL2_OVERLAY)),
                           ("cal2_overlay", list(spec.CAL1_OVERLAY)), ("geometries_overlay", list(spec.BINDING_OVERLAY)),
                           ("consumer_overlay", list(spec.GEOMETRIES_OVERLAY)),
                           ("merge_pair_fixed_overlay", list(spec.N20_N21_PROVIDERS_OVERLAY)),
                           ("composite_overlay", list(spec.CONSUMER_OVERLAY)),
                           ("n22_n25_providers_overlay", list(spec.N20_N21_CONSUMER_OVERLAY)),
                           ("halves_overlay", list(spec.N22_N25_CONSUMER_OVERLAY)),
                           ("merge_overlay", list(spec.HALVES_OVERLAY)),
                           ("latest_start_offsets_seconds", {spec.SLOT_IDS[0]: 2701}),
                           ("cbmc_version", "6.11.1"), ("overlay_bundle_sha256", "4" * 64),
                           ("limits", spec.LIMITS | {"singleton_kib": 5 * spec.GIB_KIB}), ("solver", "kissat")):
            with self.subTest(key=key):
                run.dump(self.state / "CI-REQUEST.json", self.frozen | {key: value})
                with self.assertRaisesRegex(ValueError, "frozen request mismatch"):
                    spec.load(self.state, verify_bundle=False)
        for field, value in (("selector", spec.PREFIX + "extra"), ("check", "sort13_optimal"),
                             ("replace", ["bidirectional_merge"]), ("seconds", 196), ("object_bits", 11),
                             ("unwind", 37), ("geometry", "other"), ("cfg", spec.CFG[:3]), ("covers", []),
                             ("expected_outcome", "VERIFIED" if self.frozen["roster"][-1]["expected_outcome"] == "FAILED" else "FAILED"),
                             ("expected_failure", {"label": "wrong", "file": "wrong.rs", "line": 1}),
                             ("required_assertions", [])):
            with self.subTest(field=field):
                bad = deepcopy(self.frozen)
                bad["roster"][-1][field] = value
                run.dump(self.state / "CI-REQUEST.json", bad)
                with self.assertRaisesRegex(ValueError, "frozen roster mismatch"):
                    spec.load(self.state, verify_bundle=False)
        for row_index in range(len(self.frozen["roster"])):
            bad = deepcopy(self.frozen)
            bad["roster"][row_index]["check"] = "wrong_check"
            run.dump(self.state / "CI-REQUEST.json", bad)
            with self.assertRaisesRegex(ValueError, "frozen roster mismatch"):
                spec.load(self.state, verify_bundle=False)
        for rows in ([], self.frozen["roster"] * 2):
            run.dump(self.state / "CI-REQUEST.json", self.frozen | {"roster": rows})
            with self.assertRaisesRegex(ValueError, "frozen roster mismatch"):
                spec.load(self.state, verify_bundle=False)
        bad_bindings = deepcopy(self.frozen)
        bad_bindings["source_bindings"]["pilot_close_roster"][0]["id"] += "_changed"
        run.dump(self.state / "CI-REQUEST.json", bad_bindings)
        with self.assertRaisesRegex(ValueError, "frozen source bindings mismatch"):
            spec.load(self.state, verify_bundle=False)
        run.dump(self.state / "CI-REQUEST.json", self.frozen)
        (self.state / "std-overlay.bundle").write_bytes(b"other bundle")
        with self.assertRaisesRegex(ValueError, "bundle digest mismatch"):
            spec.load(self.state)

    def test_close_fill_gate_rejects_loop_and_array_length_drift(self):
        roots = {}
        for rel in (5, 6, 7):
            tail = 8 + rel
            prefix = "".join(f"                scratch[{index}].assume_init(),\n" for index in range(8, tail))
            roots[rel] = (
                f"    fn gen_n16_wide_fill_r48_rel{rel}() {{\n"
                "        let mut scratch = [MaybeUninit::<Wide>::uninit(); 48];\n"
                f"        for i in 0..{tail} {{}}\n"
                f"        for i in {tail + 1}..32 {{}}\n"
                "        for i in 32..48 {}\n"
                f"        let old = unsafe {{\n            [\n{prefix}            ]\n        }};\n"
                f"        for i in 1..{rel} {{}}\n"
                f"        for i in 0..{rel} {{}}\n"
                f"        for j in 0..{rel + 1} {{}}\n"
                "    }\n"
            ).replace(" {}", " {\n        }")
        spec.check_close_fill_bounds("".join(roots.values()))
        for rel in roots:
            for before, after, message in (
                (f"for i in 0..{rel} {{", f"for i in 0..{rel + 1} {{", "literal loop bounds"),
                (f"for i in 1..{rel} {{", f"for i in 0..{rel} {{", "literal loop bounds"),
                (f"for j in 0..{rel + 1} {{", f"for j in 0..{rel + 2} {{", "literal loop bounds"),
                ("for i in 32..48 {", "for i in 32..49 {", "literal loop bounds"),
                ("                scratch[8].assume_init(),\n", "", "old array length"),
            ):
                with self.subTest(rel=rel, before=before):
                    changed = roots | {rel: roots[rel].replace(before, after, 1)}
                    with self.assertRaisesRegex(ValueError, f"rel{rel} {message}"):
                        spec.check_close_fill_bounds("".join(changed.values()))

    def test_n10_witness_gate_recomputes_both_permutations_and_literal_bounds(self):
        source = "fn earlier() {}\n\n" + N10_MODULE_FIXTURE
        checked = spec.check_n10_witness_source(source)
        self.assertEqual([index - 1 for index in checked["expected"]], [1, 3, 4, 6, 8, 9, 0, 2, 5, 7])
        self.assertEqual([index - 1 for index in checked["corrupted"]], [1, 3, 6, 4, 8, 9, 0, 2, 5, 7])
        for before, after, message in (
            ("for i in 1..10 {", "for i in 1..11 {", "literal loop bounds"),
            ("for i in 1..10 {", "for i in 0..10 {", "literal loop bounds"),
            ("    #[kani::unwind(36)]", "    #[kani::unwind(8)]", "literal loop bounds"),
            ("small_sort(&mut v[1..11], &mut less)", "small_sort(&mut v[1..10], &mut less)", "call range"),
            ("const INPUT: [Wide; 12]", "const INPUT: [Wide; 13]", "INPUT length"),
            ("        input_record(0, 4),\n", "        input_record(1, 4),\n", "INPUT length, keys"),
            ("0xaaaa_bbbb_cccc_dddd", "0xaaaa_bbbb_cccc_ddde", "canary literals"),
            ("payload: 0x8000_0000_0000_0100 + tag", "payload: 0x8000_0000_0000_0101 + tag", "payload constructor"),
            ("INPUT[2], INPUT[4], INPUT[5], INPUT[7]", "INPUT[2], INPUT[5], INPUT[4], INPUT[7]", "EXPECTED order"),
            ("INPUT[2], INPUT[4], INPUT[7], INPUT[5]", "INPUT[2], INPUT[4], INPUT[5], INPUT[7]", "CORRUPTED order"),
            ("let (a, b) = (v[i], v[i + 1]);", "let (a, b) = (v[i - 1], v[i]);", "observer indices"),
            ("v[3].tag == 4 && v[4].tag == 6", "v[3].tag == 4 && v[4].tag == 8", "swap pair"),
            ("v[3].tag < 5 && v[4].tag >= 5", "v[3].tag < 4 && v[4].tag >= 4", "tie cover"),
            ("        v[3] = v[4];\n        v[4] = left;\n", "        v[3] = v[5];\n        v[5] = left;\n",
             "exchange"),
            ("same_wide(v[11], RIGHT), \"GEN_N10_WIDE_AFTER_FRAME\"",
             "same_wide(v[10], RIGHT), \"GEN_N10_WIDE_AFTER_FRAME\"", "frame indices"),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(source.count(before), 1)
                with self.assertRaisesRegex(ValueError, message):
                    spec.check_n10_witness_source(source.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "N10 swap is not one adjacent cross-half pair"), \
                patch.object(spec, "N10_WITNESS_SWAP", (1, 2)):
            spec.check_n10_witness_source(source)
        with self.assertRaises(ValueError):
            spec.check_n10_witness_source(source.replace(spec.N10_WITNESS_DECLARATION, "mod other {\n", 1))

    def test_n12_witness_gate_recomputes_both_permutations_bounds_and_observed_arrays(self):
        source = "fn earlier() {}\n\n" + N10_MODULE_FIXTURE + "\n" + N12_MODULE_FIXTURE
        checked = spec.check_n12_witness_source(source)
        self.assertEqual([index - 1 for index in checked["expected"]], [1, 3, 4, 5, 7, 9, 10, 11, 0, 2, 6, 8])
        self.assertEqual([index - 1 for index in checked["corrupted"]], [1, 3, 4, 7, 5, 9, 10, 11, 0, 2, 6, 8])
        # The N10 gate stops at the next opt-in module, so the appended N12 module does not leak into it.
        self.assertEqual([index - 1 for index in spec.check_n10_witness_source(source)["expected"]],
                         [1, 3, 4, 6, 8, 9, 0, 2, 5, 7])
        before_call = "        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n"
        after_call = "        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n"
        n12 = source.index(spec.N12_WITNESS_DECLARATION)
        head, tail = source[:n12], source[n12:]
        swapped = tail.replace(before_call, "@@", 1).replace(after_call, before_call, 1).replace("@@", after_call, 1)
        for before, after, message in (
            ("for i in 1..12 {", "for i in 1..13 {", "literal loop bounds"),
            ("for i in 1..12 {", "for i in 0..12 {", "literal loop bounds"),
            ("    #[kani::unwind(36)]\n    fn gen_n12", "    #[kani::unwind(8)]\n    fn gen_n12", "literal loop bounds"),
            ("small_sort(&mut v[1..13], &mut less)", "small_sort(&mut v[1..12], &mut less)", "call range"),
            ("const INPUT: [Wide; 14]", "const INPUT: [Wide; 15]", "INPUT length"),
            ("        input_record(0, 4),\n", "        input_record(1, 4),\n", "INPUT length, keys"),
            ("        input_record(0, 11),\n", "        input_record(1, 11),\n", "INPUT length, keys"),
            ("0xaaaa_bbbb_cccc_dddd", "0xaaaa_bbbb_cccc_ddde", "canary literals"),
            ("payload: 0x8000_0000_0000_0100 + tag", "payload: 0x8000_0000_0000_0101 + tag", "payload constructor"),
            ("INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[8]", "INPUT[2], INPUT[4], INPUT[6], INPUT[5], INPUT[8]",
             "EXPECTED order"),
            ("INPUT[2], INPUT[4], INPUT[5], INPUT[8], INPUT[6]", "INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[8]",
             "CORRUPTED order"),
            ("let (a, b) = (v[i], v[i + 1]);", "let (a, b) = (v[i - 1], v[i]);", "observer indices"),
            ("v[4].tag == 5 && v[5].tag == 7", "v[4].tag == 5 && v[5].tag == 9", "swap pair"),
            ("v[4].tag < 6 && v[5].tag >= 6", "v[4].tag < 5 && v[5].tag >= 5", "tie cover"),
            ("        v[4] = v[5];\n        v[5] = left;\n", "        v[4] = v[6];\n        v[6] = left;\n", "exchange"),
            ("same_wide(v[13], RIGHT), \"GEN_N12_WIDE_AFTER_FRAME\"",
             "same_wide(v[12], RIGHT), \"GEN_N12_WIDE_AFTER_FRAME\"", "frame indices"),
            (after_call, before_call, "observers do not read"),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(tail.count(before), 1)
                with self.assertRaisesRegex(ValueError, f"N12 .*{message}"):
                    spec.check_n12_witness_source(head + tail.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "N12 observers do not read EXPECTED before and CORRUPTED after"):
            spec.check_n12_witness_source(head + swapped)
        with self.assertRaisesRegex(ValueError, "N12 swap is not one adjacent cross-half pair"), \
                patch.object(spec, "N12_WITNESS_SWAP", (4, 5)):
            spec.check_n12_witness_source(source)
        with self.assertRaises(ValueError):
            spec.check_n12_witness_source(source.replace(spec.N12_WITNESS_DECLARATION, "mod other {\n", 1))

    def wide_n12_n14_file(self, module=None):
        """A pilot-file stand-in: the shared comparator at line 35, then the exact module at line 1497."""
        module = WIDE_N12_N14_MODULE_FIXTURE if module is None else module
        head = ["// pilot module stand-in"] + [""] * 32 + ["fn wide_less(a: &Wide, b: &Wide) -> bool {",
                '    kani::cover(true, "GEN_N16_WIDE_COMPARATOR_CALLED");', "    a.key < b.key", "}"]
        head += [""] * (1496 - len(head) - 2) + ["}", ""]
        self.assertEqual(len(head), 1496)
        return "\n".join(head) + "\n" + module

    def test_wide_n12_n14_check_gate_binds_offsets_bounds_scopes_and_tie_rules(self):
        source = self.wide_n12_n14_file()
        spec.check_wide_n12_n14_source(source)
        rendered = {(n, d): spec.wide_n12_n14_check_text(n, d) for n, d in spec.WIDE_N12_N14_CHECK_GEOMETRY.values()}
        for text in rendered.values():
            self.assertEqual(source.count(text), 1)
        for (n, direction), before, after in (
            ((12, "up"), "let up_right = d.add(6 + b);", "let up_right = d.add(7 + b);"),
            ((12, "up"), "kani::requires(k < 6 && a <= k),", "kani::requires(k < 7 && a <= k),"),
            ((12, "up"), "ptr::slice_from_raw_parts(d, 12)", "ptr::slice_from_raw_parts(d, 14)"),
            ((12, "up"), "ptr::slice_from_raw_parts_mut(s, 12)", "ptr::slice_from_raw_parts_mut(s, 11)"),
            ((12, "up"), "&& dst == s.add(k + 1),", "&& dst == s.add(k),"),
            ((12, "up"), "let takes_left = (*up_left).key <= (*up_right).key;",
             "let takes_left = (*up_left).key < (*up_right).key;"),
            ((12, "up"), "= merge_up(up_left, up_right, up_dst, &mut less);",
             "= merge_down(up_left, up_right, up_dst, &mut less);"),
            ((12, "up"), "let mut v = wide_array::<14>();", "let mut v = wide_array::<16>();"),
            ((12, "up"), "let s = v[1..13].as_mut_ptr();", "let s = v[0..12].as_mut_ptr();"),
            ((12, "up"), "scratch_before[6 + (k - a)]", "scratch_before[7 + (k - a)]"),
            ((12, "up"), "for i in 0..14 {", "for i in 1..13 {"),
            ((12, "up"), 'kani::cover(k == 5, "GEN_N12_WIDE_UP_K_LAST");', 'kani::cover(k == 4, "GEN_N12_WIDE_UP_K_LAST");'),
            ((12, "up"), "        kani::assume(k < 6 && a <= k);\n",
             "        kani::assume(k < 6 && a <= k);\n        kani::assume(sorted_halves(&scratch));\n"),
            ((12, "down"), "kani::modifies(s.wrapping_add(11 - k))", "kani::modifies(s.wrapping_add(10 - k))"),
            ((12, "down"), "let down_left = d.add(5 - c);", "let down_left = d.add(6 - c);"),
            ((12, "down"), "let down_right = d.add(11 - d_count);", "let down_right = d.add(12 - d_count);"),
            ((12, "down"), "let down_dst = s.add(11 - k);", "let down_dst = s.add(12 - k);"),
            ((12, "down"), "&& dst == s.add(10 - k),", "&& dst == s.add(11 - k),"),
            ((12, "down"), "let takes_left = (*down_left).key > (*down_right).key;",
             "let takes_left = (*down_left).key >= (*down_right).key;"),
            ((12, "down"), "left == down_left.wrapping_sub(takes_left as usize)",
             "left == down_left.sub(takes_left as usize)"),
            ((12, "down"), 'same_wide(v[12 - k], expected), "GEN_N12_WIDE_DOWN_VALUE"',
             'same_wide(v[11 - k], expected), "GEN_N12_WIDE_DOWN_VALUE"'),
            ((14, "up"), "let up_right = d.add(7 + b);", "let up_right = d.add(6 + b);"),
            ((14, "up"), "kani::requires(k < 7 && a <= k),", "kani::requires(k < 8 && a <= k),"),
            ((14, "up"), "let s = v[1..15].as_mut_ptr();", "let s = v[1..13].as_mut_ptr();"),
            ((14, "up"), "for i in 0..16 {", "for i in 0..15 {"),
            ((14, "down"), "kani::modifies(s.wrapping_add(13 - k))", "kani::modifies(s.wrapping_add(k))"),
            ((14, "down"), "let down_left = d.add(6 - c);", "let down_left = d.add(7 - c);"),
            ((14, "down"), "let down_right = d.add(13 - d_count);", "let down_right = d.add(15 - d_count);"),
            ((14, "down"), "&& dst == s.add(12 - k),", "&& dst == s.add(14 - k),"),
            ((14, "down"), 'kani::cover(k == 6, "GEN_N14_WIDE_DOWN_K_LAST");',
             'kani::cover(k == 7, "GEN_N14_WIDE_DOWN_K_LAST");'),
            ((14, "down"), "kani::requires(!ub_checks::same_allocation(d, s)),\n", ""),
            ((14, "down"), "    #[kani::proof_for_contract(actual_merge_down_wide_n14)]",
             "    #[kani::proof_for_contract(actual_merge_down_wide_n12)]"),
        ):
            with self.subTest(geometry=(n, direction), before=before):
                text = rendered[(n, direction)]
                self.assertEqual(text.count(before), 1)
                with self.assertRaisesRegex(ValueError, "differ from their N/m geometry"):
                    spec.check_wide_n12_n14_source(source.replace(text, text.replace(before, after, 1), 1))
        for before, after in (("        for i in 32..48 {\n            scratch[i].write(any_wide());",
                               "        for i in 32..47 {\n            scratch[i].write(any_wide());"),
                              ("    use super::*;\n", "    use super::{Wide, kani};\n")):
            with self.subTest(helper=before):
                self.assertEqual(source.count(before), 1)
                with self.assertRaisesRegex(ValueError, "differ from their N/m geometry"):
                    spec.check_wide_n12_n14_source(source.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "declaration or witness marker"):
            spec.check_wide_n12_n14_source(source.replace(spec.N14_WITNESS_MARKER, "", 1))
        for later in ("\n#[cfg(kani_later)]\nmod later {\n}\n", "fn trailing() {}\n", "fn trailing() {\n}\n"):
            with self.assertRaisesRegex(ValueError, "last opt-in module"):
                spec.check_wide_n12_n14_source(source + later)

    def test_n14_witness_gate_recomputes_both_permutations_bounds_and_observed_arrays(self):
        source = self.wide_n12_n14_file()
        checked = spec.check_n14_witness_source(source)
        self.assertEqual([index - 1 for index in checked["expected"]], [1, 3, 4, 5, 6, 8, 10, 11, 12, 13, 0, 2, 7, 9])
        self.assertEqual([index - 1 for index in checked["corrupted"]], [1, 3, 4, 5, 8, 6, 10, 11, 12, 13, 0, 2, 7, 9])
        marker = source.index(spec.N14_WITNESS_MARKER)
        head, tail = source[:marker], source[marker:]
        before_call = "        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n"
        after_call = "        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n"
        swapped = tail.replace(before_call, "@@", 1).replace(after_call, before_call, 1).replace("@@", after_call, 1)
        for before, after, message in (
            ("for i in 1..14 {", "for i in 1..15 {", "literal loop bounds"),
            ("for i in 1..14 {", "for i in 0..14 {", "literal loop bounds"),
            ("    #[kani::unwind(36)]\n    fn gen_n14", "    #[kani::unwind(8)]\n    fn gen_n14", "literal loop bounds"),
            ("small_sort(&mut v[1..15], &mut less)", "small_sort(&mut v[1..14], &mut less)", "call range"),
            ("const INPUT: [Wide; 16]", "const INPUT: [Wide; 17]", "INPUT length"),
            ("        input_record(0, 6),\n", "        input_record(1, 6),\n", "INPUT length, keys"),
            ("        input_record(1, 9),\n", "        input_record(0, 9),\n", "INPUT length, keys"),
            ("0x1111_2222_3333_4444", "0x1111_2222_3333_4445", "canary literals"),
            ("payload: 0x8000_0000_0000_0100 + tag", "payload: 0x8000_0000_0000_0101 + tag", "payload constructor"),
            ("INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[7], INPUT[9]",
             "INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[9], INPUT[7]", "EXPECTED order"),
            ("INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[9], INPUT[7]",
             "INPUT[2], INPUT[4], INPUT[5], INPUT[6], INPUT[7], INPUT[9]", "CORRUPTED order"),
            ("let (a, b) = (v[i], v[i + 1]);", "let (a, b) = (v[i - 1], v[i]);", "observer indices"),
            ("v[5].tag == 6 && v[6].tag == 8", "v[5].tag == 6 && v[6].tag == 10", "swap pair"),
            ("v[5].tag < 7 && v[6].tag >= 7", "v[5].tag < 6 && v[6].tag >= 6", "tie cover"),
            ("        v[5] = v[6];\n        v[6] = left;\n", "        v[5] = v[7];\n        v[7] = left;\n", "exchange"),
            ("same_wide(v[15], RIGHT), \"GEN_N14_WIDE_AFTER_FRAME\"",
             "same_wide(v[14], RIGHT), \"GEN_N14_WIDE_AFTER_FRAME\"", "frame indices"),
            (after_call, before_call, "observers do not read"),
            ("        let mut v = INPUT;\n", "        let mut v = INPUT;\n        v[3].key = kani::any();\n", "kani::any"),
            ("        let mut less = wide_less;\n",
             "        let mut less = wide_less;\n        kani::assume(v[1].key <= v[2].key);\n", "kani::assume"),
            ("    #[kani::proof]\n", "    #[kani::proof_for_contract(actual_merge_up_wide_n14)]\n", "proof_for_contract"),
            ("    #[kani::proof]\n", "    #[kani::proof]\n    #[kani::stub(insert_tail, insert_tail)]\n", "kani::stub"),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(tail.count(before), 1)
                with self.assertRaisesRegex(ValueError, f"N14 .*{message}"):
                    spec.check_n14_witness_source(head + tail.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "N14 observers do not read EXPECTED before and CORRUPTED after"):
            spec.check_n14_witness_source(head + swapped)
        with self.assertRaisesRegex(ValueError, "N14 swap is not one adjacent cross-half pair"), \
                patch.object(spec, "N14_WITNESS_SWAP", (3, 4)):
            spec.check_n14_witness_source(source)
        with self.assertRaisesRegex(ValueError, "N14 witness marker missing"):
            spec.check_n14_witness_source(source.replace(spec.N14_WITNESS_MARKER, "    // moved\n", 1))
        with self.assertRaisesRegex(ValueError, "N14 witness module declaration"):
            spec.check_n14_witness_source(source.replace(spec.WIDE_N12_N14_DECLARATION, "mod other {\n", 1))
        # The marker cannot move ahead of the Checks: the head would then carry the witness.
        moved = source.replace(spec.N14_WITNESS_MARKER, "", 1).replace(
            "    fn wide_array", spec.N14_WITNESS_MARKER + "    fn wide_array", 1)
        with self.assertRaisesRegex(ValueError, "N14 witness body contains"):
            spec.check_n14_witness_source(moved)

    def test_wide_n12_n14_native_coordinates_and_copy_sites_bind_the_frozen_roster(self):
        rows = self.frozen["source_bindings"]["wide_n12_n14_roster"]
        sites = rows[-1]["native_evidence"]["copy_sites"]
        self.assertEqual([site["line"] for site in sites], [832, 833, 834, 835, 329, 722, 362, 885, 918])
        smallsort = [""] * 1100
        for site in sites:
            smallsort[site["line"] - 1] = " " * (site["column"] - 1) + site["token"]
        comparator_line, comparator_column = spec.COMPARATOR_COORDINATE
        u64_line, u64_column = spec.U64_COMPARATOR_COORDINATE
        blobs = {
            f"library/{spec.PILOT_MODULE_FILE}": self.wide_n12_n14_file().encode(),
            f"library/{spec.SMALLSORT_FILE}": "\n".join(smallsort).encode() + b"\n",
            f"library/{spec.COMPARATOR_FILE}": (b"\n" * (comparator_line - 1) + b" " * (comparator_column - 1)
                                                 + f'crate::kani::cover(true, "{spec.COMPARATOR_LABEL}");\n'.encode()),
            f"library/{spec.U64_N13_FILE}": (b"\n" * (u64_line - 1) + b" " * (u64_column - 1)
                                             + f'kani::cover(true, "{spec.U64_COMPARATOR_LABEL}");\n'.encode()),
        }

        def check(changed_rows=rows, **changes):
            with patch.object(spec, "git_blob", side_effect=lambda _std, _rev, path: changes.get(path, blobs[path])):
                return spec.check_native_coordinates(self.std, spec.OVERLAY[0], changed_rows,
                                                     prefix=spec.WIDE_N12_N14_PREFIX, module_file=spec.PILOT_MODULE_FILE)

        self.assertTrue(check())
        module = f"library/{spec.PILOT_MODULE_FILE}"
        for index, (field, value, message) in enumerate((
            ("modifies", ["s.wrapping_add(k)"], "Check target or modifies anchor"),
            ("lines", [1536], "Check target or modifies anchor"),
            ("column", 1, "scope or cfg_attr column"),
            ("copy_sites", rows[1]["check_evidence"]["copy_sites"], "actual copy site or direction"),
            ("target_instance", spec.WIDE_N12_N14_PREFIX + "actual_merge_up_wide_n14", "Check target or modifies anchor"),
        )):
            with self.subTest(field=field):
                bad = deepcopy(rows)
                bad[1 if field == "modifies" else 0]["check_evidence"][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    check(bad)
        bad = deepcopy(rows)
        bad[-1]["native_evidence"]["copy_sites"] = sites[:-1]
        with self.assertRaisesRegex(ValueError, "actual typed-copy sites differ"):
            check(bad)
        bad = deepcopy(rows)
        bad[2]["native_evidence"]["coordinates"]["GEN_N14_WIDE_UP_VALUE"]["line"] += 1
        with self.assertRaisesRegex(ValueError, "GEN_N14_WIDE_UP_VALUE: expected"):
            check(bad)
        bad = deepcopy(rows)
        bad[-1]["expected_failure"]["line"] -= 1
        with self.assertRaisesRegex(ValueError, "failure coordinate differs"):
            check(bad)
        # An extra labelled call in the module, or a missing row, leaves an unbound native label.
        with self.assertRaisesRegex(ValueError, "extra or missing labelled calls"):
            check(rows[:-1])
        with self.assertRaisesRegex(ValueError, "last opt-in module"):
            check(**{module: blobs[module] + b'fn extra() {\n    kani::cover(true, "GEN_N14_EXTRA");\n}\n'})

    def n32_file(self, module=None):
        """A pilot-file stand-in: the shared comparator at line 35, then the exact N32 module at line 1943."""
        module = N32_MODULE_FIXTURE if module is None else module
        head = ["// pilot module stand-in"] + [""] * 32 + ["fn wide_less(a: &Wide, b: &Wide) -> bool {",
                '    kani::cover(true, "GEN_N16_WIDE_COMPARATOR_CALLED");', "    a.key < b.key", "}"]
        head += [""] * (N32_MODULE_LINE - 1 - len(head) - 2) + ["}", ""]
        self.assertEqual(len(head), N32_MODULE_LINE - 1)
        return "\n".join(head) + "\n" + module

    def test_n32_fixture_is_the_geometry_render(self):
        self.assertEqual(N32_MODULE_FIXTURE, spec.n32_module_text())
        self.assertTrue(N32_MODULE_FIXTURE.startswith(spec.N32_DECLARATION))
        self.assertEqual(spec.check_n32_pilot_source(self.n32_file()), N32_MODULE_FIXTURE)

    def test_n32_source_gate_rejects_geometry_rel15_and_merge_mutations(self):
        source = self.n32_file()
        s8 = spec.n32_s8_text()
        fill_u64, fill_wide = spec.n32_fill_text("u64"), spec.n32_fill_text("wide")
        checks = {(kind, role): spec.n32_check_text(kind, role) for kind, role in spec.N32_CHECK_ORDER}
        for text in (s8, fill_u64, fill_wide, *checks.values()):
            self.assertEqual(source.count(text), 1)
        mutations = (
            # S8 geometry: source, destination, tmp, read window, frames and tmp blocks.
            (s8, "sort8_stable(s.add(16), d.add(16), d.add(40), &mut less)", "sort8_stable(s.add(16), d.add(16), d.add(32), &mut less)"),
            (s8, "sort8_stable(s.add(16), d.add(16), d.add(40), &mut less)", "sort8_stable(s.add(15), d.add(16), d.add(40), &mut less)"),
            (s8, "sort8_stable(s.add(16), d.add(16), d.add(40), &mut less)", "sort8_stable(s, d, d.add(32), &mut less)"),
            (s8, "input_count += usize::from(before[17 + i] == probe);", "input_count += usize::from(before[16 + i] == probe);"),
            (s8, "inversion |= before[17 + i] > before[18 + i];", "inversion |= before[16 + i] > before[17 + i];"),
            (s8, "tmp_right_ordered &= scratch[44 + i]", "tmp_right_ordered &= scratch[40 + i]"),
            (s8, "        for i in 24..40 {\n", "        for i in 24..48 {\n"),
            (s8, "        for i in 17..34 {\n", "        for i in 17..33 {\n"),
            (s8, "let mut scratch = [MaybeUninit::<u64>::uninit(); 48];", "let mut scratch = [MaybeUninit::<u64>::uninit(); 40];"),
            (s8, "let s = v[1..33].as_mut_ptr();", "let s = v[0..32].as_mut_ptr();"),
            (s8, "let probe: u64 = kani::any();", "let probe: u64 = u64::from(kani::any::<bool>());"),
            # rel15: snapshot, extra read or iteration, sorted premise, position and exact post.
            (fill_u64, "        for i in 0..15 {\n            // SAFETY: D[16..31]", "        for i in 0..16 {\n            // SAFETY: D[16..31]"),
            (fill_u64, "let mut old = [0u64; 15];", "let mut old = [0u64; 16];"),
            (fill_u64, "old[i] = unsafe { scratch[16 + i].assume_init() };", "old[i] = unsafe { scratch[17 + i].assume_init() };"),
            (fill_u64, "        for i in 1..15 {\n", "        for i in 1..14 {\n"),
            (fill_u64, "pos += usize::from(old[i] <= x);", "pos += usize::from(old[i] < x);"),
            (fill_u64, "        for j in 0..16 {\n", "        for j in 0..15 {\n"),
            (fill_u64, "ptr::copy_nonoverlapping(s.add(31), d.add(31), 1);", "ptr::copy_nonoverlapping(s.add(30), d.add(31), 1);"),
            (fill_u64, "insert_tail(d.add(16), d.add(31), &mut less);", "insert_tail(d.add(15), d.add(31), &mut less);"),
            (fill_u64, "        for i in 0..31 {\n", "        for i in 0..32 {\n"),
            (fill_u64, "let x = before[32];", "let x = before[31];"),
            (fill_u64, "kani::cover(pos == 15,", "kani::cover(pos == 14,"),
            (fill_u64, "        kani::assume(sorted_prefix);\n", "        kani::assume(sorted_prefix);\n        kani::assume(x != old[0]);\n"),
            (fill_wide, "equal_distinct |= old[i].key == x.key && old[i].tag != x.tag;", "equal_distinct |= old[i].key == x.key;"),
            (fill_wide, "sorted_prefix &= old[i - 1].key <= old[i].key;", "sorted_prefix &= old[i - 1].key < old[i].key;"),
            (fill_wide, "exact &= same_wide(unsafe { scratch[16 + j].assume_init() }, expected);",
             "exact &= unsafe { scratch[16 + j].assume_init() }.key == expected.key;"),
            # Merge Checks: offsets, bounds, scopes, tie rules, cursors and a sorted guard.
            (checks[("u64", "up")], "let up_right = d.add(16 + b);", "let up_right = d.add(15 + b);"),
            (checks[("u64", "up")], "kani::requires(k < 16 && a <= k),", "kani::requires(k < 17 && a <= k),"),
            (checks[("u64", "up")], "ptr::slice_from_raw_parts(d, 32)", "ptr::slice_from_raw_parts(d, 31)"),
            (checks[("u64", "up")], "let takes_left = (*up_left) <= (*up_right);", "let takes_left = (*up_left) < (*up_right);"),
            (checks[("u64", "up")], "&& dst == s.add(k + 1),", "&& dst == s.add(k),"),
            (checks[("u64", "up")], 'kani::cover(k == 15, "GEN_N32_U64_UP_K_LAST");', 'kani::cover(k == 14, "GEN_N32_U64_UP_K_LAST");'),
            (checks[("u64", "up")], "        kani::assume(k < 16 && a <= k);\n",
             "        kani::assume(k < 16 && a <= k);\n        kani::assume(sorted_halves(&scratch));\n"),
            (checks[("u64", "down")], "kani::modifies(s.wrapping_add(31 - k))", "kani::modifies(s.wrapping_add(30 - k))"),
            (checks[("u64", "down")], "let down_left = d.add(15 - c);", "let down_left = d.add(16 - c);"),
            (checks[("u64", "down")], "let down_right = d.add(31 - d_count);", "let down_right = d.add(32 - d_count);"),
            (checks[("u64", "down")], "&& dst == s.add(30 - k),", "&& dst == s.add(31 - k),"),
            (checks[("u64", "down")], "left == down_left.wrapping_sub(takes_left as usize)", "left == down_left.sub(takes_left as usize)"),
            (checks[("u64", "down")], "kani::assert(v[32 - k] == expected,", "kani::assert(v[31 - k] == expected,"),
            (checks[("wide", "up")], "let mut v = wide_v34();", "let mut v = [any_wide(); 34];"),
            (checks[("wide", "up")], "= merge_up(up_left, up_right, up_dst, &mut less);", "= merge_down(up_left, up_right, up_dst, &mut less);"),
            (checks[("wide", "down")], "let takes_left = (*down_left).key > (*down_right).key;", "let takes_left = (*down_left).key >= (*down_right).key;"),
            (checks[("wide", "down")], "down_left.key == down_right.key && down_left.tag != down_right.tag",
             "down_left.key == down_right.key"),
            (checks[("wide", "down")], "kani::requires(!ub_checks::same_allocation(d, s)),\n", ""),
            (checks[("wide", "down")], "    #[kani::proof_for_contract(actual_merge_down_wide_n32)]",
             "    #[kani::proof_for_contract(actual_merge_down_u64_n32)]"),
        )
        for text, before, after in mutations:
            with self.subTest(before=before, after=after):
                self.assertEqual(text.count(before), 1)
                with self.assertRaisesRegex(ValueError, "differs from its V34/D48 geometry render"):
                    spec.check_n32_pilot_source(source.replace(text, text.replace(before, after, 1), 1))
        for before, after in (("        for i in 17..34 {\n            v[i] = any_wide();", "        for i in 17..33 {\n            v[i] = any_wide();"),
                              ("    use super::*;\n", "    use super::{Wide, kani};\n")):
            with self.subTest(helper=before):
                self.assertEqual(source.count(before), 1)
                with self.assertRaisesRegex(ValueError, "geometry render"):
                    spec.check_n32_pilot_source(source.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "declaration missing or ambiguous"):
            spec.check_n32_pilot_source(source.replace(spec.N32_DECLARATION, "mod n32_pilot {\n", 1))
        for later in ("\n#[cfg(kani_later)]\nmod later {\n}\n", "fn trailing() {}\n"):
            with self.assertRaisesRegex(ValueError, "geometry render"):
                spec.check_n32_pilot_source(source + later)

    def test_n32_native_coordinates_and_copy_sites_bind_the_frozen_roster(self):
        rows = self.frozen["source_bindings"]["n32_pilot_roster"]
        sites = rows[0]["native_evidence"]["copy_sites"] + rows[1]["native_evidence"]["copy_sites"][1:]
        sites += [rows[1]["native_evidence"]["copy_sites"][0]["transcribes"]]
        smallsort = [""] * 1100
        for site in sites:
            smallsort[site["line"] - 1] = " " * (site["column"] - 1) + site["token"]
        comparator_line, comparator_column = spec.COMPARATOR_COORDINATE
        u64_line, u64_column = spec.U64_COMPARATOR_COORDINATE
        blobs = {
            f"library/{spec.PILOT_MODULE_FILE}": self.n32_file().encode(),
            f"library/{spec.SMALLSORT_FILE}": "\n".join(smallsort).encode() + b"\n",
            f"library/{spec.COMPARATOR_FILE}": (b"\n" * (comparator_line - 1) + b" " * (comparator_column - 1)
                                                 + f'crate::kani::cover(true, "{spec.COMPARATOR_LABEL}");\n'.encode()),
            f"library/{spec.U64_N13_FILE}": (b"\n" * (u64_line - 1) + b" " * (u64_column - 1)
                                             + f'kani::cover(true, "{spec.U64_COMPARATOR_LABEL}");\n'.encode()),
        }

        def check(changed_rows=rows, **changes):
            with patch.object(spec, "git_blob", side_effect=lambda _std, _rev, path: changes.get(path, blobs[path])):
                return spec.check_native_coordinates(self.std, spec.OVERLAY[0], changed_rows,
                                                     prefix=spec.N32_PREFIX, module_file=spec.PILOT_MODULE_FILE)

        self.assertTrue(check())
        module = f"library/{spec.PILOT_MODULE_FILE}"
        for index, field, value, message in (
            (4, "modifies", ["s.wrapping_add(k)"], "Check target or modifies anchor"),
            (3, "lines", [rows[3]["check_evidence"]["lines"][0] - 1], "Check target or modifies anchor"),
            (3, "column", 1, "scope or cfg_attr column"),
            (3, "copy_sites", rows[4]["check_evidence"]["copy_sites"], "actual copy site or direction"),
            (5, "target_instance", spec.N32_PREFIX + "actual_merge_up_u64_n32", "Check target or modifies anchor"),
        ):
            with self.subTest(field=field):
                bad = deepcopy(rows)
                bad[index]["check_evidence"][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    check(bad)
        for index, copy_sites in ((0, sites[:5]), (1, rows[2]["native_evidence"]["copy_sites"]),
                                  (2, rows[1]["native_evidence"]["copy_sites"]), (1, rows[0]["native_evidence"]["copy_sites"])):
            with self.subTest(copy_sites=index):
                bad = deepcopy(rows)
                bad[index]["native_evidence"]["copy_sites"] = copy_sites
                with self.assertRaisesRegex(ValueError, "local or actual typed-copy sites differ"):
                    check(bad)
        bad = deepcopy(rows)
        bad[2]["native_evidence"]["coordinates"]["GEN_N32_WIDE_FILL_REL15_EXACT_UPPER_BOUND"]["line"] += 1
        with self.assertRaisesRegex(ValueError, "GEN_N32_WIDE_FILL_REL15_EXACT_UPPER_BOUND: expected"):
            check(bad)
        bad = deepcopy(rows)
        bad[0]["native_evidence"]["coordinates"]["GEN_N32_U64_S8_R48_SORTED"]["function"] += "_other"
        with self.assertRaisesRegex(ValueError, "native function or class"):
            check(bad)
        with self.assertRaisesRegex(ValueError, "extra or missing labelled calls"):
            check(rows[:-1])
        with self.assertRaisesRegex(ValueError, "geometry render"):
            check(**{module: blobs[module] + b'fn extra() {\n    kani::cover(true, "GEN_N32_EXTRA");\n}\n'})

    def n32_closure_file(self, module=None):
        """A pilot-file stand-in: the shared comparator at line 35, then the exact closure module at line 2594."""
        module = N32_CLOSURE_MODULE_FIXTURE if module is None else module
        head = ["// pilot module stand-in"] + [""] * 32 + ["fn wide_less(a: &Wide, b: &Wide) -> bool {",
                '    kani::cover(true, "GEN_N16_WIDE_COMPARATOR_CALLED");', "    a.key < b.key", "}"]
        head += [""] * (N32_CLOSURE_MODULE_LINE - 1 - len(head) - 2) + ["}", ""]
        self.assertEqual(len(head), N32_CLOSURE_MODULE_LINE - 1)
        return "\n".join(head) + "\n" + module

    def test_n32_closure_fixture_is_the_render(self):
        self.assertEqual(N32_CLOSURE_MODULE_FIXTURE, spec.n32_closure_module_text())
        self.assertTrue(N32_CLOSURE_MODULE_FIXTURE.startswith(spec.N32_CLOSURE_DECLARATION))
        self.assertEqual(spec.check_n32_closure_source(self.n32_closure_file()), N32_CLOSURE_MODULE_FIXTURE)
        # The u64 control masks are recomputed from the literal words: 24 ones, sorted 0xffffff00, flip to 0xffffff80.
        self.assertEqual(spec.n32_u64_witness_masks(), (24, 0xFFFF_FF00, 0xFFFF_FF80))
        self.assertEqual(spec.rust_hex(0xFFFF_FF80), "0xffff_ff80")
        self.assertEqual(spec.rust_hex(0x1111_2222_3333_4444), "0x1111_2222_3333_4444")
        for words in ((0,) * 32, (1, 0) * 16, (1, 0, 1, 0, 1, 0, 1, 1, *(1,) * 8) * 2):
            with self.subTest(words=words[:8]), patch.object(spec, "N32_U64_WITNESS_WORDS", words):
                with self.assertRaisesRegex(ValueError, "multiplicity of ones"):
                    spec.n32_u64_witness_masks()
        with patch.object(spec, "N32_U64_WITNESS_FLIP", 9), self.assertRaisesRegex(ValueError, "multiplicity"):
            spec.n32_u64_witness_masks()

    def test_n32_closure_source_gate_rejects_geometry_route_and_post_mutations(self):
        source = self.n32_closure_file()
        s8, u64, wide = spec.n32_s8_left_text(), spec.n32_u64_witness_text(), spec.n32_wide_witness_text()
        for text in (s8, u64, wide):
            self.assertEqual(source.count(text), 1)
        mutations = (
            # Left S8: source, destination, tmp, read window, tmp blocks and both frame intervals.
            (s8, "sort8_stable(s, d, d.add(32), &mut less)", "sort8_stable(s, d, d.add(40), &mut less)"),
            (s8, "sort8_stable(s, d, d.add(32), &mut less)", "sort8_stable(s.add(16), d.add(16), d.add(40), &mut less)"),
            (s8, "sort8_stable(s, d, d.add(32), &mut less)", "sort8_stable(s.add(1), d, d.add(32), &mut less)"),
            (s8, "input_count += usize::from(before[1 + i] == probe);", "input_count += usize::from(before[i] == probe);"),
            (s8, "inversion |= before[1 + i] > before[2 + i];", "inversion |= before[i] > before[1 + i];"),
            (s8, "tmp_right_ordered &= scratch[36 + i]", "tmp_right_ordered &= scratch[40 + i]"),
            (s8, "tmp_left_ordered &= scratch[32 + i]", "tmp_left_ordered &= scratch[i]"),
            (s8, "        for i in 8..32 {\n            scratch[i].write", "        for i in 8..40 {\n            scratch[i].write"),
            (s8, "        for i in 40..48 {\n            //", "        for i in 41..48 {\n            //"),
            (s8, "let mut scratch = [MaybeUninit::<u64>::uninit(); 48];", "let mut scratch = [MaybeUninit::<u64>::uninit(); 40];"),
            (s8, "let s = v[1..33].as_mut_ptr();", "let s = v[0..32].as_mut_ptr();"),
            (s8, "let probe: u64 = kani::any();", "let probe: u64 = u64::from(kani::any::<bool>());"),
            (s8, "        for i in 17..34 {\n", "        for i in 17..33 {\n"),
            # Stable u64 control: D32 scratch, entry, slice, literal words, masks, flip, frame and the sole failure.
            (u64, "let mut scratch = [MaybeUninit::<u64>::uninit(); 48];", "let mut scratch = [MaybeUninit::<u64>::uninit(); 32];"),
            (u64, "<u64 as StableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut scratch, &mut less);",
             "<u64 as StableSmallSortTypeImpl>::small_sort(&mut v[0..32], &mut scratch, &mut less);"),
            (u64, "<u64 as StableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut scratch, &mut less);",
             "<u64 as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut less);"),
            (u64, "U64_LEFT, 1, 0, 1, 0,", "U64_LEFT, 1, 1, 1, 0,"),
            (u64, "kani::assert(mask == 0xffff_ff00,", "kani::assert(mask == 0xffff_fe00,"),
            (u64, "kani::assert(mask == 0xffff_ff80,", "kani::assert(mask == 0xffff_ff00,"),
            (u64, "        v[8] ^= 1u64;\n", "        v[9] ^= 1u64;\n"),
            (u64, "            ones == 24 && mask.count_ones() == ones,", "            mask.count_ones() == ones,"),
            (u64, 'kani::assert(mask.count_ones() == ones, "GEN_N32_STABLE_U64_MULTIPLICITY");',
             'kani::assert(ordered, "GEN_N32_STABLE_U64_MULTIPLICITY");'),
            (u64, 'kani::cover(true, "AFTER_STABLE_N32_RETURN");', 'kani::cover(false, "AFTER_STABLE_N32_RETURN");'),
            (u64, "        for i in 1..32 {\n            ordered", "        for i in 2..32 {\n            ordered"),
            (u64, "        let mut less = u64_less;\n", "        let mut less = u64_less;\n        kani::assume(v[1] == 1);\n"),
            # Wide control: actual route, slice, swap pair, observers and the extra preliminary assertion.
            (wide, "<Wide as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut less);",
             "<Wide as StableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut [MaybeUninit::uninit(); 48], &mut less);"),
            (wide, "        v[2] = v[3];\n        v[3] = left;\n", "        v[2] = v[4];\n        v[4] = left;\n"),
            (wide, 'kani::assert(exact, "GEN_N32_WIDE_AFTER_RECORDS_BY_TAG");', 'kani::cover(exact, "GEN_N32_WIDE_AFTER_RECORDS_BY_TAG");'),
            (wide, "    #[kani::proof]\n", "    #[kani::proof]\n    #[kani::stub(insert_tail, insert_tail)]\n"),
        )
        for text, before, after in mutations:
            with self.subTest(before=before, after=after):
                self.assertEqual(text.count(before), 1)
                with self.assertRaisesRegex(ValueError, "N32 closure module differs from its V34/D48 render"):
                    spec.check_n32_closure_source(source.replace(text, text.replace(before, after, 1), 1))
        for before, after in (("    use super::*;\n", "    use super::{Wide, kani};\n"),
                              ("use super::super::super::{StableSmallSortTypeImpl, UnstableSmallSortTypeImpl};",
                               "use super::super::super::UnstableSmallSortTypeImpl;")):
            with self.subTest(import_line=before):
                with self.assertRaisesRegex(ValueError, "render"):
                    spec.check_n32_closure_source(source.replace(before, after, 1))
        with self.assertRaisesRegex(ValueError, "declaration missing or ambiguous"):
            spec.check_n32_closure_source(source.replace(spec.N32_CLOSURE_DECLARATION, "mod n32_closure {\n", 1))
        for later in ("\n#[cfg(kani_later)]\nmod later {\n}\n", "fn trailing() {}\n"):
            with self.assertRaisesRegex(ValueError, "render"):
                spec.check_n32_closure_source(source + later)
        # The pilot gate still binds its own revision: the closure file is not a pilot-closing file.
        with self.assertRaisesRegex(ValueError, "declaration missing"):
            spec.check_n32_pilot_source(source)

    def test_n32_wide_witness_gate_recomputes_both_permutations_bounds_and_canaries(self):
        source = self.n32_closure_file()
        geometry = spec.LITERAL_WITNESSES[spec.N32_CLOSURE_PREFIX]
        checked = spec.check_literal_witness_source(source, geometry)
        self.assertEqual([index - 1 for index in checked["expected"]],
                         [1, 3, 17, 19, 0, 2, *range(4, 17), 18, *range(20, 32)])
        self.assertEqual([index - 1 for index in checked["corrupted"]],
                         [1, 17, 3, 19, 0, 2, *range(4, 17), 18, *range(20, 32)])
        marker = source.index(spec.N32_WIDE_WITNESS_MARKER)
        head, tail = source[:marker], source[marker:]
        for before, after, message in (
            ("for i in 1..32 {", "for i in 1..33 {", "literal loop bounds"),
            ("    #[kani::unwind(36)]\n    fn gen_n32_wide", "    #[kani::unwind(31)]\n    fn gen_n32_wide", "literal loop bounds"),
            ("small_sort(&mut v[1..33], &mut less)", "small_sort(&mut v[1..32], &mut less)", "call range"),
            ("        input_record(1, 4),\n", "        input_record(0, 4),\n", "INPUT length, keys"),
            ("        input_record(0, 17),\n", "        input_record(1, 17),\n", "INPUT length, keys"),
            ("tag: 32, payload", "tag: 16, payload", "canary literals"),
            ("INPUT[2], INPUT[4], INPUT[18], INPUT[20], INPUT[1]", "INPUT[2], INPUT[18], INPUT[4], INPUT[20], INPUT[1]",
             "EXPECTED order"),
            ("INPUT[2], INPUT[18], INPUT[4], INPUT[20], INPUT[1]", "INPUT[2], INPUT[4], INPUT[18], INPUT[20], INPUT[1]",
             "CORRUPTED order"),
            ("v[2].tag == 3 && v[3].tag == 17", "v[2].tag == 3 && v[3].tag == 19", "swap pair"),
            ("v[2].tag < 16 && v[3].tag >= 16", "v[2].tag < 3 && v[3].tag >= 3", "tie cover"),
            ("        v[2] = v[3];\n        v[3] = left;\n", "        v[2] = v[4];\n        v[4] = left;\n", "exchange"),
            ("same_wide(v[33], RIGHT), \"GEN_N32_WIDE_AFTER_FRAME\"",
             "same_wide(v[32], RIGHT), \"GEN_N32_WIDE_AFTER_FRAME\"", "frame indices"),
            ("        let mut v = INPUT;\n", "        let mut v = INPUT;\n        v[3].key = kani::any();\n", "kani::any"),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(tail.count(before), 1)
                with self.assertRaisesRegex(ValueError, f"N32 .*{message}"):
                    spec.check_literal_witness_source(head + tail.replace(before, after, 1), geometry)
        # Tags 16 and 17 are active N32 records: the historical canaries would be indistinguishable.
        historical = geometry | {"left": spec.N10_WITNESS_LEFT, "right": spec.N10_WITNESS_RIGHT}
        relabelled = tail.replace("tag: 32, payload", "tag: 16, payload", 1).replace("tag: 33, payload", "tag: 17, payload", 1)
        with self.assertRaisesRegex(ValueError, "N32 records are not distinguishable from the canaries"):
            spec.check_literal_witness_source(head + relabelled, historical)
        with self.assertRaisesRegex(ValueError, "N32 swap is not one adjacent cross-half pair"), \
                patch.object(spec, "N32_WITNESS_SWAP", (0, 1)):
            spec.check_literal_witness_source(source, geometry)
        # The marker cannot move ahead of the u64 control: the tail would then carry nondeterminism.
        moved = source.replace(spec.N32_WIDE_WITNESS_MARKER, "", 1).replace(
            "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_u64_s8_l48_full",
            spec.N32_WIDE_WITNESS_MARKER + "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_u64_s8_l48_full", 1)
        with self.assertRaisesRegex(ValueError, "N32 witness body contains"):
            spec.check_literal_witness_source(moved, geometry)

    def test_n32_closure_native_coordinates_and_copy_sites_bind_the_frozen_roster(self):
        rows = self.frozen["roster"]
        sites = rows[1]["native_evidence"]["copy_sites"]
        smallsort = [""] * 1100
        for site in sites:
            smallsort[site["line"] - 1] = " " * (site["column"] - 1) + site["token"]
        comparator_line, comparator_column = spec.COMPARATOR_COORDINATE
        u64_line, u64_column = spec.U64_COMPARATOR_COORDINATE
        blobs = {
            f"library/{spec.PILOT_MODULE_FILE}": self.n32_closure_file().encode(),
            f"library/{spec.SMALLSORT_FILE}": "\n".join(smallsort).encode() + b"\n",
            f"library/{spec.COMPARATOR_FILE}": (b"\n" * (comparator_line - 1) + b" " * (comparator_column - 1)
                                                 + f'crate::kani::cover(true, "{spec.COMPARATOR_LABEL}");\n'.encode()),
            f"library/{spec.U64_N13_FILE}": (b"\n" * (u64_line - 1) + b" " * (u64_column - 1)
                                             + f'kani::cover(true, "{spec.U64_COMPARATOR_LABEL}");\n'.encode()),
        }

        def check(changed_rows=rows, **changes):
            with patch.object(spec, "git_blob", side_effect=lambda _std, _rev, path: changes.get(path, blobs[path])):
                return spec.check_native_coordinates(self.std, spec.OVERLAY[0], changed_rows,
                                                     prefix=spec.N32_CLOSURE_PREFIX, module_file=spec.PILOT_MODULE_FILE)

        self.assertTrue(check())
        module = f"library/{spec.PILOT_MODULE_FILE}"
        # Reached sites only: dropping the fill copy, adding the unreached shift or guard, or S8 sites on a control.
        shift = {"file": spec.SMALLSORT_FILE, "line": 722, "column": 13,
                 "token": "ptr::copy_nonoverlapping(sift, gap_guard.dst, 1);"}
        for index, copy_sites in ((0, sites), (1, rows[0]["native_evidence"]["copy_sites"]),
                                  (2, [*sites[:5], shift, *sites[5:]]), (2, sites[:-1])):
            with self.subTest(copy_sites=index, count=len(copy_sites)):
                bad = deepcopy(rows)
                bad[index]["native_evidence"]["copy_sites"] = copy_sites
                with self.assertRaisesRegex(ValueError, "actual typed-copy sites differ"):
                    check(bad)
        for index, label in ((1, "GEN_N32_STABLE_U64_MULTIPLICITY"), (2, "GEN_N32_WIDE_STABLE_EQUAL_KEYS")):
            with self.subTest(failure=label):
                bad = deepcopy(rows)
                bad[index]["expected_failure"]["line"] += 1
                with self.assertRaisesRegex(ValueError, "failure coordinate differs"):
                    check(bad)
                bad = deepcopy(rows)
                bad[index]["expected_failure"]["line"] += 1
                bad[index]["native_evidence"]["coordinates"][label]["line"] += 1
                with self.assertRaisesRegex(ValueError, f"{label}: expected"):
                    check(bad)
        bad = deepcopy(rows)
        bad[0]["native_evidence"]["coordinates"]["GEN_N32_U64_S8_L48_SORTED"]["function"] += "_other"
        with self.assertRaisesRegex(ValueError, "native function or class"):
            check(bad)
        bad = deepcopy(rows)
        bad[2]["native_evidence"]["coordinates"]["GEN_N16_WIDE_COMPARATOR_CALLED"]["line"] = 36
        with self.assertRaisesRegex(ValueError, "GEN_N16_WIDE_COMPARATOR_CALLED: expected"):
            check(bad)
        # Every labelled call of the module needs its row; a lost cover or post leaves a call unbound.
        with self.assertRaisesRegex(ValueError, "extra or missing labelled calls"):
            check(rows[:-1])
        bad = deepcopy(rows)
        del bad[2]["native_evidence"]["coordinates"]["GEN_N32_WIDE_WITNESS_CROSS_HALF_TIE"]
        with self.assertRaisesRegex(ValueError, "extra or missing labelled calls"):
            check(bad)
        bad = deepcopy(rows)
        bad[1]["selector"] = spec.N32_CLOSURE_PREFIX + "gen_n32_stable_u64_witness_corrupt"
        with self.assertRaisesRegex(ValueError, "source root kind or unwind differs"):
            check(bad)
        with self.assertRaisesRegex(ValueError, "render"):
            check(**{module: blobs[module] + b'fn extra() {\n    kani::cover(true, "GEN_N32_EXTRA");\n}\n'})

    def test_source_coordinate_gate_reads_call_indentation(self):
        source = (
            b"fn check() {\n"
            b"    if predicate {\n"
            b"        kani::cover(\n"
            b'            predicate, "SENTINEL",\n'
            b"        );\n"
            b"    }\n"
            b'    kani::assert(predicate, "POST");\n'
            b"}\n"
        )
        module_path = f"library/{spec.MODULE_FILE}"
        comparator_path = f"library/{spec.COMPARATOR_FILE}"
        comparator_line, comparator_column = spec.COMPARATOR_COORDINATE
        comparator = (b"\n" * (comparator_line - 1) + b" " * (comparator_column - 1)
                      + f'crate::kani::cover(true, "{spec.COMPARATOR_LABEL}");\n'.encode())
        u64_file = f"library/{spec.U64_N13_FILE}"
        u64_line, u64_column = spec.U64_COMPARATOR_COORDINATE
        u64_comparator = (b"\n" * (u64_line - 1) + b" " * (u64_column - 1)
                          + f'kani::cover(true, "{spec.U64_COMPARATOR_LABEL}");\n'.encode())
        blobs = {module_path: source, comparator_path: comparator, u64_file: u64_comparator}
        coordinates = {
            "SENTINEL": {"file": spec.MODULE_FILE, "line": 3, "column": 9,
                         "function": spec.PREFIX + "check", "class": "cover"},
            "POST": {"file": spec.MODULE_FILE, "line": 7, "column": 5,
                     "function": spec.PREFIX + "check", "class": "assertion"},
            spec.COMPARATOR_LABEL: {"file": spec.COMPARATOR_FILE, "line": comparator_line,
                                    "column": comparator_column, "class": "cover"},
        }
        row = {"id": "TEST", "covers": ["SENTINEL", spec.COMPARATOR_LABEL],
               "native_evidence": {"coordinates": coordinates}}
        with patch.object(spec, "git_blob", side_effect=lambda _checkout, _revision, path: blobs[path]):
            self.assertTrue(spec.check_native_coordinates(self.std, spec.OVERLAY[0], [row]))

            for label, old_indent, new_indent in (
                ("SENTINEL", b"        kani::cover", b"    kani::cover"),
                ("POST", b"    kani::assert", b"        kani::assert"),
            ):
                changed_row = deepcopy(row)
                changed_row["native_evidence"]["coordinates"][label]["column"] += 1
                with self.subTest(label=label, mutation="column + 1"):
                    with self.assertRaisesRegex(ValueError, f"{label}: expected .*source has"):
                        spec.check_native_coordinates(self.std, spec.OVERLAY[0], [changed_row])

                with self.subTest(label=label, mutation="source indentation"):
                    with (patch.dict(blobs, {module_path: source.replace(old_indent, new_indent)}),
                          self.assertRaisesRegex(ValueError, f"{label}: expected .*source has")):
                        spec.check_native_coordinates(self.std, spec.OVERLAY[0], [row])

            with (patch.dict(blobs, {comparator_path: b"\n" + comparator}),
                  self.assertRaisesRegex(ValueError, "comparator cover coordinate")):
                spec.check_native_coordinates(self.std, spec.OVERLAY[0], [row])

            for key, value in (("function", spec.PREFIX + "other"), ("class", "cover")):
                changed_row = deepcopy(row)
                changed_row["native_evidence"]["coordinates"]["POST"][key] = value
                with self.assertRaisesRegex(ValueError, "native function or class differs"):
                    spec.check_native_coordinates(self.std, spec.OVERLAY[0], [changed_row])

            failure = {"label": "POST", **coordinates["POST"]}
            self.assertTrue(spec.check_native_coordinates(self.std, spec.OVERLAY[0], [row | {
                "expected_failure": failure,
            }]))
            with self.assertRaisesRegex(ValueError, "failure coordinate differs"):
                spec.check_native_coordinates(self.std, spec.OVERLAY[0], [row | {
                    "expected_failure": failure | {"column": 9},
                }])

    def test_consumer_rejects_wrong_intermediate_source_layout(self):
        consumer = spec.U64_N26_N32_CONSUMER_MODULE
        with (patch.object(spec, "git", return_value="M\tcore/Cargo.toml"),
              self.assertRaisesRegex(ValueError, "changed out-of-scope paths")):
            spec.check_opt_in_layout(self.std, spec.N26_N32_PROVIDERS_OVERLAY[0],
                                     spec.OVERLAY[0], consumer, (spec.CFG[19], spec.CFG[-1]),
                                     inline_cfg=True)

    def test_runtime_source_gate_requires_historical_blobs(self):
        request = deepcopy(self.frozen)
        del request["source_bindings"]["historical_blobs"]
        with patch.object(spec, "git") as lookup:
            with self.assertRaisesRegex(ValueError, "missing historical_blobs in source bindings"):
                spec.check_source_bindings(self.std, request)
        lookup.assert_not_called()

    def test_runtime_source_gate_rejects_wrong_exact_column(self):
        file = "core/src/example.rs"
        commit, blob = "1" * 40, "2" * 40
        schedules = {key: self.frozen["source_bindings"][key] for key in ("sort9_swaps", "sort13_swaps")}
        sort = ""
        first_calls = {}
        for length in (9, 13):
            schedule = schedules[f"sort{length}_swaps"]
            calls = [" " * (pair["column"] - 1) + f"swap_if_less(v_base, {pair['a']}, {pair['b']}, is_less);"
                     for pair in schedule]
            sort += "\n" * (schedule[0]["line"] - 2 - sort.count("\n"))
            sort += f"fn sort{length}_optimal<T, F>() {{\n" + "\n".join(calls) + "\n}\n"
            first_calls[length] = calls[0]
        sources = {f"library/{file}": b"first\n  call();\n",
                   f"library/{spec.SMALLSORT_FILE}": sort.encode()}
        bindings = {"blobs": {file: blob},
                    "historical_blobs": {},
                    **schedules,
                    "coordinates": [{"file": file, "line": 2, "column": 3, "token": "call()"}]}
        request = {"overlay": [commit, "3" * 40], "source_bindings": bindings}
        with (patch.object(spec, "git", return_value=blob),
              patch.object(spec, "git_blob", side_effect=lambda _std, _commit, path: sources[path])):
            self.assertEqual(spec.check_source_bindings(self.std, request), bindings)
            for length, original in first_calls.items():
                wrong = sort.replace(original, original.replace(", is_less);", ", other);"), 1).encode()
                with (patch.dict(sources, {f"library/{spec.SMALLSORT_FILE}": wrong}),
                      self.assertRaisesRegex(ValueError, f"actual sort{length} swap schedule mismatch")):
                    spec.check_source_bindings(self.std, request)
            bindings["coordinates"][0]["column"] += 1
            with self.assertRaisesRegex(ValueError, "pinned source coordinate differs"):
                spec.check_source_bindings(self.std, request)
        with patch.object(spec, "git", return_value="4" * 40):
            with self.assertRaisesRegex(ValueError, "pinned source blob differs"):
                spec.check_source_bindings(self.std, request)

    def test_full_event_and_sole_parent_tree_guard(self):
        path = self.state / "event.json"
        sha, tree = "4" * 40, "5" * 40
        env = {"GITHUB_REPOSITORY": spec.FORK, "GITHUB_EVENT_NAME": "push", "GITHUB_REF": spec.REF,
               "GITHUB_SHA": sha, "GITHUB_EVENT_PATH": str(path), "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
               spec.TRIGGER_TREE_ENV: tree}
        event = {"after": sha, "ref": spec.REF, "repository": {"full_name": spec.FORK}, "deleted": False}
        run.dump(path, event)
        with patch.object(spec, "git", side_effect=[f"{sha} {spec.TRIGGER_PARENT}", tree]), \
                patch.object(spec, "identity", return_value={"commit": sha, "tree": tree}):
            trigger = spec.check_trigger(env=env)
            self.assertEqual((trigger["parent"], trigger["tree"]), (spec.TRIGGER_PARENT, tree))
        for update in ({"GITHUB_REF": spec.REF + "1"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                       {"GITHUB_REPOSITORY": "model-checking/kani"}, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                spec.check_trigger(env=env | update)
        for update in ({"after": "6" * 40}, {"ref": spec.REF + "1"}, {"deleted": True}, {"repository": {}}):
            with self.subTest(update=update), patch.object(spec, "git", return_value=f"{sha} {spec.TRIGGER_PARENT}"):
                run.dump(path, event | update)
                with self.assertRaisesRegex(ValueError, "trigger SHA or sole"):
                    spec.check_trigger(env=env)
        run.dump(path, event)
        for parents in ("", "6" * 40, f"{spec.TRIGGER_PARENT} {'6' * 40}"):
            with patch.object(spec, "git", return_value=f"{sha} {parents}"), self.assertRaisesRegex(ValueError, "sole"):
                spec.check_trigger(env=env)
        for expected in (None, "", "6" * 39, "g" * 40):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "approved trigger tree"):
                spec.check_trigger(env=env | {spec.TRIGGER_TREE_ENV: expected})
        with patch.object(spec, "git", side_effect=[f"{sha} {spec.TRIGGER_PARENT}", "6" * 40]), \
                self.assertRaisesRegex(ValueError, "trigger tree mismatch"):
            spec.check_trigger(env=env)

    def test_pins_cli_rejects_changed_tree_with_matching_trailer_and_missing_pin(self):
        workspace = self.state / "workspace"
        checkout = workspace / "control"
        checkout.mkdir(parents=True)
        state = self.state / "ch8-rev2-gen-stable-n32-closure"
        state.mkdir()
        output = self.state / "outputs"
        event = self.state / "push.json"
        env = os.environ | {
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": spec.git(spec.REPO, "rev-parse", "--path-format=absolute",
                                                           "--git-path", "objects"),
            "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(self.state), "REV2_STATE": str(state),
            "GITHUB_REPOSITORY": spec.FORK, "GITHUB_EVENT_NAME": "push", "GITHUB_REF": spec.REF,
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "1", "GITHUB_EVENT_PATH": str(event),
            "GITHUB_OUTPUT": str(output),
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
        env.pop(spec.TRIGGER_TREE_ENV, None)

        def git(*args):
            return subprocess.check_output(["git", "-C", str(checkout), *args], env=env, text=True).strip()

        git("init", "-q")
        (checkout / ".git/shallow").write_text(spec.TRIGGER_PARENT + "\n")
        sources = checkout / "ch8-cal1"
        sources.mkdir()
        for name in ("run.py", "report.py", "request.py", "setup_diagnostics.py", "supervisor.py",
                     "stdout_relay.py", "cbmc_relay.py", "native_metrics.py", "CI-REQUEST.json", "std-overlay.bundle"):
            shutil.copyfile(spec.HERE / name, sources / name)

        def trigger():
            git("add", "ch8-cal1")
            tree = git("write-tree")
            sha = git("-c", "user.name=Tiramisu-Cake", "-c", "user.email=igkharin@gmail.com", "commit-tree",
                      tree, "-p", spec.TRIGGER_PARENT, "-m", "Synthetic tree guard fixture [skip ci]",
                      "-m", f"REV2-Control-Tree: {tree}")
            git("checkout", "-q", "--detach", sha)
            self.assertEqual(git("rev-list", "--parents", "-n", "1", "HEAD"), f"{sha} {spec.TRIGGER_PARENT}")
            self.assertEqual(git("show", "-s", "--format=%(trailers:key=REV2-Control-Tree,valueonly)", "HEAD"), tree)
            run.dump(event, {"after": sha, "ref": spec.REF, "repository": {"full_name": spec.FORK}, "deleted": False})
            env["GITHUB_SHA"] = sha
            return tree

        def entrypoint(command):
            script = ("import runpy, sys, time; from pathlib import Path; time.monotonic = lambda: 61; "
                      "path = sys.argv.pop(1); sys.path.insert(0, str(Path(path).parent)); "
                      "sys.argv[0] = path; runpy.run_path(path, run_name='__main__')")
            return subprocess.run([sys.executable, "-B", "-c", script, str(sources / "run.py"), command],
                                  env=env, capture_output=True, text=True)

        (state / "epoch").write_text("60")
        reviewed = trigger()
        env["CH8_REV2_N26_N31_COPY_BACK_TRIGGER_TREE"] = reviewed
        missing = entrypoint("pins")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("approved trigger tree is missing or malformed", missing.stderr)
        env[spec.TRIGGER_TREE_ENV] = reviewed.upper()
        result = entrypoint("pins")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("trigger_admitted=true", output.read_text().splitlines())
        admission = spec.read(state / "trigger.json")
        self.assertEqual((admission["tree"], admission["approved_tree"]), (reviewed, reviewed))
        initial_output = output.read_bytes()

        for pin, message in (("", "approved trigger tree is missing or malformed"),
                             ("b4a386280f9a01b72e435ce0fe0546353fd757c4", "trigger tree mismatch"),
                             ("6" * 40, "trigger tree mismatch")):
            env[spec.TRIGGER_TREE_ENV] = pin
            for command in ("pins", "sources", "finish"):
                with self.subTest(command=command, pin=pin):
                    result = entrypoint(command)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
        env[spec.TRIGGER_TREE_ENV] = reviewed
        with (sources / "run.py").open("a") as compromised:
            compromised.write("\n# Synthetic tree mutation\n")
        self.assertNotEqual(trigger(), reviewed)
        for command in ("pins", "sources", "finish"):
            result = entrypoint(command)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("trigger tree mismatch", result.stderr)
        self.assertEqual(output.read_bytes(), initial_output)
        self.assertEqual(spec.read(state / "trigger.json"), admission)
        self.assertFalse((state / "artifact").exists())

        shutil.copyfile(spec.HERE / "run.py", sources / "run.py")
        self.assertEqual(trigger(), reviewed)
        result = entrypoint("finish")
        self.assertEqual(result.returncode, 0, result.stderr)
        index = spec.read(state / "artifact" / "index.json")
        self.assertEqual(index["trigger"], admission)
        self.assertEqual(index["clocks"]["epoch"], 60)
        self.assertEqual([(slot["id"], slot["outcome"]) for slot in index["slots"]],
                         [(key, "NOT_STARTED") for key in ROOTS])
        run.dump(state / "trigger.json", admission | {"parent": "6" * 40})
        result = entrypoint("finish")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trigger differs from the initial checkout receipt", result.stderr)

    def test_exact_discovery_mismatches(self):
        path = self.state / "list.json"
        good = self.list_document()
        run.dump(path, good)
        entries = run.read_list(path)
        selected = run.check_overlay_roster(entries, self.frozen["roster"])
        self.assertEqual(len(selected), 196)
        duplicate = entries[0].copy()
        wrong_kind = duplicate | {"kind": "standard-harnesses" if duplicate["kind"] == "contract-harnesses"
                                  else "contract-harnesses"}
        wrong_file = duplicate | {"file": "wrong.rs"}
        other_module = duplicate | {"selector": spec.PREFIX + "unexpected", "file": spec.MODULE_FILE}
        check = next(item for item in entries if item["selector"] == spec.GEOMETRIES_PREFIX + "s13_b13_l13_swap")
        wrong_check_kind = [item if item != check else item | {"kind": "standard-harnesses"} for item in entries]
        consumer = next(item for item in entries if item["selector"] == self.frozen["roster"][1]["selector"])
        self.assertEqual(consumer["kind"], "standard-harnesses")
        wrong_consumer_kind = [item if item != consumer else item | {"kind": "contract-harnesses"}
                               for item in entries]
        witness = next(item for item in entries if item["selector"] == self.frozen["roster"][0]["selector"])
        self.assertEqual(witness["kind"], "standard-harnesses")
        wrong_witness_kind = [item if item != witness else item | {"kind": "contract-harnesses"} for item in entries]
        wrong_n = [item if item != consumer else item | {"selector": spec.PILOT_PREFIX + "unexpected"}
                   for item in entries]
        unexpected_name = duplicate | {"selector": "smallsort::elsewhere"}
        inherited_only = [item for item in entries if item["selector"].startswith(spec.PROVIDER_PREFIX)]
        for bad in (entries[:-1], inherited_only, entries + [duplicate], entries[1:] + [wrong_kind],
                    entries[1:] + [wrong_file],
                    entries + [other_module], entries + [unexpected_name], wrong_check_kind, wrong_consumer_kind,
                    wrong_witness_kind, wrong_n):
            with self.assertRaisesRegex(ValueError, "exact discovery"):
                run.check_overlay_roster(bad, self.frozen["roster"])
        for historic_selector in (spec.CLOSE_DISCOVERY[0][1], spec.WIDE_WITNESS_SELECTOR, spec.N10_WITNESS_SELECTOR,
                                  spec.N12_WITNESS_SELECTOR, spec.N14_WITNESS_SELECTOR, spec.WIDE_N12_N14_DISCOVERY[0][1],
                                  spec.N32_DISCOVERY[0][1], spec.N32_DISCOVERY[3][1]):
            missing_historic = [item for item in entries if item["selector"] != historic_selector]
            self.assertEqual(len(missing_historic), len(entries) - 1)
            with self.assertRaisesRegex(ValueError, "exact discovery"):
                run.check_overlay_roster(missing_historic, self.frozen["roster"])
        # Exactly the three new plain roots are added. Historical roots, a Check in a plain position,
        # a swapped order or a partial roster cannot stand in for them.
        rows = self.frozen["roster"]
        historical = self.frozen["source_bindings"]["n32_pilot_roster"]
        for active in ([historical[0], *rows[1:]], [*rows[:2], self.frozen["source_bindings"]["wide_n12_n14_roster"][-1]],
                       [rows[0] | {"check": "actual_merge_up_u64_n32"}, *rows[1:]],
                       [*rows[:2], rows[2] | {"check": "actual_merge_up_wide_n32"}],
                       [rows[1], rows[0], rows[2]], [rows[0], rows[2], rows[1]],
                       rows[1:], rows[:2], rows + rows[:1]):
            with self.assertRaisesRegex(ValueError, "N32 closure additions"):
                run.check_overlay_roster(entries, active)
        self.assertEqual(run.discovery_additions(rows), rows)
        misplaced = [item if item != consumer else item | {"file": f"smallsort/verify/{spec.MERGE_PAIR_FIXED_MODULE}.rs"}
                     for item in entries]
        self.assertRaisesRegex(ValueError, "exact discovery", run.check_overlay_roster,
                               misplaced, self.frozen["roster"])
        self.assertRaisesRegex(ValueError, "exact discovery", run.check_overlay_roster, entries, ())
        for target in good["contracts"]:
            for change in ({"function": "bad::target"}, {"file": "other.rs"}, {"harnesses": []},
                           {"harnesses": target["harnesses"] * 2}):
                with self.subTest(target=target["function"], change=change):
                    doc = deepcopy(good)
                    doc["contracts"][good["contracts"].index(target)].update(change)
                    run.dump(path, doc)
                    with self.assertRaisesRegex(ValueError, "Check object mismatch"):
                        run.check_overlay_roster(run.read_list(path), self.frozen["roster"])
        for enabled in (False, True):
            with self.subTest(consumer_enabled=enabled):
                baseline = self.list_document(consumer_enabled=enabled)
                rows = self.frozen["roster"] if enabled else ()
                run.dump(path, baseline)
                selected = run.check_overlay_roster(run.read_list(path), rows)
                self.assertEqual(len(selected), 196 if enabled else 193)
                inherited = {item["selector"]: item["targets"][0] for item in selected
                             if item["selector"] in spec.MERGE_CHECKS}
                self.assertEqual(inherited, spec.MERGE_CHECKS)
                selectors = [spec.CLOSE_DISCOVERY[0][1], spec.WIDE_WITNESS_SELECTOR, spec.N10_WITNESS_SELECTOR,
                             spec.N12_WITNESS_SELECTOR, spec.N14_WITNESS_SELECTOR,
                             *(selector for _, selector in spec.N32_DISCOVERY[:3])]
                if enabled:
                    selectors.extend(row["selector"] for row in self.frozen["roster"])
                for selector in selectors:
                    targeted = deepcopy(baseline)
                    self.assertTrue(any(selector in names for names in targeted["standard-harnesses"].values()))
                    targeted["contracts"].append({"function": spec.MERGE_PREFIX + "actual_pair_step_n26",
                                                   "file": spec.MERGE_FILE, "harnesses": [selector]})
                    run.dump(path, targeted)
                    with self.assertRaises(ValueError) as caught:
                        run.check_overlay_roster(run.read_list(path), rows)
                    self.assertEqual(str(caught.exception), f"standard harness has a contract target: {selector}")

    def test_clock_rejects_invalid_job_epoch(self):
        self.enterContext(patch.object(run.time, "monotonic", return_value=1))
        path = self.state / "epoch"
        for epoch in ("-1", "0", "nan", "inf", "1.01"):
            with self.subTest(epoch=epoch):
                path.write_text(epoch)
                with self.assertRaisesRegex(ValueError, "invalid job epoch"):
                    run.clocks(self.state)
        path.write_text("1")
        self.assertEqual(run.clocks(self.state)["epoch"], 1)

    def test_clock_and_latest_start(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        clocks = run.clocks(self.state)
        self.assertEqual(list(clocks["latest_starts"].values()),
                         [60 + offset for offset in spec.LATEST_START_OFFSETS.values()])
        self.assertEqual((clocks["slots_deadline"], clocks["verify_deadline"], clocks["finalize_deadline"],
                          clocks["reserve_deadline"], clocks["job_deadline"]),
                         (3975, 4095, 4815, 5175, 6060))
        self.assertEqual(clocks["latest_starts"], dict(zip(spec.SLOT_IDS, (3360, 3565, 3770))))
        slot = self.slots[-1]
        last = clocks["latest_starts"][slot[0]]
        clock.return_value = last
        with patch.object(run, "invoke", return_value=COMPLETED):
            record = run.measure_slot(self.state, self.std, self.tool, self.frozen, slot, last)
        self.assertEqual(record["started_monotonic"], last)
        self.assertEqual(record["slot_deadline_monotonic"] + 10, clocks["slots_deadline"])
        self.assertEqual(record["receipt_deadline_monotonic"], last + 5)
        clock.return_value = last + .01
        with patch.object(run, "invoke") as invoke:
            record = run.measure_slot(self.state, self.std, self.tool, self.frozen, slot, last)
        invoke.assert_not_called()
        self.assertEqual(record["reason"], "INSUFFICIENT_LATEST_START_WINDOW")
        self.assertEqual(record["latest_start_monotonic"], last)

    def test_prelaunch_receipt_refusal_never_invokes_supervisor(self):
        with (patch.object(run.time, "monotonic", return_value=60),
              patch.object(run, "save_receipt", side_effect=run.ReceiptDeadlineExceeded),
              patch.object(run, "invoke") as invoke):
            record = run.measure_slot(self.state, self.std, self.tool, self.frozen, self.slots[0], 61)
        invoke.assert_not_called()
        self.assertEqual(record["outcome"], "NOT_STARTED")
        self.assertEqual(record["reason"], "PRELAUNCH_RECEIPT_UNAVAILABLE")
        self.assertTrue(record["receipt_write_deferred"])

    def test_missed_first_latest_start_does_not_latch_later_slots(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=3350))
        (self.state / "epoch").write_text("60")
        run.dump(self.state / "setup.json", {"status": "READY"})
        slots = list(reversed(self.synthetic_slots()))
        boundaries = run.clocks(self.state)
        boundaries["slots_deadline"] = 3740
        boundaries["verify_deadline"] = 3860
        boundaries["latest_starts"] = {slots[0][0]: 3360, slots[1][0]: 3400}

        def slow_probe():
            clock.return_value = 3361
            return None

        with (patch.object(run, "expected_slots", return_value=slots), patch.object(spec, "identity"),
              patch("telemetry.PssProbe", side_effect=slow_probe),
              patch.object(run, "invoke", return_value=COMPLETED) as invoke,
              patch.object(results, "project", return_value={"outcome": "RSS_LIMIT", "complete": True}),
              patch.object(run, "close_measurements") as close):
            run.measure(self.state, self.std, self.tool, self.frozen, boundaries,
                        step_deadline=boundaries["verify_deadline"] + run.MEASUREMENT_JOURNAL_SECONDS)
            report.finish(self.state, self.frozen, "Linux")
        self.assertEqual(invoke.call_count, 1)
        close.assert_called_once()
        records = [self.read_receipt(slot[0]) for slot in slots]
        self.assertEqual(records[0]["reason"], "INSUFFICIENT_LATEST_START_WINDOW")
        self.assertNotIn("child", records[0])
        self.assertTrue(all(row.get("child", {}).get("reaped") is True for row in records[1:]))

    def test_setup_preflight_then_exact_cfg_off_and_on_lists(self):
        for failure in (None, "witness", "compiler", "roster", "inherited", "cfg_off"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                state = Path(temp)
                seen = []

                def supervise(argv, *, directory, deadline, env, nominal_kib, reserve_kib, **unused):
                    phase = directory.name
                    seen.append(phase)
                    self.assertEqual(nominal_kib, 10 * spec.GIB_KIB)
                    self.assertEqual(reserve_kib, 2 * spec.GIB_KIB)
                    self.assertTrue(Path(env["TMPDIR"]).is_dir())
                    # Build, compile preflight and both lists keep the stock PATH: the relay serves no stage.
                    self.assertEqual(env.get("PATH"), os.environ.get("PATH"))
                    self.assertNotIn("relay", env.get("PATH", ""))
                    flags = spec.CFG[:-1] if phase == "off" else spec.CFG
                    cfg = " ".join(f"--cfg={flag}" for flag in flags)
                    self.assertEqual(env.get("RUSTFLAGS"), cfg if phase != "build" else None)
                    if phase == "overlay-compile":
                        self.assertEqual(deadline, 1180)
                        self.assertTrue({"--no-codegen", "--only-codegen", "--quiet", "--no-assert-contracts"} <= set(argv))
                        if failure == "compiler":
                            (directory / "stderr.log").write_text("error[E0000]: test fixture\nerror: could not compile `core`\n")
                            return COMPLETED | {"exit_code": 1}
                        if failure != "witness":
                            (directory / "stderr.log").write_text(
                                f"Running `/tool/kani-compiler --crate-name core -Z no-codegen --cfg=kani {cfg}`\n")
                    else:
                        self.assertEqual(deadline, 1250)
                    if phase in {"off", "on"}:
                        self.assertEqual(argv[1], "list")
                        doc = self.list_document(consumer_enabled=phase == "on" or failure == "cfg_off")
                        if failure == "roster" and phase == "on":
                            next(iter(doc["contract-harnesses"].values())).pop()
                        if failure == "inherited" and phase == "on":
                            doc["standard-harnesses"]["smallsort/verify/cal1.rs"][0] += "_changed"
                        run.dump(directory / "kani-list.json", doc)
                    return COMPLETED

                with (patch.object(run.time, "monotonic", return_value=1000), patch.object(spec, "identity", return_value={}),
                      patch.object(spec, "git") as git, patch.object(tool, "attest", return_value={}),
                      patch.object(run.supervisor, "run", side_effect=supervise)):
                    if failure:
                        with self.assertRaises(run.RunError):
                            run.prepare(state, self.std, self.tool, self.frozen, {"epoch": 990, "prepare_deadline": 1250})
                    else:
                        run.prepare(state, self.std, self.tool, self.frozen, {"epoch": 990, "prepare_deadline": 1250})
                git.assert_called_once_with(self.std, "checkout", "--detach", spec.OVERLAY[0], deadline=1250)
                expected = ["build", "overlay-compile"]
                if failure not in {"witness", "compiler"}:
                    expected += ["off"]
                    if failure != "cfg_off":
                        expected += ["on"]
                self.assertEqual(seen, expected)
                setup = spec.read(state / "setup.json")
                self.assertEqual(setup["status"], "SETUP_ERROR" if failure else "READY")
                self.assertEqual((state / "discovery.json").is_file(), not failure)
                if failure is None:
                    discovery = spec.read(state / "discovery.json")
                    self.assertEqual(discovery["total_listed"] - discovery["cfg_off"]["total_listed"], 3)
                    self.assertEqual(discovery["cfg_off"]["cfg"], spec.CFG[:-1])
                    self.assertEqual(discovery["cfg"], spec.CFG)
                if failure == "compiler":
                    self.assertEqual(setup["overlay_compile"]["compilation_status"], "FAILED")
                    self.assertEqual(spec.read(state / "error.json")["primary_diagnostic"]["code"], "E0000")

    def test_partial_receipt_and_cutoff_report(self):
        for index, stop in enumerate(("TIMEOUT", "RSS_LIMIT")):
            state = self.state / stop
            slot = self.slots[0]
            selector = slot[2][0]["selector"]

            def supervise(argv, *, directory, deadline, nominal_kib, reserve_kib, diagnostics, **unused):
                active = spec.read(state / "artifact" / "slots" / slot[0] / "receipt.json")
                self.assertEqual(active["outcome"], "INCOMPLETE")
                self.assertEqual(active["cold_deadline_monotonic"] - active["started_monotonic"], 180)
                self.assertEqual(deadline - active["started_monotonic"],
                                 slot[3] - spec.LIMITS["receipt_seconds"])
                self.assertEqual(active["slot_deadline_monotonic"] - active["started_monotonic"], slot[3])
                self.assertEqual(nominal_kib, 4 * spec.GIB_KIB)
                self.assertEqual(reserve_kib, 2 * spec.GIB_KIB)
                diagnostics.observe({"verifier_pids": [5], "records": [{"pid": 5, "start_id": 8, "rss": 70}],
                                     "rss_kib": 100, "phase": "cbmc"}, 1060)
                diagnostics.observe({"verifier_pids": [5], "records": [{"pid": 5, "start_id": 8, "rss": 90}],
                                     "rss_kib": 99, "phase": "cbmc"}, 1061)
                log = (f"Checking harness {selector}...\n"
                       '[Kani] Running: `cbmc --object-bits 12 --unwind 36 "/tmp/x y/core.out"`\n'
                       "Starting Bounded Model Checking\nsize of program expression: 11 steps\n")
                if stop == "RSS_LIMIT":
                    log += "converting SSA\n13 variables, 26 clauses\n"
                    run.dump(directory / "export.json", {"run_state": "PARTIAL", "harnesses": []})
                (directory / "stdout.log").write_text(log + "partial line")
                (directory / "stderr.log").write_text("")
                return COMPLETED | {"stop_reason": stop, "exit_code": -15, "stdout_complete": False,
                                    "cold_wall_seconds": 61, "monotonic_observation_end": 1061,
                                    "last_observed_phase": "cbmc", "last_phase_monotonic": 1061, "peak_rss_kib": 100}

            with patch.object(run.time, "monotonic", return_value=1000), patch.object(run.supervisor, "run", side_effect=supervise):
                result = run.measure_slot(state, self.std, self.tool, self.frozen, slot, 1250)
            self.assertEqual(result["outcome"], stop)
            self.assertEqual(result["reason"], stop)
            self.assertTrue(result["censored"])
            self.assertFalse(result["projection_complete"])
            self.assertEqual(result["cold_wall_seconds"], 61)
            self.assertEqual(result["last_phase_monotonic"], 1061)
            self.assertEqual(result["resolved"][0]["resolved_unwind"], 36)
            self.assertEqual(result["memory_telemetry"]["group_peak"]["cbmc_rss_kib"], 70)
            self.assertEqual(result["memory_telemetry"]["cbmc_peak"]["group_rss_kib"], 99)
            metrics = result["native_metrics"]["streams"]["stdout"]
            self.assertIn("symex_steps", metrics["first_marker_by_kind"])
            self.assertEqual(metrics["cnf_status"], "UNOBSERVED_IN_PREFIX" if index == 0 else "OBSERVED")
            self.assertEqual(result["result_evidence"]["export"]["state"], "INCOMPLETE")
        for optional in (state / "artifact").glob("slots/*/projection.json"):
            optional.write_bytes(b"x" * spec.MIB)
        with patch.dict(spec.LIMITS, {"artifact_bytes": 3 * spec.MIB}):
            report.finish(state, self.frozen, "Linux")
        artifact = state / "artifact"
        summary = spec.read(artifact / "SUMMARY.json")
        index = spec.read(artifact / "index.json")
        self.assertEqual([row["outcome"] for row in summary["rows"]],
                         ["RSS_LIMIT"] + ["NOT_STARTED"] * (len(ROOTS) - 1))
        self.assertEqual(len(index["dropped_optional_members"]), 1)
        self.assertIn("initial 13 / 26", (artifact / "SUMMARY.md").read_text())
        self.assertEqual(index["members"]["SUMMARY.json"]["sha256"], spec.sha256(artifact / "SUMMARY.json"))
        self.assertFalse(any(path.endswith((".log", ".goto")) for path in index["members"]))
        self.assertEqual(spec.read(artifact / "slots" / slot[0] / "receipt.json")
                         ["native_metrics"]["initial_solve_cnf"]["clauses"], 26)

    def test_projection_failure_preserves_cutoff_and_reap(self):
        child = COMPLETED | {"stop_reason": "REAP_UNVERIFIED", "primary_stop_reason": "TIMEOUT", "reaped": False}
        with patch.object(run, "invoke", return_value=child), patch.object(results, "project", side_effect=ValueError("bad output")):
            record = run.measure_slot(self.state, self.std, self.tool, self.frozen, self.slots[0], run.time.monotonic() + 250)
        self.assertEqual(record["outcome"], "REAP_UNVERIFIED")
        self.assertTrue(record["censored"])
        self.assertEqual(record["child"]["primary_stop_reason"], "TIMEOUT")
        self.assertTrue(record["projection_skipped"])
        self.assertEqual(record["projection_status"], "REAP_UNVERIFIED")

    def test_final_attestation_requires_reap_and_tolerates_pss_failure(self):
        slots = self.synthetic_slots()
        for bad_reap in (False, True):
            with self.subTest(bad_reap=bad_reap), tempfile.TemporaryDirectory() as state_dir:
                state = Path(state_dir)
                run.dump(state / "setup.json", {"status": "READY"})
                launched = []

                def supervise(argv, *, directory, diagnostics, **unused):
                    key = directory.name
                    launched.append(key)
                    diagnostics.observe({"verifier_pids": [5], "records": [{"pid": 5, "start_id": 8, "rss": 70}],
                                         "rss_kib": 100, "phase": "cbmc"}, 43)
                    if bad_reap:
                        return COMPLETED | {"stop_reason": "REAP_UNVERIFIED", "primary_stop_reason": "TIMEOUT", "reaped": False}
                    return COMPLETED | {"stop_reason": "RSS_LIMIT"}

                with (patch.object(run, "expected_slots", return_value=slots),
                      patch.object(spec, "identity"), patch.object(run.supervisor, "run", side_effect=supervise),
                      patch("telemetry.Thread.start", side_effect=RuntimeError("no thread")),
                      patch.object(run, "close_measurements") as close,
                      patch.object(results, "project", return_value={"outcome": "RSS_LIMIT", "complete": True}) as project):
                    now = time.monotonic()
                    (state / "epoch").write_text(str(now))
                    boundaries = run.clocks(state)
                    boundaries["slots_deadline"] = now + 500
                    boundaries["verify_deadline"] = now + 620
                    boundaries["latest_starts"] = {slots[0][0]: now + 20, slots[1][0]: now + 250}
                    if bad_reap:
                        with self.assertRaisesRegex(run.RunError, "PROCESS_CLEANUP_COULD_NOT_BE_VERIFIED"):
                            run.measure(state, self.std, self.tool, self.frozen, boundaries,
                                        step_deadline=now + 650, gate_deadline=now + 300)
                        close.assert_not_called()
                        project.assert_not_called()
                    else:
                        run.measure(state, self.std, self.tool, self.frozen, boundaries,
                                    step_deadline=now + 650, gate_deadline=now + 300)
                        close.assert_called_once()
                    report.finish(state, self.frozen, "Linux")
                self.assertEqual(launched, [slot[0] for slot in slots[:1] if bad_reap] +
                                 ([] if bad_reap else [slot[0] for slot in slots]))
                if bad_reap:
                    for key in (slot[0] for slot in slots[1:]):
                        blocked = spec.read(state / "artifact" / "slots" / key / "receipt.json")
                        self.assertEqual((blocked["outcome"], blocked["reason"]),
                                         ("NOT_STARTED", "PROCESS_CLEANUP_COULD_NOT_BE_VERIFIED"))
                record = spec.read(state / "artifact" / "slots" / launched[0] / "receipt.json")
                self.assertEqual(record["child"]["reaped"], not bad_reap)
                self.assertEqual(record["outcome"], "REAP_UNVERIFIED" if bad_reap else "RSS_LIMIT")
                if bad_reap:
                    self.assertTrue(record["projection_skipped"])
                    self.assertEqual(record["projection_status"], "REAP_UNVERIFIED")
                    self.assertNotIn("memory_telemetry", record)
                else:
                    memory = record["memory_telemetry"]
                    self.assertEqual(memory["cbmc_peak"]["cbmc_rss_kib"], 70)
                    self.assertEqual(memory["cbmc_peak"]["pss"], {"pss_kib": None, "reason": "PROBE_START_FAILED"})

        for stop in ("RSS_LIMIT", "SAMPLER_ERROR"):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as state_dir:
                state = Path(state_dir)
                run.dump(state / "setup.json", {"status": "READY"})
                launched = []

                def supervise(argv, *, directory, **unused):
                    launched.append(directory.name)
                    return COMPLETED | {"stop_reason": stop, "reaped": True}

                with (patch.object(run, "expected_slots", return_value=slots),
                      patch.object(spec, "identity"), patch.object(run.supervisor, "run", side_effect=supervise),
                      patch("telemetry.Thread.start", side_effect=RuntimeError("no thread")),
                      patch.object(run, "close_measurements"),
                      patch.object(results, "project", return_value={"outcome": stop, "complete": True})):
                    now = time.monotonic()
                    (state / "epoch").write_text(str(now))
                    boundaries = run.clocks(state)
                    boundaries["slots_deadline"] = now + 500
                    boundaries["verify_deadline"] = now + 620
                    boundaries["latest_starts"] = {slots[0][0]: now + 20, slots[1][0]: now + 250}
                    with patch.object(run, "expected_slots", return_value=slots):
                        run.measure(state, self.std, self.tool, self.frozen, boundaries,
                                    step_deadline=now + 650, gate_deadline=now + 300)
                self.assertEqual(launched, [slot[0] for slot in slots])
                first = spec.read(state / "artifact" / "slots" / launched[0] / "receipt.json")
                self.assertEqual(first["child"]["reaped"], True)
                self.assertEqual(first["outcome"], stop)

    def test_slow_projection_preserves_timeout_and_reap_checkpoint(self):
        run.dump(self.state / "setup.json", {"status": "READY"})
        epoch = 1000
        real_clock = time.monotonic
        offset = epoch + spec.LIMITS["setup_seconds"] - 1 - real_clock()
        launched = []
        slow_attempts = []

        def clock():
            return offset + real_clock()

        def supervise(argv, *, directory, deadline, diagnostics, **unused):
            nonlocal offset
            launched.append(directory.name)
            offset += deadline - clock()
            return COMPLETED | {"stop_reason": "TIMEOUT", "last_observed_phase": "cbmc"}

        def project(directory, rows, child, *, mode):
            if directory.name != self.slots[0][0]:
                return {"outcome": "TIMEOUT", "complete": False}
            slow_attempts.append(directory.name)
            checkpoint = self.read_receipt(directory.name)
            self.assertEqual((checkpoint["outcome"], checkpoint["child"]["reaped"]), ("TIMEOUT", True))
            self.assertEqual(checkpoint["projection_status"], "PENDING")
            time.sleep(16)
            self.fail("the projection completed its sixteen-second delay")

        with (patch.object(run.time, "monotonic", side_effect=clock), patch.object(spec, "identity"),
              patch.object(run.supervisor, "run", side_effect=supervise), patch.object(results, "project", side_effect=project),
              patch.object(run, "close_measurements") as close):
            (self.state / "epoch").write_text(str(epoch))
            boundaries = run.clocks(self.state)
            run.measure(self.state, self.std, self.tool, self.frozen, boundaries)
            # The report re-reads the synthetic epoch, so keep it on the same clock.
            report.finish(self.state, self.frozen, "Linux")
        close.assert_called_once()
        self.assertEqual(launched, list(ROOTS))
        self.assertEqual(slow_attempts, launched[:1])
        index = spec.read(self.state / "artifact" / "index.json")
        self.assertEqual(index["clocks"], boundaries)
        record = self.read_receipt(launched[0])
        self.assertEqual((record["outcome"], record["child"]["reaped"]), ("TIMEOUT", True))
        self.assertTrue(record["projection_budget_exhausted"])
        self.assertFalse(record["receipt_deadline_exceeded"])
        self.assertLessEqual(record["receipt_write_completed_monotonic"], record["receipt_deadline_monotonic"])
        self.assertEqual(record["receipt_deadline_monotonic"], record["slot_deadline_monotonic"])
        self.assertLessEqual(record["started_monotonic"], record["latest_start_monotonic"])
        self.assertTrue(all((self.state / "work" / key).is_dir() for key in launched))

    def test_late_atomic_commit_and_deferred_retry_preserve_terminal_outcome(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt), tempfile.TemporaryDirectory() as temp:
                state = Path(temp)
                run.dump(state / "setup.json", {"status": "READY"})
                now = 61
                launched = []
                first = self.slots[0][0]
                save = run.save_receipt
                writes = []

                def supervise(argv, *, directory, **unused):
                    launched.append(directory.name)
                    return COMPLETED | {"exit_code": 1}

                def delayed_save(state, record):
                    nonlocal now
                    if record["id"] == first:
                        writes.append(len(launched))
                        if record.get("receipt_write_deferred"):
                            self.assertEqual(launched, list(ROOTS))
                            now += .25
                        if len(writes) == 3 and interrupt:
                            now = record["slot_deadline_monotonic"] + .25
                            raise run.ReceiptDeadlineExceeded("synthetic atomic write interruption")
                    save(state, record)
                    if record["id"] == first and len(writes) == 3:
                        now = record["slot_deadline_monotonic"] + .25

                def projected(directory, rows, child, *, mode):
                    checkpoint = spec.read(state / "artifact" / "slots" / rows[0]["id"] / "receipt.json")
                    self.assertEqual((checkpoint["process_outcome"], checkpoint["child"]["reaped"]), ("EXIT_1", True))
                    return {"outcome": "INCOMPLETE", "observed_outcome": "FAILED", "complete": False}

                with (patch.object(run.time, "monotonic", side_effect=lambda: now), patch.object(spec, "identity"),
                      patch.object(run.supervisor, "run", side_effect=supervise),
                      patch.object(results, "project", side_effect=projected),
                      patch.object(run, "save_receipt", side_effect=delayed_save),
                      patch.object(report, "save_receipt", side_effect=delayed_save), patch.object(run, "close_measurements")):
                    (state / "epoch").write_text("60")
                    run.measure(state, self.std, self.tool, self.frozen, run.clocks(state))
                    self.assertEqual(writes, [0, 1, 1])
                    report.finish(state, self.frozen, "Linux")
                self.assertEqual(launched, list(ROOTS))
                slot_count = len(self.slots)
                self.assertEqual(writes, [0, 1, 1, slot_count, slot_count] if interrupt else [0, 1, 1, slot_count])
                receipt = spec.read(state / "artifact" / "slots" / first / "receipt.json")
                self.assertEqual((receipt["outcome"], receipt["projection_outcome"]), ("FAILED", "INCOMPLETE"))
                self.assertEqual(receipt["process_outcome"], "EXIT_1")
                self.assertEqual(receipt["receipt_write_completed_monotonic"],
                                 61 + self.slots[0][3] + (.50 if interrupt else .25))
                self.assertEqual(receipt["slot_elapsed_seconds"], self.slots[0][3] + (.50 if interrupt else .25))
                self.assertTrue(receipt["receipt_deadline_exceeded"])
                self.assertEqual(receipt.get("receipt_write_deferred", False), interrupt)

    def test_receipt_watchdog_interrupts_slow_atomic_write_and_finish_retries(self):
        (self.state / "epoch").write_text(str(time.monotonic()))
        run.dump(self.state / "setup.json", {"status": "READY"})
        save = run.save_receipt
        writes = []

        def slow_write(state, record):
            writes.append(record["outcome"])
            if len(writes) == 3:
                time.sleep(2)
                self.fail("receipt watchdog did not interrupt the write")
            save(state, record)

        boundaries = run.clocks(self.state)
        with (patch.object(spec, "identity"), patch.object(run, "close_measurements"),
              patch.object(run, "invoke", return_value=COMPLETED | {"exit_code": 1}),
              patch.object(results, "project", return_value={"outcome": "FAILED", "complete": True}),
              patch.dict(spec.LIMITS, {"receipt_seconds": .5}),
              patch.object(run, "save_receipt", side_effect=slow_write),
              patch.object(run, "RECEIPT_COMMIT_RESERVE_SECONDS", .1)):
            run.measure(self.state, self.std, self.tool, self.frozen, boundaries)
        key = self.slots[0][0]
        self.assertEqual(self.read_receipt(key)["process_outcome"], "EXIT_1")
        self.assertEqual(self.read_receipt(key)["projection_status"], "PENDING")
        report.finish(self.state, self.frozen, "Linux")
        recovered = self.read_receipt(key)
        self.assertEqual((recovered["outcome"], recovered["child"]["reaped"]), ("FAILED", True))
        self.assertTrue(recovered["receipt_deadline_exceeded"])
        self.assertTrue(recovered["receipt_write_deferred"])

    def test_finish_replays_deferred_receipt_next_to_partial_tmp(self):
        self.enterContext(patch.object(run.time, "monotonic", return_value=100))
        (self.state / "epoch").write_text("60")
        slot = self.slots[-1]
        key = slot[0]
        admission = {"commit": "4" * 40, "tree": "5" * 40, "parent": spec.TRIGGER_PARENT}
        output = self.state / "outputs"
        artifact = self.state / "artifact"
        receipt_path = artifact / "slots" / key / "receipt.json"
        partial = receipt_path.with_suffix(".tmp")
        checkpoint = run.receipt(slot, "INCOMPLETE", "TERMINAL_EVIDENCE_PENDING") | {
            "child": COMPLETED | {"exit_code": 1},
            "process_outcome": "EXIT_1",
            "started_monotonic": 62,
            "slot_deadline_monotonic": 257,
            "receipt_deadline_monotonic": 90,
        }
        run.save_receipt(self.state, checkpoint)
        partial.write_text('{"outcome":')
        deferred = checkpoint | {"outcome": "FAILED", "reason": "EXITED", "receipt_write_deferred": True}
        run.dump(self.state / "receipt-finalization.json", {"timings": {}, "pending": {key: deferred}})

        with (patch.object(run, "workspace", return_value=(self.state, self.std, self.tool)),
              patch.object(spec, "check_trigger", return_value=admission),
              patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)})):
            with patch.object(sys, "argv", ["run.py", "pins"]):
                run.main()
            with patch.object(sys, "argv", ["run.py", "finish"]):
                run.main()

        self.assertIn("trigger_admitted=true", output.read_text().splitlines())
        self.assertFalse(partial.exists())
        saved = self.read_receipt(key)
        self.assertEqual((saved["outcome"], saved["process_outcome"], saved["child"]["reaped"]),
                         ("FAILED", "EXIT_1", True))
        self.assertTrue(saved["receipt_write_deferred"])
        self.assertTrue(saved["receipt_deadline_exceeded"])
        self.assertEqual(saved["receipt_write_completed_monotonic"], 100)
        index = spec.read(artifact / "index.json")
        self.assertEqual(index["trigger"], admission)
        self.assertEqual(index["slots"][-1]["outcome"], "FAILED")
        self.assertEqual(index["members"][receipt_path.relative_to(artifact).as_posix()]["sha256"],
                         spec.sha256(receipt_path))
        self.assertNotIn(partial.relative_to(artifact).as_posix(), index["members"])

    def test_finish_uses_earlier_step_or_publication_deadline(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        admission = {"tree": "5" * 40}
        run.dump(self.state / "trigger.json", admission)

        publication_deadline = run.clocks(self.state)["receipt_publication_deadline"]
        for started, expected_deadline in ((61, 361), (publication_deadline - 10, publication_deadline)):
            with self.subTest(started=started):
                clock.return_value = started

                def gate(*, deadline):
                    self.assertEqual(deadline, expected_deadline)
                    clock.return_value = started + 1
                    return admission

                def late_report(*_args):
                    clock.return_value = expected_deadline + .01

                with (patch.object(sys, "argv", ["run.py", "finish"]),
                      patch.object(run, "workspace", return_value=(self.state, self.std, self.tool)),
                      patch.object(spec, "check_trigger", side_effect=gate),
                      patch.object(run, "receipt_window", wraps=run.receipt_window) as window,
                      patch.object(report, "finish", side_effect=late_report) as finish):
                    with self.assertRaisesRegex(run.ReceiptDeadlineExceeded, "finish completed beyond"):
                        run.main()
                    window.assert_called_once_with(expected_deadline)
                    finish.assert_called_once()

    def test_pins_and_sources_deadline_includes_trigger_validation(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        output = self.state / "outputs"
        setup_deadline = run.clocks(self.state)["prepare_deadline"]
        for command, started, expected_deadline in (("pins", 61, 106), ("sources", 61, 181),
                                                    ("pins", setup_deadline - 10, setup_deadline),
                                                    ("sources", setup_deadline - 10, setup_deadline)):
            with self.subTest(command=command, started=started):
                clock.return_value = started

                def late_gate(**kwargs):
                    self.assertEqual(kwargs["deadline"], expected_deadline)
                    clock.return_value = expected_deadline + .01
                    return {"tree": "5" * 40}

                with (patch.object(run, "workspace", return_value=(self.state, self.std, self.tool)),
                      patch.object(sys, "argv", ["run.py", command]),
                      patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                      patch.object(spec, "check_trigger", side_effect=late_gate),
                      patch.object(run, "sources") as sources):
                    with self.assertRaisesRegex(run.ReceiptDeadlineExceeded, "trigger validation exceeded"):
                        run.main()
                    sources.assert_not_called()
                self.assertFalse(output.exists())
                self.assertFalse((self.state / "trigger.json").exists())

    def test_measure_gate_and_upload_keep_absolute_boundaries(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        boundaries = run.clocks(self.state)
        self.assertEqual(run.MEASURE_SECONDS, 800)
        self.assertEqual(boundaries["prepare_deadline"], 3300)
        self.assertEqual(boundaries["setup_deadline"], 3360)
        self.assertEqual((boundaries["slots_deadline"], boundaries["verify_deadline"],
                          boundaries["finalize_deadline"], boundaries["reserve_deadline"],
                          boundaries["job_deadline"], boundaries["receipt_publication_deadline"]),
                         (3975, 4095, 4815, 5175, 6060, 4390))
        with patch.object(run, "workspace", return_value=(self.state, self.std, self.tool)):
            with patch.object(sys, "argv", ["run.py", "measure"]), patch.object(spec, "check_trigger") as gate:
                clock.return_value = boundaries["setup_deadline"] + 0.01
                with self.assertRaisesRegex(run.ReceiptDeadlineExceeded, "measure trigger validation"):
                    run.main()
                gate.assert_not_called()
            with patch.object(sys, "argv", ["run.py", "upload-check"]):
                clock.return_value = boundaries["finalize_deadline"]
                run.main()
                clock.return_value += 0.01
                with self.assertRaisesRegex(ValueError, "upload completed after"):
                    run.main()

    def test_finish_cutoff_matches_upload_admission(self):
        clock = self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        admission = {"tree": "5" * 40}
        run.dump(self.state / "trigger.json", admission)
        boundaries = run.clocks(self.state)
        cutoff = boundaries["receipt_publication_deadline"]
        self.assertEqual((boundaries["finalize_deadline"], cutoff), (4815, 4390))
        self.assertEqual(boundaries["finalize_deadline"] - cutoff,
                         spec.LIMITS["upload_seconds"] + run.UPLOAD_LAUNCH_HEADROOM_SECONDS)

        def finish_report(*_args):
            clock.return_value = cutoff

        with patch.object(run, "workspace", return_value=(self.state, self.std, self.tool)):
            clock.return_value = cutoff - 1
            with (patch.object(sys, "argv", ["run.py", "finish"]),
                  patch.object(spec, "check_trigger", return_value=admission) as gate,
                  patch.object(report, "finish", side_effect=finish_report)):
                run.main()
                gate.assert_called_once_with(deadline=cutoff)

            with (patch.object(sys, "argv", ["run.py", "upload-gate"]),
                  patch.object(spec, "check_trigger", return_value=admission),
                  patch.object(report, "validate_artifact_index", return_value={"trigger": admission}) as validate):
                clock.return_value = cutoff - 1
                run.main()
                validate.assert_called_once()
                clock.return_value = cutoff + 0.01
                with self.assertRaisesRegex(ValueError, "full upload window"):
                    run.main()

    def test_artifact_upload_gate_binds_schema_pins_and_member_digests(self):
        report.finish(self.state, self.frozen, "Linux")
        artifact = self.state / "artifact"
        index_path = artifact / "index.json"
        index = spec.read(index_path)
        report.validate_artifact_index(artifact, self.frozen)
        for field, value, message in (
                ("schema", "foreign-schema", "schema"),
                ("overlay", ["0" * 40, self.frozen["overlay"][1]], "overlay"),
                ("members", {"SUMMARY.json": {"bytes": 3, "sha256": "0" * 64}}, "inventory")):
            with self.subTest(field=field):
                bad = deepcopy(index)
                bad[field] = value
                run.dump(index_path, bad)
                with self.assertRaisesRegex(ValueError, message):
                    report.validate_artifact_index(artifact, self.frozen)
        run.dump(index_path, index)

    def test_measure_step_limits_latest_starts_without_shortening_slot(self):
        self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        run.dump(self.state / "setup.json", {"status": "READY"})
        boundaries = run.clocks(self.state)
        step_deadline = boundaries["slots_deadline"] - 100
        verify_deadline = min(boundaries["verify_deadline"], step_deadline - run.MEASUREMENT_JOURNAL_SECONDS)
        overall_deadline = min(boundaries["slots_deadline"],
                                verify_deadline - spec.LIMITS["post_attestation_seconds"])
        reduction = boundaries["slots_deadline"] - overall_deadline
        records = [run.receipt(slot, "INCOMPLETE", "synthetic") | {"child": COMPLETED}
                   for slot in self.slots]
        with (patch.object(spec, "identity") as identity,
              patch("telemetry.Thread.start", side_effect=RuntimeError("no thread")),
              patch.object(run, "measure_slot", side_effect=records) as measure,
              patch.object(run, "close_measurements") as close):
            run.measure(self.state, self.std, self.tool, self.frozen, boundaries, step_deadline=step_deadline)
        self.assertEqual([call.kwargs["deadline"] for call in identity.call_args_list], [61 + spec.LIMITS["measure_gate_seconds"]] * 2)
        self.assertEqual([(call.args[4][3], call.args[5]) for call in measure.call_args_list],
                         [(slot[3], boundaries["latest_starts"][slot[0]] - reduction) for slot in self.slots])
        self.assertEqual(close.call_args.args[-1], verify_deadline)

    def test_receipt_journal_error_does_not_replace_measurement_error(self):
        self.enterContext(patch.object(run.time, "monotonic", return_value=61))
        (self.state / "epoch").write_text("60")
        run.dump(self.state / "setup.json", {"status": "READY"})
        failure = run.RunError("synthetic attestation error")
        records = [run.receipt(slot, "INCOMPLETE", "synthetic") | {"child": COMPLETED}
                   for slot in self.slots]
        with (patch.object(spec, "identity"),
              patch("telemetry.Thread.start", side_effect=RuntimeError("no thread")),
              patch.object(run, "measure_slot", side_effect=records),
              patch.object(run, "close_measurements", side_effect=failure),
              patch.object(run, "dump", side_effect=OSError("synthetic journal error"))):
            with self.assertRaises(run.RunError) as raised:
                run.measure(self.state, self.std, self.tool, self.frozen, run.clocks(self.state))
        self.assertIs(raised.exception, failure)
        self.assertIn("synthetic journal error", raised.exception.__notes__[0])

    def test_missing_setup_still_indexes_all_rows(self):
        run.dump(self.state / "error.json", {"message": "synthetic setup failure"})
        report.finish(self.state, self.frozen, "Linux")
        index = spec.read(self.state / "artifact" / "index.json")
        self.assertEqual(index["calibration_status"], "INCOMPLETE")
        self.assertEqual([(row["id"], row["outcome"]) for row in index["slots"]],
                         [(key, "NOT_STARTED") for key in ROOTS])

    def test_offline_close_requires_exact_roster_full_receipt_and_profile(self):
        records = []
        for slot in self.slots:
            outcome = slot[2][0]["expected_outcome"]
            record = run.receipt(slot, outcome, "EXITED")
            covers = slot[2][0]["covers"]
            record.update(child=COMPLETED | {"peak_rss_kib": 4 * spec.GIB_KIB, "exit_code": int(outcome == "FAILED")},
                          cold_wall_seconds=180, receipt_deadline_exceeded=False, projection_status="COMPLETE",
                          projection=f"slots/{slot[0]}/projection.json",
                          receipt_write_completed_monotonic=200, receipt_deadline_monotonic=201,
                          timings={"verification_seconds": 120}, projection_complete=True,
                          covers={"expected_labels_total": len(covers), "expected_reached_labels": covers},
                          result_evidence={"mandatory_anchors": {"complete": True}},
                          expected_result={"status": "MATCHED", "expected_outcome": outcome,
                                           "observed_outcome": outcome})
            if slot[0] == spec.RELAY_SLOT_ID:
                # measure_slot copies the judged relay delivery into the receipt of the relay slot.
                record["stdout_relay"] = {"status": "COMPLETE", "reasons": [], "call": {"outcome": "COMPLETE"}}
                record["stdout_delivery"] = "COMPLETE"
            else:
                # measure_slot marks every receipt without a relay as STOCK_PIPE.
                record["stdout_delivery"] = "STOCK_PIPE"
            records.append(record)
        self.assertEqual(len(records), 3)
        self.assertEqual([(row["id"], row["outcome"], row["expected_result"]["status"]) for row in records],
                         [(spec.SLOT_IDS[0], "VERIFIED", "MATCHED"), (spec.SLOT_IDS[1], "FAILED", "MATCHED"),
                          (spec.SLOT_IDS[2], "FAILED", "MATCHED")])
        attestation = {"status": "COMPLETE", "started_monotonic": 200,
                       "finished_monotonic": 201, "deadline_monotonic": 202}
        direct = report.summarize({}, records, "Linux", None, attestation)
        self.assertEqual(direct["diagnosis"], "GEN_STABLE_N32_CLOSURE_WITHIN_PROFILE")
        self.assertEqual(direct["type_diagnoses"], {"STABLE_U64": "WITHIN_PROFILE", "GENERAL_WIDE": "WITHIN_PROFILE"})
        self.assertTrue(direct["roster_within_profile"])
        self.assertTrue(all(row["slot_status"] == "WITHIN_PROFILE" for row in direct["rows"]))
        self.assertEqual([(row["profile"]["delivery_route"], row["profile"]["stdout_delivery"]) for row in direct["rows"]],
                         [("STOCK_PIPE", "STOCK_PIPE")] * 2 + [("STDOUT_RELAY", "COMPLETE")])
        within = {slot: "WITHIN_PROFILE" for slot in spec.SLOT_IDS}
        wide = set(spec.TYPE_SLOT_IDS["GENERAL_WIDE"])
        self.assertEqual(wide, {spec.RELAY_SLOT_ID})
        for index in range(3):
            kind, other = ("GENERAL_WIDE", "STABLE_U64") if spec.SLOT_IDS[index] in wide else ("STABLE_U64", "GENERAL_WIDE")
            # A root that changes its frozen delivery changes the frozen roster digest and opens every slot.
            frozen_delivery = records[index]["roots"][0]["stdout_delivery"]
            moved = records[index] | {"roots": [records[index]["roots"][0] | {
                "stdout_delivery": "STOCK_PIPE" if frozen_delivery == "STDOUT_RELAY" else "STDOUT_RELAY"}]}
            summary = report.summarize({}, [*records[:index], moved, *records[index + 1:]], "Linux", None, attestation)
            self.assertEqual(summary["slot_diagnoses"], dict.fromkeys(spec.SLOT_IDS, "OPEN"))
            self.assertFalse(summary["roster_matched"])
            if spec.SLOT_IDS[index] == spec.RELAY_SLOT_ID:
                # Relay delivery is necessary for the Wide control and never replaces the native match.
                changes = ({"stdout_relay": None}, {"stdout_relay": {"status": "INCOMPLETE", "reasons": ["SPILL_LIMIT"],
                                                                     "call": {}}, "stdout_delivery": "INCOMPLETE"},
                           {"stdout_relay": {"status": "INSTALLED"}, "stdout_delivery": "NOT_JUDGED"},
                           {"stdout_delivery": "STOCK_PIPE"}, {"stdout_delivery": None})
            else:
                changes = ({"stdout_relay": {"status": "COMPLETE", "reasons": [], "call": {"outcome": "COMPLETE"}}},
                           {"stdout_delivery": "COMPLETE"}, {"stdout_delivery": None})
            for change in changes:
                with self.subTest(slot=spec.SLOT_IDS[index], change=sorted(change)):
                    stray = records[index] | change
                    if change.get("stdout_relay", ...) is None:
                        stray = {key: value for key, value in stray.items() if key != "stdout_relay"}
                    summary = report.summarize({}, [*records[:index], stray, *records[index + 1:]], "Linux", None,
                                               attestation)
                    self.assertEqual(summary["slot_diagnoses"], within | {spec.SLOT_IDS[index]: "OPEN"})
                    self.assertEqual(summary["type_diagnoses"], {kind: "OPEN", other: "WITHIN_PROFILE"})
                    self.assertEqual(summary["diagnosis"], "GEN_STABLE_N32_CLOSURE_OPEN")
        for index in (1, 2):
            unmatched = records[index] | {"expected_result": {"status": "MISMATCHED", "observed_outcome": "VERIFIED"}}
            self.assertEqual(report.summarize({}, [*records[:index], unmatched, *records[index + 1:]], "Linux", None,
                                              attestation)["slot_diagnoses"][spec.SLOT_IDS[index]], "OPEN")
        record = records[0]
        record["timings"]["verification_seconds"] = 120.01
        over = report.summarize({}, records, "Linux", None, attestation)
        self.assertTrue(over["roster_matched"])
        self.assertEqual(over["diagnosis"], "GEN_STABLE_N32_CLOSURE_OPEN")
        self.assertEqual(over["type_diagnoses"], {"STABLE_U64": "OPEN", "GENERAL_WIDE": "WITHIN_PROFILE"})
        self.assertFalse(over["roster_within_profile"])
        self.assertEqual(over["rows"][0]["slot_status"], "OPEN")
        self.assertEqual(over["rows"][0]["profile"]["metrics"]["verification_seconds"], "OVER_LIMIT")
        record["timings"]["verification_seconds"] = 120
        self.assertFalse(report.summarize({}, records, "Linux", None, None)["roster_within_profile"])
        late = attestation | {"finished_monotonic": 203}
        self.assertFalse(report.summarize({}, records, "Linux", None, late)["roster_within_profile"])
        wrong_labels = record["covers"] | {"expected_reached_labels":
                                          ["wrong"] + record["covers"]["expected_reached_labels"][1:]}
        for update in ({"receipt_deadline_exceeded": True}, {"receipt_write_deferred": True},
                       {"covers": wrong_labels},
                       {"receipt_write_completed_monotonic": 202},
                       {"receipt_write_completed_monotonic": None},
                       {"child": record["child"] | {"reaped": False}},
                       {"receipt_deadline_exceeded": None}, {"projection_status": "ERROR"},
                       {"projection_complete": False}, {"projection_truncated": True},
                       {"publication_truncated": True}, {"projection": None},
                       {"child": record["child"] | {"sampler_valid": False}},
                       {"result_evidence": {"mandatory_anchors": {"complete": False}}},
                       {"expected_result": {"status": "MISMATCHED", "observed_outcome": "VERIFIED"}},
                       {"cold_wall_seconds": 180.01},
                       {"timings": {"verification_seconds": 120.01}},
                       {"child": record["child"] | {"peak_rss_kib": 4 * spec.GIB_KIB + 1}},
                       {"child": record["child"] | {"exit_code": 1 - record["child"]["exit_code"]}}):
            self.assertFalse(report.summarize({}, [record | update, *records[1:]],
                                              "Linux", None, attestation)["roster_within_profile"])
        # The same profile mutations on the Wide relay control reach only the general Wide type.
        wide_slot = records[2]
        self.assertEqual(wide_slot["id"], "GEN-N32-WIDE-WITNESS-CORRUPT")
        for update in ({"receipt_deadline_exceeded": True}, {"cold_wall_seconds": 180.01},
                       {"child": wide_slot["child"] | {"peak_rss_kib": 4 * spec.GIB_KIB + 1}},
                       {"child": wide_slot["child"] | {"exit_code": 0}}):
            summary = report.summarize({}, [*records[:2], wide_slot | update], "Linux", None, attestation)
            self.assertEqual(summary["type_diagnoses"], {"STABLE_U64": "WITHIN_PROFILE", "GENERAL_WIDE": "OPEN"})
        # The stable u64 control has the opposite effect: its exit code 1 is required, 0 opens STABLE_U64 only.
        u64_control = records[1]
        summary = report.summarize({}, [records[0], u64_control | {"child": u64_control["child"] | {"exit_code": 0}},
                                        records[2]], "Linux", None, attestation)
        self.assertEqual(summary["type_diagnoses"], {"STABLE_U64": "OPEN", "GENERAL_WIDE": "WITHIN_PROFILE"})
        for bad_attestation in (attestation | {"status": "FAILED"},
                                attestation | {"finished_monotonic": 203},
                                attestation | {"finished_monotonic": None},
                                {"started_monotonic": 200, "finished_monotonic": 201,
                                 "deadline_monotonic": 202}):
            self.assertFalse(report.summarize({}, records, "Linux", None, bad_attestation)["roster_within_profile"])

        old_bits = record | {"id": "N32-ACTUAL-BITS", "outcome": "VERIFIED", "child": COMPLETED,
                             "expected_result": {"status": "MATCHED", "observed_outcome": "VERIFIED"},
                             "roots": [record["roots"][0] | {"id": "N32-ACTUAL-BITS", "expected_outcome": "VERIFIED",
                                                            "selector": spec.CONSUMER_PREFIX + "n32_actual_bits"}]}
        old_corrupt = record | {"id": "N32-ACTUAL-CORRUPT",
                                "roots": [record["roots"][0] | {"id": "N32-ACTUAL-CORRUPT",
                                                               "selector": spec.CONSUMER_PREFIX + "n32_actual_corrupt"}]}
        extra_id = "SYNTHETIC-HISTORIC-SLOT"
        extra = record | {"id": extra_id,
                          "roots": [record["roots"][0] | {"id": extra_id,
                                                           "selector": spec.CLOSE_PREFIX + "gen_n16_s8_l32_full"}]}
        old_wide = record | {"id": spec.WIDE_WITNESS_SLOT_ID,
                             "roots": [record["roots"][0] | {"id": spec.WIDE_WITNESS_SLOT_ID,
                                                              "selector": spec.WIDE_WITNESS_SELECTOR}]}
        for foreign in ([old_bits, old_corrupt], [record, old_bits, old_corrupt],
                        [old_corrupt | {"id": record["id"]}], [], [record, extra], [record, extra, extra],
                        [old_wide], [record, old_wide], [*records[:2], old_wide], records[:2],
                        [records[1], records[0], *records[2:]], [*records, records[0]]):
            rejected = report.summarize({}, foreign, "Linux", None, attestation)
            self.assertFalse(rejected["roster_within_profile"])
            self.assertFalse(rejected["roster_matched"])
            self.assertEqual(rejected["diagnosis"], "GEN_STABLE_N32_CLOSURE_OPEN")
            self.assertEqual(rejected["type_diagnoses"], {"STABLE_U64": "OPEN", "GENERAL_WIDE": "OPEN"})

        run.save_receipt(self.state, record)
        run.dump(self.state / "attestation.json", attestation)
        report.finish(self.state, self.frozen, "Linux")
        self.assertEqual(self.read_receipt(record["id"])["projection_status"], "MISSING")
        summary = spec.read(self.state / "artifact" / "SUMMARY.json")
        self.assertFalse(summary["roster_matched"])

    def test_cnf_summary_retains_subsequent_native_markers(self):
        metrics = {"streams": {"stdout": {
            "first_cnf": {"variables": 10, "clauses": 20, "line": 4, "solve_context": "INITIAL_SOLVE"},
            "subsequent_cnf": [{"variables": 14, "clauses": 28, "line": 19,
                                 "solve_context": "COVER_OR_REACHABILITY"}],
            "cnf_status": "OBSERVED", "capture_complete": True,
            "capture_truncated": False, "incomplete_tail": None, "cnf_omitted": 0,
        }}}
        rendered = report.cnf_text(metrics)
        self.assertIn("10 / 20 line 4 INITIAL_SOLVE", rendered)
        self.assertIn("later 14 / 28 line 19 COVER_OR_REACHABILITY", rendered)

    def test_verified_u64_n20_n21_reaches_mandatory_receipt(self):
        child = COMPLETED | {"exit_code": 0}
        result = {"status": "MATCHED", "expected_outcome": "VERIFIED", "observed_outcome": "VERIFIED"}
        projection = {"outcome": "VERIFIED", "complete": True, "expected_result": result}
        with patch.object(run, "invoke", return_value=child), patch.object(results, "project", return_value=projection):
            run.measure_slot(self.state, self.std, self.tool, self.frozen, self.slots[0], run.time.monotonic() + 250)
        receipt = self.read_receipt(self.slots[0][0])
        self.assertEqual(receipt["outcome"], "VERIFIED")
        self.assertEqual(receipt["expected_result"], result)
        self.assertEqual(receipt["child"]["exit_code"], 0)

    def test_incomplete_positive_preserves_observation_only(self):
        row = deepcopy(self.frozen["roster"][0])
        row.update(id="GEN-N16-S8-L32-FULL", selector=spec.CLOSE_PREFIX + "gen_n16_s8_l32_full",
                   expected_outcome="VERIFIED", expected_failure=None)
        slot = (row["id"], "singleton", [row], row["seconds"])
        projection = {"outcome": "VERIFIED", "observed_outcome": "VERIFIED",
                      "complete": False, "projection_truncated": True}
        with patch.object(run, "invoke", return_value=COMPLETED), patch.object(results, "project", return_value=projection):
            run.measure_slot(self.state, self.std, self.tool, self.frozen, slot, run.time.monotonic() + 250)
        receipt = self.read_receipt(slot[0])
        self.assertEqual((receipt["outcome"], receipt["observed_outcome"]), ("INCOMPLETE", "VERIFIED"))
        self.assertFalse(receipt["projection_complete"])

    def test_attestation_uses_deadline_and_leaves_receipts(self):
        first = run.receipt(self.slots[0], "TIMEOUT", "TIMEOUT")
        run.save_receipt(self.state, first)
        with (patch.object(run.time, "monotonic", return_value=990), patch.object(tool, "attest") as attest,
              patch.object(tool, "_runtime_identity", return_value={}),
              patch.object(spec, "identity", side_effect=[{}, TimeoutError("checkout deadline")]) as identity):
            with self.assertRaises(TimeoutError):
                run.close_measurements(self.state, self.std, self.tool, self.frozen, {"tool": {}}, 1000)
        self.assertEqual(attest.call_args.args[1], 1000)
        self.assertEqual([call.kwargs["deadline"] for call in identity.call_args_list], [1000, 1000])
        report.finish(self.state, self.frozen, "Linux")
        index = spec.read(self.state / "artifact" / "index.json")
        self.assertEqual(index["final_attestation_status"], "TIMEOUT")
        self.assertEqual(index["slots"][0]["outcome"], "TIMEOUT")
        self.assertFalse((self.state / "end.json").exists())

    def test_cbmc_banner_exact_release(self):
        tool._require_release("CBMC", "6.11.0 (cbmc-6.11.0)", spec.CBMC_VERSION)
        tool._require_release("goto-cc", "gcc (goto-cc 6.11.0 (cbmc-6.11.0)) 13.3.0", spec.CBMC_VERSION)
        for banner in ("gcc (goto-cc 6.11.0~rc1 (cbmc-6.11.0))", "gcc (goto-cc 6.11.0 (cbmc-7.0.0))"):
            with self.assertRaises(tool.AttestationError):
                tool._require_release("goto-cc", banner, spec.CBMC_VERSION)
