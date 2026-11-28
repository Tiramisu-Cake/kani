"""Frozen REV2 N32 closure inputs for general Wide and stable u64, and source/trigger checks."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FORK = "Tiramisu-Cake/kani"
REF = "refs/heads/uninit-ci/ch8-q-pilot-v1"
ARTIFACT_SCHEMA = "smallsort-rev2-gen-stable-n32-closure-artifact-v1"
TRIGGER_TREE_ENV = "CH8_REV2_GEN_STABLE_N32_CLOSURE_TRIGGER_TREE"
TRIGGER_PARENT = "467af9cb8dba0e3be78a8d7d07672a1943c4806b"
BASE = ("dab03cf510df5c35141cde49f1368b1242f5035e", "7fd542ad59723ff2beeacb9632fb0568e81b0655")
TOOL = ("9834c96ce90ff57d8495416530b080dc3d52ce25", "938e9932cb2127239afb4f093f6302652c053398")
CAL1_OVERLAY = ("080a0104159fd04b6764a24f8538a97588f6612e", "96f95b8082983b57f203b0e3e12151552dba0f76")
CAL2_OVERLAY = ("043a1f19f9d36eb1666979f97b8e7e483ab41c5e", "1361a0da67b9bd21fc7c77a941582d0fd17b9a8d")
FIX3_OVERLAY = ("32129c149a15fb1b60a7314e738f3cb466d076e5", "1b0cc32c571b370178e64f2b8c79773d2ce27051")
BINDING_OVERLAY = ("32c2857f4b7137601de54ea42a02610c8fd29ed9", "0e682cfceaed5d33d3d3374b5dc97da5012bba93")
GEOMETRIES_OVERLAY = ("217b8efaa6c9c0d6e5d44f77e98d74bd5493360a", "ff2563b5867b8327b95db909262ddf80e3ed9c03")
CONSUMER_OVERLAY = ("b93859fb447a39c0c8c7d854f70dedf9a47b263f", "562a2fac5ed349a9fc09097789d0816f200c3819")
COMPOSITE_OVERLAY = ("9a8bb36e3b85d9f5729bdfa3b02e434d26c16470", "9ecbe7211c315b8dabbb5598f7c1eafe10784c06")
N17_OVERLAY = ("49811849392302943d45b02beb4b0403509b9447", "642b76724b9a702ec7f600059a615ad3438d6719")
N18_N19_PROVIDERS_OVERLAY = ("86ea7aa5b773888e52f9fb78fda38d5cbff9ea61", "63b199cc33052d6390fd0fdaa2b5c36962545fc4")
N18_N19_CONSUMER_R1 = ("a6f189eecbee57fe7517547bf7461c9dd2897e27", "4f149dce6a6a5663eb55cc526a880474aac7ca16")
N18_N19_CONSUMER_FIX1 = ("959087ac8632c68d8a6f0e28f58a8708475d564b", "2123d3d5a77af26c6faf2d98d031904e75771300")
N20_N21_PROVIDERS_OVERLAY = ("87ef4442ded137d2ee5f65bc29a4f87b8a3b69cd", "832289728d493a114f89c318546c7e50d36f6d45")
MERGE_PAIR_FIXED_OVERLAY = ("f72f4303bacfff4706b20268a87b2a1031a8ee0b", "03f9ce753b375729c2f8e53c18b2eaf7f3f07fc1")
N20_N21_CONSUMER_OVERLAY = ("000e6c4bf6ef0436e83e745618c077d988543169", "c79edb9b6caf4734907f31590b782f2698b7e647")
U64_N20_N21_FINAL_OVERLAY = ("b09c6f22bfbd1ce8eb6afccf96df6b9a2ad3c54b", "a784a8d12b2d7439233385ffa25f512e4f2c623b")
N22_N25_PROVIDERS_OVERLAY = ("b076d2ff4ed720930e2de62d70c0bbd1bb0308d5", "33cd29a7756b24febf399932f86d8d09892653f7")
N22_N25_FINAL_OVERLAY = ("a1335f8e11960150afda1d00d60c72b4362e3cec", "a04025df1dddb1668c12219307c943a23ee9382a")
N26_N32_PROVIDERS_OVERLAY = ("72bb79d26dd495d0461c6e6d3c05d21c2d1b1878", "c513d0ec1a137457add28b2b9ee9c47ac23642d3")
N26_N32_CONSUMER_OVERLAY = ("727137f7efd6f5feb05eb7b3db4f3875c8699675", "50089d49d2be1058df3f271abef7d0bfc9ee57d4")
N22_N25_CONSUMER_OVERLAY = ("8fe1b01f0a85ee60118d1813d6b74645e4594213", "f754c01d0ed26cb8d4e28c81efe8467cdf97d034")
HALVES_OVERLAY = ("ea34c58ab95b4cbccd9acaa3080597b8b2517a87", "75c4a374a0c906c989e2770a26990c7cdc6cdf83")
MERGE_OVERLAY = ("71953c45a9a38cff3538c8a5e413890efc896d70", "f59ea89d61b25e34f06f9b14d61ad48694b86950")
N26_N31_CONSUMER_OVERLAY = ("50609bb850c64080aedd74c00c9865dcae1ce74b", "c2e93c566512c45179ab015b55835167eefc6191")
COPY_BACK_OVERLAY = ("ee9eccad17d08988300e5b9e9e18d821889cdc92", "b242e0d68a9666e2f6c965656cb9b27c6475df4a")
U64_N13_OVERLAY = ("4d6dd509956dff820a596ff1af9c0aae347aca26", "b0dc6d628690b7bc58225e2f60503ed4f8ae32b3")
U64_N14_N17_OVERLAY = ("53e733666ede6b256c84498a6dd350f1e84dddfb", "b1d2c899753acd6e137e9c10e153270f30a65846")
U64_N18_N19_R1_OVERLAY = ("eb5b697e44b1d0ca1acc4e5f14222ef50864af38", "4c9908379efe2466694a5d5dfd26459b4edd23d7")
U64_N18_N19_FIX1_OVERLAY = ("c8eefae4c8073cff31e5576b372d5105b52797a1", "4f9687a4edccf69ef86ee8b4c2e01de9b3517539")
PILOT_OVERLAY = ("14a5a7322a050c7d5028054acc5825172d43c14c", "bf379fc6b403e9caa51e549cc53956d66549ef3c")
FIX1_OVERLAY = ("5a8702f59ae309b8069d380b1e3887fd48c2564b", "76ff14e1811ae4115aa1aeef2ae42986d21d3c50")
CLOSE_R1_OVERLAY = ("a7df430f35dca8e0a6372fe8410229277974194a", "cac68fdb2a6e45ce9166f37783ee2aa390d38bcf")
CLOSE_OVERLAY = ("e8e8af6d3b4c77ce0ee25066e9c97b6df3fd222e", "f48157264ed99a8bd5b5faa4c38709eef61c0b47")
WIDE_WITNESS_OVERLAY = ("cebdba9913d72c892eb6701d9a989bb2a9830768", "eb6a2ab705d354dc3394f022466594d9aa0d2e4f")
N10_WITNESS_OVERLAY = ("bec3b6ee805fd3640da34e20482a3de647b3c865", "7ba43a3e1930dcd881a044fb9f87eb2208d9399b")
N12_WITNESS_OVERLAY = ("b465318cc95001c651011c2e5579bba12669b467", "9d4c78baf73fae2b15f29c2c81730399e1a2d9fa")
WIDE_N12_N14_OVERLAY = ("93d0c4a18d2f9e13c366a51c6f15e61c209a32d3", "08402ed55717ed79fcffd20a5fff0e4b60c9ea2a")
N32_PILOT_OVERLAY = ("88d05a138c4bca054de4ec1215ceb7f54087c3df", "7dd117f5257b790fcd07f21826e6a8adecf75cc2")
N32_CLOSURE_OVERLAY = ("650d8aa728c9d508acad6ecaecd3a4f10fa74f0b", "0b64ec35411e5d5406e323cc2440c6146205d0ef")
OVERLAY = N32_CLOSURE_OVERLAY
BUNDLE_SHA256 = "5287434510865a2eff4af7203e9dbb010c84bf4587f29583f59a6a0a16f1ac85"
STOCK_Z = ["function-contracts", "mem-predicates", "float-lib", "c-ffi", "loop-contracts", "quantifiers", "stubbing"]
FIX1_CFG = "kani_smallsort_rev2_gen_stable_n16_pilot_fix1"
CLOSE_CFG = "kani_smallsort_rev2_gen_stable_n16_close"
WIDE_WITNESS_CFG = "kani_smallsort_rev2_gen_stable_n16_close_witness_fix1"
N10_WITNESS_CFG = "kani_smallsort_rev2_gen_stable_n10_wide_witness"
N12_WITNESS_CFG = "kani_smallsort_rev2_gen_stable_n12_wide_witness"
WIDE_N12_N14_CFG = "kani_smallsort_rev2_gen_stable_wide_n12_n14"
N32_PILOT_CFG = "kani_smallsort_rev2_gen_stable_n32_pilot"
N32_CLOSURE_CFG = "kani_smallsort_rev2_gen_stable_n32_closure"
CFG = ["kani_smallsort_cal1", "kani_smallsort_cal2_merge_mask", "kani_smallsort_rev2_provider_cost",
       "kani_smallsort_rev2_s13_binding", "kani_smallsort_rev2_s13_geometries",
       "kani_smallsort_rev2_n32_consumer", "kani_smallsort_rev2_n32_composite",
       "kani_smallsort_rev2_n17", "kani_smallsort_rev2_n18_n19_providers",
       "kani_smallsort_rev2_n18_n19_consumer", "kani_smallsort_rev2_n20_n21_providers",
       "kani_smallsort_rev2_merge_pair_fixed", "kani_smallsort_rev2_n20_n21_consumer",
       "kani_smallsort_rev2_n22_n25_providers", "kani_smallsort_rev2_n22_n25_consumer",
       "kani_smallsort_rev2_n26_n31_halves", "kani_smallsort_rev2_n26_n31_merge",
       "kani_smallsort_rev2_n26_n31_consumer", "kani_smallsort_rev2_n26_n31_copy_back",
       "kani_smallsort_rev2_u64_n13", "kani_smallsort_rev2_u64_n14_n17",
       "kani_smallsort_rev2_u64_n18_n19", "kani_smallsort_rev2_u64_n20_n21",
       "kani_smallsort_rev2_u64_n22_n25_providers", "kani_smallsort_rev2_u64_n26_n32_providers",
       "kani_smallsort_rev2_u64_n26_n32_consumer",
       "kani_smallsort_rev2_gen_stable_n16_pilot", FIX1_CFG, CLOSE_CFG, WIDE_WITNESS_CFG,
       N10_WITNESS_CFG, N12_WITNESS_CFG, WIDE_N12_N14_CFG, N32_PILOT_CFG, N32_CLOSURE_CFG]
# The historical N16 FIX2 root kept its 30-flag vector and the N32 pilot its 34-flag vector.
# All three active rows use the full 35-flag vector.
N32_PILOT_ROW_CFG = CFG[:CFG.index(N32_PILOT_CFG) + 1]
WIDE_WITNESS_ROW_CFG = CFG[:CFG.index(WIDE_WITNESS_CFG) + 1]
PROVIDER_PREFIX = "slice::sort::shared::smallsort::verify::rev2_provider_cost::"
PROVIDER_DISCOVERY = (
    ("contract-harnesses", PROVIDER_PREFIX + "s13_swap_leaf"),
    ("standard-harnesses", PROVIDER_PREFIX + "s13_plain_byte"),
    ("standard-harnesses", PROVIDER_PREFIX + "m32_plain_mask"),
    ("contract-harnesses", PROVIDER_PREFIX + "m32_pair_step"),
)
BINDING_PREFIX = "slice::sort::shared::smallsort::verify::rev2_s13_binding::"
BINDING_DISCOVERY = tuple(("standard-harnesses", BINDING_PREFIX + name)
                          for name in ("s13_base1_bits", "s13_base1_corrupt_mask"))
GEOMETRIES_PREFIX = "slice::sort::shared::smallsort::verify::rev2_s13_geometries::"
GEOMETRIES_DISCOVERY = tuple(
    ("contract-harnesses" if name.endswith("_swap") else "standard-harnesses", GEOMETRIES_PREFIX + name)
    for name in ("s13_b01_l17_bits", "s13_b13_l13_swap", "s13_b13_l13_bits",
                 "s13_b17_l16_swap", "s13_b17_l16_bits", "s13_b17_l16_corrupt_mask")
)
CONSUMER_PREFIX = "slice::sort::shared::smallsort::verify::rev2_n32_consumer::"
CONSUMER_DISCOVERY = tuple(
    ("standard-harnesses", CONSUMER_PREFIX + name)
    for name in ("n32_insert_left_bytes", "n32_insert_right_bytes", "n32_actual_bits", "n32_actual_corrupt",
                 "n32_composite_witness_corrupt")
)
N17_PREFIX = "slice::sort::shared::smallsort::verify::rev2_n17::"
N17_DISCOVERY = tuple(
    ("standard-harnesses", N17_PREFIX + name)
    for name in ("n17_insert_bytes", "n17_actual_bits", "n17_witness_corrupt")
)
N18_N19_PROVIDERS_MODULE = "rev2_n18_n19_providers"
N18_N19_PROVIDERS_PREFIX = f"slice::sort::shared::smallsort::verify::{N18_N19_PROVIDERS_MODULE}::"
N18_N19_PROVIDERS_DISCOVERY = tuple(
    ("standard-harnesses" if name in ("s9_b01_l09_bits", "s9_b10_l10_bits", "n19_insert_right_bytes")
     else "contract-harnesses", N18_N19_PROVIDERS_PREFIX + name)
    for name in ("s9_b01_l09_bits", "s9_b10_l10_bits", "s9_b10_swap",
                 "n19_insert_right_bytes", "m18_m19_pair_step", "m19_odd_center")
)
N18_N19_CONSUMER_MODULE = "rev2_n18_n19_consumer"
N18_N19_CONSUMER_PREFIX = f"slice::sort::shared::smallsort::verify::{N18_N19_CONSUMER_MODULE}::"
N18_N19_CONSUMER_DISCOVERY = tuple(("standard-harnesses", N18_N19_CONSUMER_PREFIX + name)
                                   for name in ("n18_actual_bits", "n18_witness_corrupt",
                                                "n19_actual_bits", "n19_witness_corrupt"))
N20_N21_PROVIDERS_MODULE = "rev2_n20_n21_providers"
N20_N21_PROVIDERS_PREFIX = f"slice::sort::shared::smallsort::verify::{N20_N21_PROVIDERS_MODULE}::"
N20_N21_PROVIDERS_DISCOVERY = tuple(
    (kind, N20_N21_PROVIDERS_PREFIX + name)
    for kind, names in (
        ("standard-harnesses", ("s9_b11_l11_bits", "n20_insert_left_bytes", "n20_n21_insert_right_bytes")),
        ("contract-harnesses", ("s9_b11_swap", "m20_m21_pair_step", "m21_odd_center")),
    )
    for name in names
)
MERGE_PAIR_FIXED_MODULE = "rev2_merge_pair_fixed"
MERGE_PAIR_FIXED_PREFIX = f"slice::sort::shared::smallsort::verify::{MERGE_PAIR_FIXED_MODULE}::"
MERGE_PAIR_FIXED_DISCOVERY = tuple(("contract-harnesses", MERGE_PAIR_FIXED_PREFIX + f"m{n}_pair_fixed")
                                   for n in (20, 21, 31, 32))
N20_N21_CONSUMER_MODULE = "rev2_n20_n21_consumer"
N20_N21_CONSUMER_PREFIX = f"slice::sort::shared::smallsort::verify::{N20_N21_CONSUMER_MODULE}::"
N20_N21_CONSUMER_DISCOVERY = tuple(
    ("standard-harnesses", N20_N21_CONSUMER_PREFIX + f"n{n}_{suffix}")
    for n in (20, 21) for suffix in ("actual_bits", "witness_corrupt")
)
N22_N25_PROVIDERS_MODULE = "rev2_n22_n25_providers"
N22_N25_PROVIDERS_PREFIX = f"slice::sort::shared::smallsort::verify::{N22_N25_PROVIDERS_MODULE}::"
N22_N25_PROVIDERS_DISCOVERY = tuple(
    (kind, N22_N25_PROVIDERS_PREFIX + name)
    for kind, names in (
        ("standard-harnesses", (
            "s9_b12_l12_bits",
            "s9_b13_l12_bits",
            "insert_b01_l12_bytes",
            "insert_b12_l12_bytes",
            "insert_b13_l12_bytes",
        )),
        ("contract-harnesses", (
            "s9_b12_swap",
            "n22_pair_fixed",
            "n23_pair_fixed",
            "n23_odd_center",
            "n24_pair_fixed",
            "n25_pair_fixed",
            "n25_odd_center",
        )),
    )
    for name in names
)
N22_N25_CONSUMER_MODULE = "rev2_n22_n25_consumer"
N22_N25_CONSUMER_PREFIX = f"slice::sort::shared::smallsort::verify::{N22_N25_CONSUMER_MODULE}::"
N22_N25_CONSUMER_DISCOVERY = tuple(
    ("standard-harnesses", N22_N25_CONSUMER_PREFIX + f"n{n}_{suffix}")
    for n in (25, 24, 23, 22) for suffix in ("actual_bits", "witness_corrupt")
)
N26_N31_HALVES_MODULE = "rev2_n26_n31_halves"
N26_N31_HALVES_PREFIX = f"slice::sort::shared::smallsort::verify::{N26_N31_HALVES_MODULE}::"
N26_N31_HALVES_DISCOVERY = tuple(
    ("contract-harnesses" if name.endswith("_swap") else "standard-harnesses",
     N26_N31_HALVES_PREFIX + name)
    for name in ("s13_b14_swap", "s13_b14_l14_bits", "s13_b15_swap", "s13_b15_l15_bits",
                 "s13_b16_swap", "s13_b16_l16_bits")
)
MERGE_MODULE = "rev2_n26_n31_merge"
MERGE_PREFIX = f"slice::sort::shared::smallsort::verify::{MERGE_MODULE}::"
HISTORICAL_CONSUMER_MODULE = "rev2_n26_n31_consumer"
HISTORICAL_CONSUMER_PREFIX = f"slice::sort::shared::smallsort::verify::{HISTORICAL_CONSUMER_MODULE}::"
HISTORICAL_CONSUMER_DISCOVERY = tuple(("standard-harnesses", HISTORICAL_CONSUMER_PREFIX + f"n{n}_{suffix}")
                                      for n in (31, 26, 27, 28, 29, 30)
                                      for suffix in ("actual_bits", "witness_corrupt"))
COPY_BACK_MODULE = "rev2_n26_n31_copy_back"
COPY_BACK_PREFIX = f"slice::sort::shared::smallsort::verify::{COPY_BACK_MODULE}::"
U64_N13_MODULE = "rev2_u64_n13"
U64_N13_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N13_MODULE}::"
U64_N14_N17_MODULE = "rev2_u64_n14_n17"
U64_N14_N17_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N14_N17_MODULE}::"
U64_N18_N19_MODULE = "rev2_u64_n18_n19"
U64_N18_N19_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N18_N19_MODULE}::"
U64_N20_N21_MODULE = "rev2_u64_n20_n21"
U64_N20_N21_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N20_N21_MODULE}::"
U64_N22_N25_PROVIDERS_MODULE = "rev2_u64_n22_n25_providers"
U64_N22_N25_PROVIDERS_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N22_N25_PROVIDERS_MODULE}::"
MODULE = "rev2_u64_n26_n32_providers"
PREFIX = f"slice::sort::shared::smallsort::verify::{MODULE}::"
VERIFY_SOURCE = "core/src/slice/sort/shared/smallsort/verify"
MODULE_FILE = f"{VERIFY_SOURCE}/{MODULE}.rs"
U64_N20_N21_FILE = f"{VERIFY_SOURCE}/{U64_N20_N21_MODULE}.rs"
U64_N22_N25_PROVIDERS_FILE = f"{VERIFY_SOURCE}/{U64_N22_N25_PROVIDERS_MODULE}.rs"
U64_N13_FILE = f"{VERIFY_SOURCE}/{U64_N13_MODULE}.rs"
U64_N14_N17_FILE = f"{VERIFY_SOURCE}/{U64_N14_N17_MODULE}.rs"
U64_N18_N19_FILE = f"{VERIFY_SOURCE}/{U64_N18_N19_MODULE}.rs"
U64_COMPARATOR_LABEL = "REV2_U64_N13_COMPARATOR_CALLED"
U64_COMPARATOR_COORDINATE = (9, 5)
COPY_BACK_FILE = f"{VERIFY_SOURCE}/{COPY_BACK_MODULE}.rs"
HISTORICAL_CONSUMER_FILE = f"{VERIFY_SOURCE}/{HISTORICAL_CONSUMER_MODULE}.rs"
MERGE_FILE = f"{VERIFY_SOURCE}/{MERGE_MODULE}.rs"
SMALLSORT_FILE = "core/src/slice/sort/shared/smallsort.rs"
INSERT_COPY_COORDINATES = {
    "shift": (SMALLSORT_FILE, 722, 13),
    "gap_fill": (SMALLSORT_FILE, 362, 13),
    "ptr_wrapper": ("core/src/ptr/mod.rs", 587, 14),
}
N26_N31_HALVES_FILE = f"{VERIFY_SOURCE}/{N26_N31_HALVES_MODULE}.rs"
N26_N31_HALVES_CHECKS = {
    N26_N31_HALVES_PREFIX + name: ("slice::sort::shared::smallsort::swap_if_less", SMALLSORT_FILE)
    for name in ("s13_b14_swap", "s13_b15_swap", "s13_b16_swap")
}
COMPARATOR_FILE = f"{VERIFY_SOURCE}/cal1_model.rs"
COMPARATOR_LABEL = "CAL1 q actual comparator executed"
N22_N25_PROVIDERS_FILE = f"{VERIFY_SOURCE}/{N22_N25_PROVIDERS_MODULE}.rs"
N22_N25_PROVIDER_CHECKS = {
    N22_N25_PROVIDERS_PREFIX + "s9_b12_swap": ("slice::sort::shared::smallsort::swap_if_less", SMALLSORT_FILE),
    N22_N25_PROVIDERS_PREFIX + "n22_pair_fixed": (f"{N22_N25_PROVIDERS_PREFIX}actual_pair_step_n22", N22_N25_PROVIDERS_FILE),
    N22_N25_PROVIDERS_PREFIX + "n23_pair_fixed": (f"{N22_N25_PROVIDERS_PREFIX}actual_pair_step_n23", N22_N25_PROVIDERS_FILE),
    N22_N25_PROVIDERS_PREFIX + "n23_odd_center": (f"{N22_N25_PROVIDERS_PREFIX}actual_odd_center_n23", N22_N25_PROVIDERS_FILE),
    N22_N25_PROVIDERS_PREFIX + "n24_pair_fixed": (f"{N22_N25_PROVIDERS_PREFIX}actual_pair_step_n24", N22_N25_PROVIDERS_FILE),
    N22_N25_PROVIDERS_PREFIX + "n25_pair_fixed": (f"{N22_N25_PROVIDERS_PREFIX}actual_pair_step_n25", N22_N25_PROVIDERS_FILE),
    N22_N25_PROVIDERS_PREFIX + "n25_odd_center": (f"{N22_N25_PROVIDERS_PREFIX}actual_odd_center_n25", N22_N25_PROVIDERS_FILE),
}
U64_N26_N32_PROVIDERS_MODULE = "rev2_u64_n26_n32_providers"
U64_N26_N32_PROVIDERS_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N26_N32_PROVIDERS_MODULE}::"
U64_N26_N32_PROVIDERS_FILE = f"{VERIFY_SOURCE}/{U64_N26_N32_PROVIDERS_MODULE}.rs"
U64_N26_N32_CONSUMER_MODULE = "rev2_u64_n26_n32_consumer"
U64_N26_N32_CONSUMER_PREFIX = f"slice::sort::shared::smallsort::verify::{U64_N26_N32_CONSUMER_MODULE}::"
U64_N26_N32_CONSUMER_FILE = f"{VERIFY_SOURCE}/{U64_N26_N32_CONSUMER_MODULE}.rs"
COMPARATOR_COORDINATE = (28, 9)
COMPARATOR_INSTANCE = ("<slice::sort::shared::smallsort::verify::cal1_model::KeyLess<u8> "
                       "as ops::function::FnMut<(&u8, &u8)>>::call_mut")
PAIR_LENGTHS = (26, 27, 28, 29, 30)
ODD_LENGTHS = (27, 29, 31)
MERGE_SLOT_IDS = (*(f"N{n}-PAIR-FIXED" for n in PAIR_LENGTHS),
                  *(f"N{n}-ODD-CENTER" for n in ODD_LENGTHS))
MERGE_CHECKS = {
    **{MERGE_PREFIX + f"n{n}_pair_fixed": (MERGE_PREFIX + f"actual_pair_step_n{n}", MERGE_FILE)
       for n in PAIR_LENGTHS},
    **{MERGE_PREFIX + f"n{n}_odd_center": (MERGE_PREFIX + f"actual_odd_center_n{n}", MERGE_FILE)
       for n in ODD_LENGTHS},
}
COPY_BACK_LENGTHS = (31, 27, 29, 30)
COPY_BACK_SLOT_IDS = tuple(f"N{n}-COPY-BACK-FRAME" for n in COPY_BACK_LENGTHS)
COPY_BACK_DISCOVERY = tuple(("standard-harnesses", COPY_BACK_PREFIX + f"n{n}_copy_back_frame")
                            for n in COPY_BACK_LENGTHS)
U64_N13_SLOT_IDS = ("U64-N13-SWAP", "U64-N13-S13-BITS", "U64-N13-S13-CORRUPT")
U64_N13_DISCOVERY = tuple(("standard-harnesses", U64_N13_PREFIX + slot.lower().replace("-", "_"))
                          for slot in U64_N13_SLOT_IDS)
INSERT_SLOT_ID = "U64-N14-N17-INSERT-STEP"
NETWORK_SLOT_LENGTHS = {"U64-N17-ACTUAL-BITS": 17,
                        **{f"U64-N{n}-WITNESS-CORRUPT": n for n in (17, 14, 15, 16)}}
U64_N14_N17_SLOT_IDS = (INSERT_SLOT_ID, *NETWORK_SLOT_LENGTHS)
U64_N14_N17_DISCOVERY = tuple(("standard-harnesses", U64_N14_N17_PREFIX + slot.lower().replace("-", "_"))
                              for slot in U64_N14_N17_SLOT_IDS)
U64_N18_N19_CHECK_TARGETS = {
    "U64-N18-PAIR-STEP": "actual_pair_step_n18",
    "U64-N19-PAIR-STEP": "actual_pair_step_n19",
    "U64-N19-ODD-CENTER": "actual_odd_center_n19",
}
U64_N20_N21_CHECK_TARGETS = {
    "U64-N20-PAIR-STEP": "actual_pair_step_n20",
    "U64-N21-PAIR-STEP": "actual_pair_step_n21",
    "U64-N21-ODD-CENTER": "actual_odd_center_n21",
}
U64_N20_N21_CHECKS = {U64_N20_N21_PREFIX + slot.lower().replace("-", "_"):
                      (U64_N20_N21_PREFIX + target, U64_N20_N21_FILE)
                      for slot, target in U64_N20_N21_CHECK_TARGETS.items()}
U64_N20_N21_INSERT_GEOMETRIES = {
    "U64-B01-INSERT-REL9": (1, 9), "U64-B11-INSERT-REL9": (11, 9),
    "U64-B11-INSERT-REL10": (11, 10),
}
U64_N20_N21_SLOT_IDS = (
    *U64_N20_N21_CHECK_TARGETS, "U64-S9-B11-L11-BITS", "U64-S9-B11-SWAP",
    *U64_N20_N21_INSERT_GEOMETRIES,
)
U64_N20_N21_DISCOVERY = tuple(
    ("contract-harnesses" if slot in U64_N20_N21_CHECK_TARGETS else "standard-harnesses",
     U64_N20_N21_PREFIX + slot.lower().replace("-", "_")) for slot in U64_N20_N21_SLOT_IDS
)
U64_N18_N19_SORT9_GEOMETRIES = {"U64-S9-B01-L09-BITS": (1, 9), "U64-S9-B10-L10-BITS": (10, 10)}
U64_N18_N19_SLOT_IDS = (
    *U64_N18_N19_CHECK_TARGETS, "U64-N19-INSERT-RIGHT", *U64_N18_N19_SORT9_GEOMETRIES, "U64-S9-B10-SWAP",
)
U64_N18_N19_HISTORICAL_DISCOVERY = tuple(
    ("contract-harnesses" if slot in U64_N18_N19_CHECK_TARGETS else "standard-harnesses",
     U64_N18_N19_PREFIX + slot.lower().replace("-", "_")) for slot in U64_N18_N19_SLOT_IDS
)
U64_N18_N19_CHECKS = {U64_N18_N19_PREFIX + slot.lower().replace("-", "_"):
                     (U64_N18_N19_PREFIX + target, U64_N18_N19_FILE)
                     for slot, target in U64_N18_N19_CHECK_TARGETS.items()}
U64_N22_N25_PROVIDER_CHECK_TARGETS = {
    "U64-N25-PAIR-STEP": "actual_pair_step_n25",
    "U64-N24-PAIR-STEP": "actual_pair_step_n24",
    "U64-N23-PAIR-STEP": "actual_pair_step_n23",
    "U64-N22-PAIR-STEP": "actual_pair_step_n22",
    "U64-N25-ODD-CENTER": "actual_odd_center_n25",
    "U64-N23-ODD-CENTER": "actual_odd_center_n23",
}
U64_N22_N25_PROVIDER_CHECKS = {
    U64_N22_N25_PROVIDERS_PREFIX + slot.lower().replace("-", "_"): (
        U64_N22_N25_PROVIDERS_PREFIX + target, U64_N22_N25_PROVIDERS_FILE)
    for slot, target in U64_N22_N25_PROVIDER_CHECK_TARGETS.items()
}
SORT9_GEOMETRIES = {"U64-S9-B13-L12-BITS": (13, 12), "U64-S9-B12-L12-BITS": (12, 12)}
SWAP_SLOT_ID = "U64-S9-B12-SWAP"
S13_BITS_SLOT_ID = "U64-S13-B13-L13-BITS"
S13_SWAP_SLOT_ID = "U64-S13-B13-SWAP"
INSERT_GEOMETRIES = {"U64-B01-INSERT-REL11": (1, 11), "U64-B01-INSERT-REL10": (1, 10)}
U64_N22_N25_PROVIDER_SLOT_IDS = (
    *U64_N22_N25_PROVIDER_CHECK_TARGETS, S13_BITS_SLOT_ID, S13_SWAP_SLOT_ID, *SORT9_GEOMETRIES,
    SWAP_SLOT_ID, *INSERT_GEOMETRIES,
)
U64_N22_N25_PROVIDER_DISCOVERY = tuple(
    ("contract-harnesses" if slot in U64_N22_N25_PROVIDER_CHECK_TARGETS else "standard-harnesses",
     U64_N22_N25_PROVIDERS_PREFIX + slot.lower().replace("-", "_"))
    for slot in U64_N22_N25_PROVIDER_SLOT_IDS
)

PROVIDER_CHECK_TARGETS = {
    **{f"U64-N{n}-PAIR-STEP": f"actual_pair_step_n{n}" for n in (26, 27, 28, 29, 30, 31, 32)},
    **{f"U64-N{n}-ODD-CENTER": f"actual_odd_center_n{n}" for n in (27, 29, 31)},
}
PROVIDER_CHECKS = {U64_N26_N32_PROVIDERS_PREFIX + slot.lower().replace("-", "_"):
                   (U64_N26_N32_PROVIDERS_PREFIX + target, U64_N26_N32_PROVIDERS_FILE)
                   for slot, target in PROVIDER_CHECK_TARGETS.items()}
U64_N26_N32_PROVIDER_SLOT_IDS = ("U64-N32-PAIR-STEP", "U64-N31-PAIR-STEP", "U64-N30-PAIR-STEP",
            "U64-S13-B17-L16-BITS", "U64-S13-B17-SWAP", "U64-N29-PAIR-STEP",
            "U64-N28-PAIR-STEP", "U64-N27-PAIR-STEP", "U64-N26-PAIR-STEP",
            "U64-N31-ODD-CENTER", "U64-N29-ODD-CENTER", "U64-N27-ODD-CENTER",
            "U64-S13-B16-L16-BITS", "U64-S13-B16-SWAP", "U64-S13-B15-L15-BITS",
            "U64-S13-B15-SWAP", "U64-S13-B14-L14-BITS", "U64-S13-B14-SWAP")
U64_N26_N32_DISCOVERY = tuple(
    ("contract-harnesses" if slot in PROVIDER_CHECK_TARGETS else "standard-harnesses",
     U64_N26_N32_PROVIDERS_PREFIX + slot.lower().replace("-", "_"))
    for slot in U64_N26_N32_PROVIDER_SLOT_IDS)
CONSUMER_LENGTHS = (31, 26, 27, 28, 29, 30)
CONSUMER_SLOT_IDS = tuple(f"N{n}-{kind}" for n in CONSUMER_LENGTHS
                          for kind in ("ACTUAL-BITS", "WITNESS-CORRUPT"))
U64_N26_N32_CONSUMER_LENGTHS = (32, 31, 30, 29, 28, 27, 26)
U64_N26_N32_CONSUMER_SLOT_IDS = tuple(
    f"U64-N{n}-{kind}" for kind in ("WITNESS-CORRUPT", "COPY-BACK-FRAME")
    for n in U64_N26_N32_CONSUMER_LENGTHS)
U64_N26_N32_CONSUMER_DISCOVERY = tuple(("standard-harnesses", U64_N26_N32_CONSUMER_PREFIX +
                                        (f"u64_n{n}_witness_corrupt" if kind == "WITNESS-CORRUPT"
                                         else f"u64_n{n}_copy_back_frame"))
                                       for kind in ("WITNESS-CORRUPT", "COPY-BACK-FRAME")
                                       for n in U64_N26_N32_CONSUMER_LENGTHS)
PILOT_MODULE = "rev2_gen_stable_n16_pilot"
PILOT_MODULE_FILE = f"{VERIFY_SOURCE}/{PILOT_MODULE}.rs"
PILOT_PREFIX = f"slice::sort::shared::smallsort::verify::{PILOT_MODULE}::"
PILOT_SLOT_IDS = (
    "GEN-N16-S8-R32-FULL", "GEN-N16-S8-R32-BITS", "GEN-N16-WIDE-S4-R48",
    "GEN-N16-WIDE-FILL-R48-REL4", "GEN-N16-U64-S32-MERGE-PAIR", "GEN-N16-WIDE-S48-MERGE-PAIR",
)
PILOT_CHECK_TARGETS = {
    "GEN-N16-U64-S32-MERGE-PAIR": "actual_merge_pair_u64_s32",
    "GEN-N16-WIDE-S48-MERGE-PAIR": "actual_merge_pair_wide_s48",
}
PILOT_DISCOVERY = tuple(
    ("contract-harnesses" if slot in PILOT_CHECK_TARGETS else "standard-harnesses",
     PILOT_PREFIX + slot.lower().replace("-", "_"))
    for slot in PILOT_SLOT_IDS)
PILOT_CHECKS = {PILOT_PREFIX + slot.lower().replace("-", "_"): (PILOT_PREFIX + target, PILOT_MODULE_FILE)
                for slot, target in PILOT_CHECK_TARGETS.items()}
FIX1_PREFIX = PILOT_PREFIX + "fix1::"
FIX1_SLOT_IDS = ("GEN-N16-WIDE-S48-MERGE-UP", "GEN-N16-WIDE-S48-MERGE-DOWN")
FIX1_CHECK_TARGETS = dict(zip(FIX1_SLOT_IDS, ("actual_merge_up_wide_s48", "actual_merge_down_wide_s48")))
FIX1_DISCOVERY = tuple(("contract-harnesses", FIX1_PREFIX + slot.lower().replace("-", "_"))
                       for slot in FIX1_SLOT_IDS)
FIX1_CHECKS = {selector: (FIX1_PREFIX + FIX1_CHECK_TARGETS[slot], PILOT_MODULE_FILE)
               for slot, (_, selector) in zip(FIX1_SLOT_IDS, FIX1_DISCOVERY)}
FIX1_DECLARATION = f"#[cfg({FIX1_CFG})]\nmod fix1 {{\n"
FIX1_WIDE_COMPARATOR_LABEL = "GEN_N16_WIDE_COMPARATOR_CALLED"
FIX1_MODIFIES = {FIX1_SLOT_IDS[0]: "s.wrapping_add(k)", FIX1_SLOT_IDS[1]: "s.wrapping_add(15 - k)"}
CLOSE_MODULE_FILE = PILOT_MODULE_FILE
CLOSE_PREFIX = PILOT_PREFIX + "close::"
CLOSE_DECLARATION = f"#[cfg({CLOSE_CFG})]\nmod close {{\n"
CLOSE_SLOT_IDS = (
    "GEN-N16-S8-L32-FULL",
    "GEN-N16-WIDE-S4-L48",
    "GEN-N16-WIDE-FILL-R48-REL7",
    "GEN-N16-WIDE-FILL-R48-REL6",
    "GEN-N16-WIDE-FILL-R48-REL5",
    "GEN-N16-WIDE-WITNESS-CORRUPT",
    "GEN-N16-STABLE-U64-WITNESS-CORRUPT",
)
CLOSE_FAILURES = {
    CLOSE_SLOT_IDS[5]: "GEN_N16_WIDE_STABLE_EQUAL_KEYS",
    CLOSE_SLOT_IDS[6]: "GEN_N16_STABLE_U64_MULTIPLICITY",
}
CLOSE_U64_SLOTS = frozenset((CLOSE_SLOT_IDS[0], CLOSE_SLOT_IDS[6]))
CLOSE_DISCOVERY = tuple(("standard-harnesses", CLOSE_PREFIX + slot.lower().replace("-", "_"))
                        for slot in CLOSE_SLOT_IDS)
WIDE_WITNESS_PREFIX = PILOT_PREFIX + "close_witness_fix1::"
WIDE_WITNESS_DECLARATION = f"#[cfg({WIDE_WITNESS_CFG})]\nmod close_witness_fix1 {{\n"
WIDE_WITNESS_SLOT_ID = "GEN-N16-WIDE-WITNESS-LITERAL-CORRUPT"
WIDE_WITNESS_SELECTOR = WIDE_WITNESS_PREFIX + "gen_n16_wide_witness_literal_corrupt"
WIDE_WITNESS_DISCOVERY = (("standard-harnesses", WIDE_WITNESS_SELECTOR),)
WIDE_WITNESS_FAILURE = "GEN_N16_WIDE_STABLE_EQUAL_KEYS"
N10_WITNESS_PREFIX = PILOT_PREFIX + "n10_wide_witness::"
N10_WITNESS_DECLARATION = f"#[cfg({N10_WITNESS_CFG})]\nmod n10_wide_witness {{\n"
N10_WITNESS_SLOT_ID = "GEN-N10-WIDE-WITNESS-LITERAL-CORRUPT"
N10_WITNESS_SELECTOR = N10_WITNESS_PREFIX + "gen_n10_wide_witness_literal_corrupt"
N10_WITNESS_DISCOVERY = (("standard-harnesses", N10_WITNESS_SELECTOR),)
N10_WITNESS_FAILURE = "GEN_N10_WIDE_STABLE_EQUAL_KEYS"
N12_WITNESS_PREFIX = PILOT_PREFIX + "n12_wide_witness::"
N12_WITNESS_DECLARATION = f"#[cfg({N12_WITNESS_CFG})]\nmod n12_wide_witness {{\n"
N12_WITNESS_SLOT_ID = "GEN-N12-WIDE-WITNESS-LITERAL-CORRUPT"
N12_WITNESS_SELECTOR = N12_WITNESS_PREFIX + "gen_n12_wide_witness_literal_corrupt"
N12_WITNESS_DISCOVERY = (("standard-harnesses", N12_WITNESS_SELECTOR),)
N12_WITNESS_FAILURE = "GEN_N12_WIDE_STABLE_EQUAL_KEYS"
WIDE_N12_N14_PREFIX = PILOT_PREFIX + "wide_n12_n14::"
WIDE_N12_N14_DECLARATION = f"#[cfg({WIDE_N12_N14_CFG})]\nmod wide_n12_n14 {{\n"
# Exact stock merge_up/merge_down Checks in the N12 and N14 geometries: slot -> (N, direction).
WIDE_N12_N14_CHECK_GEOMETRY = {
    "GEN-N12-WIDE-MERGE-UP": (12, "up"), "GEN-N12-WIDE-MERGE-DOWN": (12, "down"),
    "GEN-N14-WIDE-MERGE-UP": (14, "up"), "GEN-N14-WIDE-MERGE-DOWN": (14, "down"),
}
WIDE_N12_N14_CHECK_SLOT_IDS = tuple(WIDE_N12_N14_CHECK_GEOMETRY)
WIDE_N12_N14_CHECK_TARGETS = {slot: f"actual_merge_{direction}_wide_n{n}"
                              for slot, (n, direction) in WIDE_N12_N14_CHECK_GEOMETRY.items()}
WIDE_N12_N14_MODIFIES = {slot: "s.wrapping_add(k)" if direction == "up" else f"s.wrapping_add({n - 1} - k)"
                         for slot, (n, direction) in WIDE_N12_N14_CHECK_GEOMETRY.items()}
WIDE_N12_N14_COPY_LINES = {"up": 885, "down": 918}
WIDE_N12_N14_CHECKS = {WIDE_N12_N14_PREFIX + slot.lower().replace("-", "_"):
                       (WIDE_N12_N14_PREFIX + target, PILOT_MODULE_FILE)
                       for slot, target in WIDE_N12_N14_CHECK_TARGETS.items()}
N14_WITNESS_SLOT_ID = "GEN-N14-WIDE-WITNESS-LITERAL-CORRUPT"
N14_WITNESS_SELECTOR = WIDE_N12_N14_PREFIX + "gen_n14_wide_witness_literal_corrupt"
N14_WITNESS_FAILURE = "GEN_N14_WIDE_STABLE_EQUAL_KEYS"
# The witness occupies the tail of the combined module, starting at this exact comment line.
N14_WITNESS_MARKER = "    // N14 literal witness on the actual unstable Wide entry. The rest of the module ends here.\n"
WIDE_N12_N14_DISCOVERY = (*(("contract-harnesses", selector) for selector in WIDE_N12_N14_CHECKS),
                          ("standard-harnesses", N14_WITNESS_SELECTOR))
WITNESS_SLOT_IDS = frozenset((WIDE_WITNESS_SLOT_ID, N10_WITNESS_SLOT_ID, N12_WITNESS_SLOT_ID, N14_WITNESS_SLOT_ID))
WITNESS_ROOTS = {WIDE_WITNESS_SLOT_ID: (WIDE_WITNESS_SELECTOR, WIDE_WITNESS_FAILURE),
                 N10_WITNESS_SLOT_ID: (N10_WITNESS_SELECTOR, N10_WITNESS_FAILURE),
                 N12_WITNESS_SLOT_ID: (N12_WITNESS_SELECTOR, N12_WITNESS_FAILURE),
                 N14_WITNESS_SLOT_ID: (N14_WITNESS_SELECTOR, N14_WITNESS_FAILURE)}
WIDE_N12_N14_SLOT_IDS = (*WIDE_N12_N14_CHECK_SLOT_IDS, N14_WITNESS_SLOT_ID)
N32_PREFIX = PILOT_PREFIX + "n32_pilot::"
N32_DECLARATION = f"#[cfg({N32_PILOT_CFG})]\nmod n32_pilot {{\n"
# Three plain Proof supports, then four exact stock merge Checks: slot -> (type, role).
N32_GEOMETRY = {
    "GEN-N32-U64-S8-R48-FULL": ("u64", "s8"),
    "GEN-N32-U64-FILL-R48-REL15": ("u64", "fill"),
    "GEN-N32-WIDE-FILL-R48-REL15": ("wide", "fill"),
    "GEN-N32-U64-MERGE-UP": ("u64", "up"),
    "GEN-N32-U64-MERGE-DOWN": ("u64", "down"),
    "GEN-N32-WIDE-MERGE-UP": ("wide", "up"),
    "GEN-N32-WIDE-MERGE-DOWN": ("wide", "down"),
}
N32_SLOT_IDS = tuple(N32_GEOMETRY)
N32_PLAIN_SLOT_IDS = N32_SLOT_IDS[:3]
N32_CHECK_SLOT_IDS = N32_SLOT_IDS[3:]
N32_U64_SLOT_IDS = tuple(slot for slot, (kind, _) in N32_GEOMETRY.items() if kind == "u64")
N32_CHECK_TARGETS = {slot: f"actual_merge_{role}_{kind}_n32" for slot, (kind, role) in N32_GEOMETRY.items()
                     if role in ("up", "down")}
N32_MODIFIES = {slot: "s.wrapping_add(k)" if role == "up" else "s.wrapping_add(31 - k)"
                for slot, (_, role) in N32_GEOMETRY.items() if role in ("up", "down")}
N32_COPY_LINES = {"up": 885, "down": 918}
N32_CHECKS = {N32_PREFIX + slot.lower().replace("-", "_"): (N32_PREFIX + target, PILOT_MODULE_FILE)
              for slot, target in N32_CHECK_TARGETS.items()}
N32_DISCOVERY = tuple(("contract-harnesses" if slot in N32_CHECK_TARGETS else "standard-harnesses",
                       N32_PREFIX + slot.lower().replace("-", "_")) for slot in N32_SLOT_IDS)
N32_CLOSURE_PREFIX = PILOT_PREFIX + "n32_closure::"
N32_CLOSURE_DECLARATION = f"#[cfg({N32_CLOSURE_CFG})]\nmod n32_closure {{\n"
# Three sequential plain Proof singletons: slot -> (type, role, selector name, sole expected failure or None).
N32_CLOSURE_GEOMETRY = {
    "GEN-N32-U64-S8-L48-FULL": ("u64", "s8", "gen_n32_u64_s8_l48_full", None),
    "GEN-N32-STABLE-U64-WITNESS-CORRUPT": ("u64", "witness", "gen_n32_stable_u64_witness_literal_corrupt",
                                           "GEN_N32_STABLE_U64_MULTIPLICITY"),
    "GEN-N32-WIDE-WITNESS-CORRUPT": ("wide", "witness", "gen_n32_wide_witness_literal_corrupt",
                                     "GEN_N32_WIDE_STABLE_EQUAL_KEYS"),
}
N32_CLOSURE_SLOT_IDS = tuple(N32_CLOSURE_GEOMETRY)
N32_CLOSURE_SELECTORS = {slot: N32_CLOSURE_PREFIX + name for slot, (_, _, name, _) in N32_CLOSURE_GEOMETRY.items()}
N32_CLOSURE_FAILURES = {slot: failure for slot, (_, _, _, failure) in N32_CLOSURE_GEOMETRY.items()}
N32_CLOSURE_U64_SLOT_IDS = tuple(slot for slot, (kind, *_) in N32_CLOSURE_GEOMETRY.items() if kind == "u64")
N32_CLOSURE_DISCOVERY = tuple(("standard-harnesses", N32_CLOSURE_SELECTORS[slot]) for slot in N32_CLOSURE_SLOT_IDS)
N32_WIDE_WITNESS_SLOT_ID = "GEN-N32-WIDE-WITNESS-CORRUPT"
# The Wide witness occupies the tail of the closure module, starting at this exact comment line.
N32_WIDE_WITNESS_MARKER = ("    // N32 literal witness on the actual unstable Wide entry. "
                           "The rest of the module ends here.\n")
# Three sequential singletons. By coordinator decision 2026-11-28 only the Wide N32 control runs behind
# the frozen CBMC stdout relay; the left S8 and the stable u64 control keep the stock CBMC pipe.
SLOT_IDS = N32_CLOSURE_SLOT_IDS
RELAY_SLOT_ID = N32_WIDE_WITNESS_SLOT_ID
STOCK_PIPE = "STOCK_PIPE"
STDOUT_RELAY_DELIVERY = "STDOUT_RELAY"
SLOT_STDOUT_DELIVERY = {slot: STDOUT_RELAY_DELIVERY if slot == RELAY_SLOT_ID else STOCK_PIPE for slot in SLOT_IDS}
# Each type is judged on its own slots. An OPEN Wide control does not withdraw complete u64 slots.
TYPE_SLOT_IDS = {"STABLE_U64": N32_CLOSURE_U64_SLOT_IDS,
                 "GENERAL_WIDE": tuple(slot for slot in N32_CLOSURE_SLOT_IDS if slot not in N32_CLOSURE_U64_SLOT_IDS)}
# Canonical JSON binds selectors, roles, expected outcomes, assertions, covers and profile.
SOURCE_BINDINGS_DIGEST = "14499e8075f024fae5850405fd8a208df9f51fefd3f8e6ccbb180ae35a2ec096"
ROSTER_DIGEST = "e09400caae52438f562cff8eb40ed8bae8b5c13c564bc49a17fbe41e49e4656c"
N32_PILOT_ROSTER_DIGEST = "5845e394a29f51aa9145a0510826d4a277b826e893825ba7f591713725821310"
WIDE_N12_N14_ROSTER_DIGEST = "2cb3104aeffc56f7c53332f0b6547de890668bc7d11467f7cc1d8d9d0fe16ff0"
N12_WIDE_WITNESS_N16_ROSTER_DIGEST = "7f4ae44e4063234934ed4cbcb3cec182a8ebe15cbba0e4845262acdcc8bea9cb"
N10_WITNESS_ROSTER_DIGEST = "528906a5c447b5ebfb68646a5a5ff7073efdf83e8f046e9bf915008ae228a2e7"
WIDE_WITNESS_ROSTER_DIGEST = "9241da1124f35a1ce9ade90d3ab7eddcb457a5df5c4627fba0ae1463f559a38f"
CLOSE_ROSTER_DIGEST = "0701391f3495aefc7215367d522c7759aa66d937d3de97156dd151bf3111b85b"
FIX1_ROSTER_DIGEST = "a5949152efec39e80362507c3a07a8d5b6b51ec0521e31f9a981cee33d3d29ff"
PILOT_ROSTER_DIGEST = "e9b522a49fc5bf72723c043d581cdf9c8625a612d4034f05ada08fb2f943b674"
U64_N26_N32_CONSUMER_ROSTER_DIGEST = "98a0b9778547cc039fd3364e273d2d52657bb361a40972ca5de7bae37a440e25"
U64_N26_N32_PROVIDER_ROSTER_DIGEST = "5b12d12a4d8c131a1477c2e083444473fba248bae26ecc4aa38e0d153ddf0ae3"
U64_N20_N21_ROSTER_DIGEST = "efe927152ff12c20ecb150ed7a04353dc68e500ae6b83158f91974742551bbb8"
U64_N18_N19_ROSTER_DIGEST = "2110ee3258b72773dc4edafc2795ed986808de7277d8a834c93099e820dfe0a3"
U64_N14_N17_ROSTER_DIGEST = "1e76eb9fb3386a1b1649152c4a1dc18764f4ae9ea316730dcb8fcbf925af055d"
U64_N13_ROSTER_DIGEST = "7aae46a6279ee88ecd1f894db37c0c9756f81cdb9c3399e0144b25199c035c88"
COPY_BACK_ROSTER_DIGEST = "6206fc1d9f76cc8e84129c1aecb99e36ab8b38ddd41d7f9152a9a0591a82ecbd"
MIB = 1024 ** 2
GIB_KIB = 1024 ** 2
CBMC_VERSION = "6.11.0"
LIMITS = {
    "job_seconds": 100 * 60, "planned_job_seconds": 85 * 60 + 15,
    "setup_seconds": 54 * 60, "measure_gate_seconds": 60,
    "overlay_compile_seconds": 180, "slots_seconds": 615,
    "cold_wall_seconds": 180, "reap_seconds": 10, "receipt_seconds": 5, "launch_headroom_seconds": 10,
    "post_attestation_seconds": 120, "finish_seconds": 300, "upload_seconds": 420,
    "reserve_seconds": 6 * 60, "measurement_journal_seconds": 5,
    "upload_launch_headroom_seconds": 5,
    "pick_up_vt_seconds": 120, "projection_bytes": 4 * MIB, "artifact_bytes": 96 * MIB,
    "setup_kib": 10 * GIB_KIB, "singleton_kib": 4 * GIB_KIB, "reserve_kib": 2 * GIB_KIB,
}

LATEST_START_OFFSETS = dict(zip(SLOT_IDS, (3300, 3505, 3710)))
RELAY_SOURCE_SHA256 = "c8b4c070dbd12a8acafa4b23df0b74833b600333f539b66fc9d27eccee3613b7"
# Stock Kani 9834c96ce9 cbmc_flags for this harness, then the --json-ui that run_cbmc appends.
EXPECTED_CBMC_ARGV = ["--no-malloc-may-fail", "--no-undefined-shift-check", "--no-signed-overflow-check",
                      "--nan-check", "--no-self-loops-to-assumptions", "--no-pointer-primitive-check",
                      "--unwind", "36", "--sat-solver", "cadical", "--slice-formula", "--object-bits", "12",
                      "{goto}", "--verbosity", "9", "--json-ui"]
STDOUT_RELAY = {
    "schema": "smallsort-cbmc-stdout-relay-v1", "slot": RELAY_SLOT_ID, "mode": "SPILL_THEN_REPLAY",
    "source": "ch8-cal1/cbmc_relay.py", "source_sha256": RELAY_SOURCE_SHA256,
    "path_scope": "Only the Wide N32 control verification child gets the relay first in PATH. Prepare, discovery, version attestation, the left S8 and the stable u64 control keep the stock PATH.",
    "chunk_bytes": 64 * 1024, "spill_cap_bytes": 4 * 1024 ** 3, "disk_reserve_bytes": 2 * 1024 ** 3,
    "spill_prefix_read_bytes": 16 * 1024 ** 2, "term_grace_seconds": 2.0, "census_rows_per_sample": 64,
    "expected_cbmc_argv": EXPECTED_CBMC_ARGV, "version_argv": ["--version"],
}


def slot_seconds():
    return LIMITS["cold_wall_seconds"] + LIMITS["reap_seconds"] + LIMITS["receipt_seconds"]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(path, *args, deadline=None, timeout=30, strip=True):
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("checkout identity deadline exhausted")
        timeout = min(timeout, remaining)
    output = subprocess.check_output(["git", "-C", str(path), *args], text=True, timeout=timeout)
    return output.strip() if strip else output


def git_blob(path, revision, name):
    return subprocess.check_output(["git", "-C", str(path), "cat-file", "blob", f"{revision}:{name}"], timeout=30)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else digest(source)


def digest(source):
    result = hashlib.sha256()
    for chunk in iter(lambda: source.read(MIB), b""):
        result.update(chunk)
    return result.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def roster_digest(rows):
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def load(here=HERE, *, verify_bundle=True):
    request = read(here / "CI-REQUEST.json")
    frozen = {
        "schema": "smallsort-rev2-gen-stable-n32-closure-v1", "status": "READY_FOR_REVIEW", "ledger_item": 2,
        "go": "NOT_GRANTED", "proof_credit": "NONE", "fork": FORK, "ref": REF,
        "trigger_parent": TRIGGER_PARENT, "base": list(BASE), "tool": list(TOOL),
        "cbmc_version": CBMC_VERSION, "solver": "cadical", "platform": "Linux", "architecture": "x86_64",
        "limits": LIMITS, "verify_z": ["unstable-options", *STOCK_Z],
        "overlay": list(OVERLAY), "pilot_overlay": list(PILOT_OVERLAY), "pilot_fix1_overlay": list(FIX1_OVERLAY),
        "close_overlay": list(CLOSE_OVERLAY),
        "wide_witness_overlay": list(WIDE_WITNESS_OVERLAY),
        "n10_wide_witness_overlay": list(N10_WITNESS_OVERLAY),
        "n12_wide_witness_overlay": list(N12_WITNESS_OVERLAY),
        "wide_n12_n14_overlay": list(WIDE_N12_N14_OVERLAY),
        "n32_pilot_overlay": list(N32_PILOT_OVERLAY),
        "n32_closure_overlay": list(N32_CLOSURE_OVERLAY),
        "stdout_relay": STDOUT_RELAY,
        "u64_n26_n32_consumer_overlay": list(N26_N32_CONSUMER_OVERLAY),
        "cal1_overlay": list(CAL1_OVERLAY), "cal2_overlay": list(CAL2_OVERLAY),
        "u64_n20_n21_final_overlay": list(U64_N20_N21_FINAL_OVERLAY),
        "fix3_overlay": list(FIX3_OVERLAY), "binding_overlay": list(BINDING_OVERLAY),
        "geometries_overlay": list(GEOMETRIES_OVERLAY), "consumer_overlay": list(CONSUMER_OVERLAY),
        "composite_overlay": list(COMPOSITE_OVERLAY), "n17_overlay": list(N17_OVERLAY),
        "n18_n19_providers_overlay": list(N18_N19_PROVIDERS_OVERLAY),
        "n18_n19_consumer_r1": list(N18_N19_CONSUMER_R1),
        "n18_n19_consumer_fix1": list(N18_N19_CONSUMER_FIX1),
        "n20_n21_providers_overlay": list(N20_N21_PROVIDERS_OVERLAY),
        "merge_pair_fixed_overlay": list(MERGE_PAIR_FIXED_OVERLAY),
        "n20_n21_consumer_overlay": list(N20_N21_CONSUMER_OVERLAY),
        "n22_n25_providers_overlay": list(N22_N25_PROVIDERS_OVERLAY),
        "n22_n25_consumer_overlay": list(N22_N25_CONSUMER_OVERLAY),
        "halves_overlay": list(HALVES_OVERLAY), "merge_overlay": list(MERGE_OVERLAY),
        "n26_n31_consumer_overlay": list(N26_N31_CONSUMER_OVERLAY),
        "copy_back_overlay": list(COPY_BACK_OVERLAY),
        "u64_n13_overlay": list(U64_N13_OVERLAY),
        "u64_n14_n17_overlay": list(U64_N14_N17_OVERLAY),
        "u64_n18_n19_r1_overlay": list(U64_N18_N19_R1_OVERLAY),
        "u64_n18_n19_fix1_overlay": list(U64_N18_N19_FIX1_OVERLAY),
        "latest_start_offsets_seconds": LATEST_START_OFFSETS,
        "overlay_bundle_sha256": BUNDLE_SHA256,
    }
    require(set(request) == set(frozen) | {"roster", "source_bindings"}, "unexpected frozen request keys")
    for key, expected in frozen.items():
        require(request[key] == expected, f"frozen request mismatch for {key}")
    if verify_bundle:
        require(sha256(here / "std-overlay.bundle") == BUNDLE_SHA256, "overlay bundle digest mismatch")
    require(sha256(HERE / "cbmc_relay.py") == RELAY_SOURCE_SHA256, "stdout relay source digest mismatch")
    require(roster_digest(request["source_bindings"]) == SOURCE_BINDINGS_DIGEST, "frozen source bindings mismatch")
    require(roster_digest(request["source_bindings"]["copy_back_roster"]) == COPY_BACK_ROSTER_DIGEST,
            "historical copy-back roster mismatch")
    require(roster_digest(request["source_bindings"]["u64_n13_roster"]) == U64_N13_ROSTER_DIGEST,
            "historical u64 N13 roster mismatch")
    require(roster_digest(request["source_bindings"]["u64_n14_n17_roster"]) == U64_N14_N17_ROSTER_DIGEST,
            "historical u64 N14/N17 roster mismatch")
    require(roster_digest(request["source_bindings"]["u64_n20_n21_roster"]) == U64_N20_N21_ROSTER_DIGEST,
            "historical u64 N20/N21 roster mismatch")
    require(roster_digest(request["source_bindings"]["u64_n18_n19_roster"]) == U64_N18_N19_ROSTER_DIGEST,
            "historical u64 N18/N19 roster mismatch")
    rows = request["roster"]
    require(roster_digest(rows) == ROSTER_DIGEST, "frozen roster mismatch")
    bindings = request["source_bindings"]
    require(len(rows) == 3 and bindings.get("n32_closure_roster") == rows, "frozen N32 closure source roster mismatch")
    require(roster_digest(bindings.get("n32_pilot_roster")) == N32_PILOT_ROSTER_DIGEST,
            "historical N32 pilot roster mismatch")
    require(roster_digest(bindings.get("wide_n12_n14_roster")) == WIDE_N12_N14_ROSTER_DIGEST,
            "historical Wide N12/N14 roster mismatch")
    # Only the Wide control is a relay slot. The left S8 and the u64 control keep the stock CBMC pipe.
    require(STDOUT_RELAY["slot"] == RELAY_SLOT_ID == N32_WIDE_WITNESS_SLOT_ID
            and [row.get("stdout_delivery") for row in rows] == [SLOT_STDOUT_DELIVERY[slot] for slot in SLOT_IDS]
            and [row.get("stdout_delivery") for row in rows] == [STOCK_PIPE, STOCK_PIPE, STDOUT_RELAY_DELIVERY],
            "N32 closure stdout delivery must be stock for S8 and u64 and the relay for the Wide control")
    require(roster_digest([*bindings.get("n12_wide_witness_roster", []), *bindings.get("wide_witness_roster", [])])
            == N12_WIDE_WITNESS_N16_ROSTER_DIGEST, "historical N12 and FIX2 N16 witness rosters mismatch")
    require(roster_digest(bindings.get("n10_wide_witness_roster")) == N10_WITNESS_ROSTER_DIGEST,
            "historical N10 Wide witness roster mismatch")
    require(roster_digest(bindings.get("wide_witness_roster")) == WIDE_WITNESS_ROSTER_DIGEST,
            "historical N16 Wide witness roster mismatch")
    require(roster_digest(request["source_bindings"].get("pilot_close_roster")) == CLOSE_ROSTER_DIGEST,
            "historical CLOSE roster mismatch")
    require(roster_digest(request["source_bindings"].get("pilot_fix1_roster")) == FIX1_ROSTER_DIGEST,
            "historical FIX1 roster mismatch")
    require(roster_digest(request["source_bindings"].get("pilot_roster")) == PILOT_ROSTER_DIGEST,
            "historical pilot roster mismatch")
    require(roster_digest(request["source_bindings"].get("u64_n26_n32_consumer_roster")) ==
            U64_N26_N32_CONSUMER_ROSTER_DIGEST, "historical u64 N26/N32 consumer roster mismatch")
    require(roster_digest(request["source_bindings"].get("u64_n26_n32_providers_roster")) ==
            U64_N26_N32_PROVIDER_ROSTER_DIGEST,
            "historical u64 N26/N32 provider roster mismatch")
    require(tuple(row["id"] for row in rows) == SLOT_IDS and all(
        row["seconds"] == slot_seconds() and row["cfg"] == CFG and row["unwind"] == 36 and row["object_bits"] == 12
        for row in rows), "singleton profile mismatch")
    return request


def identity(path, expected, *, check_submodules=True, deadline=None):
    sha = git(path, "rev-parse", "HEAD", deadline=deadline)
    tree = git(path, "rev-parse", "HEAD^{tree}", deadline=deadline)
    require((sha, tree) == tuple(expected), f"checkout mismatch in {path}: {sha}/{tree}")
    require(not git(path, "branch", "--show-current", deadline=deadline), f"expected detached checkout in {path}")
    # Verify all initialized submodule indexes and HEADs, including recursive dirt.
    modules = git(path, "submodule", "status", "--recursive", deadline=deadline,
                  timeout=45, strip=False).splitlines() if check_submodules else []
    require(all(line.startswith(" ") for line in modules), f"uninitialized or drifted submodule in {path}")
    require(not git(path, "status", "--porcelain=v1", "--untracked-files=all",
                    "--ignore-submodules=none", deadline=deadline), f"dirty checkout in {path}")
    return {"commit": sha, "tree": tree, "submodules": modules, "clean": True,
            "submodules_checked": check_submodules, "path": str(path)}


def check_trigger(path=REPO, env=os.environ, *, deadline=None):
    expected_tree = env.get(TRIGGER_TREE_ENV)
    require(isinstance(expected_tree, str) and re.fullmatch(r"[0-9a-fA-F]{40}", expected_tree),
            "approved trigger tree is missing or malformed")
    expected_tree = expected_tree.lower()
    require(env.get("GITHUB_REPOSITORY") == FORK and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_REF") == REF, "fork/push/exact-ref guard rejected the run")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1", "REV2 admits only the first run attempt")
    sha, *parents = git(path, "rev-list", "--parents", "-n", "1", "HEAD", deadline=deadline).split()
    event = read(Path(env["GITHUB_EVENT_PATH"]))
    require(sha == env.get("GITHUB_SHA") == event.get("after") and event.get("ref") == REF
            and event.get("deleted") is False and event.get("repository", {}).get("full_name") == FORK
            and parents == [TRIGGER_PARENT], "trigger SHA or sole commit parent mismatch")
    require(git(path, "rev-parse", "HEAD^{tree}", deadline=deadline) == expected_tree, "trigger tree mismatch")
    data = identity(path, (sha, expected_tree), check_submodules=False, deadline=deadline)
    return data | {"parent": parents[0], "repository": FORK, "ref": REF, "event": "push",
                   "approved_tree": expected_tree,
                   "push_before": event.get("before"), "push_forced": event.get("forced"),
                   "run_id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"]}


def check_cal2_layout(std, overlay):
    """Recover the exact base blobs by removing the added opt-in items."""
    root = "library/core/src/slice/sort/shared/smallsort"
    cargo = "library/core/Cargo.toml"
    core = "library/core/src/lib.rs"
    original = {root + ".rs", root + "/verify.rs", cargo, core}
    paths = git(std, "diff", "--name-status", BASE[0], overlay).splitlines()
    additions = set()
    for line in paths:
        status, name = line.split("\t", 1)
        if status == "A" and re.fullmatch(re.escape(root) + r"/verify/cal1(?:_[a-z_]+)?\.rs", name):
            additions.add(Path(name).stem)
        else:
            require(status == "M" and name in original, f"overlay changed out-of-scope source: {line}")
    require({"cal1", "cal1_direct"}.issubset(additions), "overlay lacks a root module")
    modules = git(std, "show", f"{overlay}:{root}/verify.rs", strip=False)
    pattern = r"^#\[cfg\(kani_smallsort_cal1\)\]\n(?:pub\(super\) )?mod (cal1(?:_[a-z_]+)?);\n"
    require(set(re.findall(pattern, modules, re.M)) == additions, "overlay module cfg or linkage mismatch")
    require(re.sub(pattern, "", modules, flags=re.M) == git(std, "show", f"{BASE[0]}:{root}/verify.rs", strip=False),
            "ordinary verification source changed")
    body = git(std, "show", f"{overlay}:{root}.rs", strip=False)
    guarded = r"^#\[cfg_attr\(\n    all\(kani, kani_smallsort_cal1\),\n.*?^\)\]\n"
    require(re.sub(guarded, "", body, flags=re.M | re.S) == git(std, "show", f"{BASE[0]}:{root}.rs", strip=False),
            "SmallSort runtime or cfg-off attributes changed")
    manifest = git_blob(std, overlay, cargo).splitlines(keepends=True)
    for flag in CFG[:2]:
        declaration = f"    'cfg({flag})',\n".encode("ascii")
        require(manifest.count(declaration) == 1, "missing or duplicate cfg lint declaration")
        manifest.remove(declaration)
    require(b"".join(manifest) == git_blob(std, BASE[0], cargo),
            "core Cargo manifest changed outside the two cfg lint declarations")
    gate = b"#![cfg_attr(all(kani, kani_smallsort_cal1), feature(fn_traits))]\n"
    updated = git_blob(std, overlay, core)
    base = git_blob(std, BASE[0], core)
    require(f"M\t{core}" in paths and updated.splitlines(keepends=True).count(gate) == 1
            and updated.replace(gate, b"", 1) == base, "core lib.rs changed outside the CAL1 fn_traits gate")
    require(git(std, "ls-tree", "--format=%(objectmode)", BASE[0], "--", core) ==
            git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", core), "core lib.rs mode changed")
    observer = root + "/verify/cal1_q_merge_model.rs"
    prior = CAL1_OVERLAY[0]
    require(git(std, "diff", "--name-status", prior, overlay).splitlines() == [f"M\t{cargo}", f"M\t{observer}"],
            "CAL2 overlay changed sources outside the manifest and observer")
    old = "        let target = if len == 32 {\n"
    new = f"        let target = if len == 32 && !cfg!({CFG[1]}) {{\n"
    before = git(std, "show", f"{prior}:{observer}", strip=False)
    require(before.count(old) == 1 and before.replace(old, new, 1) ==
            git(std, "show", f"{overlay}:{observer}", strip=False), "unexpected CAL2 observer change")
    for path in (cargo, observer):
        require(git(std, "ls-tree", "--format=%(objectmode)", prior, "--", path) ==
                git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", path), f"{path} mode changed")
    return paths


def check_fix3_layout(std, overlay):
    """Recover the byte-exact CAL2 source outside the provider-cost guards."""
    prior = CAL2_OVERLAY[0]
    check_cal2_layout(std, prior)
    root = "library/core/src/slice/sort/shared/smallsort"
    manifest = "library/core/Cargo.toml"
    registry = root + "/verify.rs"
    module = root + "/verify/rev2_provider_cost.rs"
    sort = root + ".rs"
    paths = git(std, "diff", "--name-status", prior, overlay).splitlines()
    require(paths == [f"M\t{manifest}", f"M\t{sort}", f"M\t{registry}", f"A\t{module}"],
            "REV2 overlay changed out-of-scope paths")
    for path in (manifest, sort, registry):
        require(git(std, "ls-tree", "--format=%(objectmode)", prior, "--", path) ==
                git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", path), f"{path} mode changed")
    require(git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", module) == "100644",
            "REV2 verification module mode mismatch")
    declaration = b"    'cfg(kani_smallsort_rev2_provider_cost)',\n"
    new_manifest = git_blob(std, overlay, manifest)
    require(new_manifest.splitlines(keepends=True).count(declaration) == 1 and
            new_manifest.replace(declaration, b"", 1) == git_blob(std, prior, manifest),
            "REV2 manifest changed outside the lint declaration")
    module_gate = rb"^#\[cfg\(all\(\s*kani_smallsort_cal1,\s*kani_smallsort_cal2_merge_mask,\s*" \
        rb"kani_smallsort_rev2_provider_cost,?\s*\)\)\]\npub\(super\) mod rev2_provider_cost;\n"
    stripped, gates = re.subn(module_gate, b"", git_blob(std, overlay, registry), flags=re.M)
    require(gates == 1 and stripped == git_blob(std, prior, registry), "REV2 module cfg or cfg-off registry mismatch")
    attr_gate = rb"^#\[cfg_attr\(\s*all\(\s*kani,\s*kani_smallsort_cal1,\s*" \
        rb"kani_smallsort_cal2_merge_mask,\s*kani_smallsort_rev2_provider_cost,?\s*\),\n.*?^\)\]\n(?=unsafe fn swap_if_less<)"
    stripped, gates = re.subn(attr_gate, b"", git_blob(std, overlay, sort), flags=re.M | re.S)
    require(gates == 1 and stripped == git_blob(std, prior, sort), "REV2 runtime or cfg-off swap mismatch")
    return paths


def check_opt_in_layout(std, prior, overlay, name, cfg, *, single_cfg=False, inline_cfg=False,
                        visibility_path=None):
    """Check an opt-in source delta and recover its exact preceding registry and manifest."""
    root = "library/core/src/slice/sort/shared/smallsort"
    manifest = "library/core/Cargo.toml"
    registry = root + "/verify.rs"
    module = f"{root}/verify/{name}.rs"
    paths = git(std, "diff", "--name-status", prior, overlay).splitlines()
    modified = [manifest, registry] + ([visibility_path] if visibility_path else [])
    require(paths == [*(f"M\t{path}" for path in modified), f"A\t{module}"],
            f"{name} overlay changed out-of-scope paths")
    for path in modified:
        require(git(std, "ls-tree", "--format=%(objectmode)", prior, "--", path) ==
                git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", path), f"{path} mode changed")
    require(git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", module) == "100644",
            f"{name} verification module mode mismatch")
    declaration = f"    'cfg({cfg[-1]})',\n".encode("ascii")
    if single_cfg:
        condition = cfg[-1]
    elif inline_cfg or visibility_path:
        condition = f"all({', '.join(cfg)})"
    else:
        cfg_lines = ",\n".join(f"    {flag}" for flag in cfg)
        condition = f"all(\n{cfg_lines}\n)"
    gate = f"#[cfg({condition})]\nmod {name};\n".encode("ascii")
    for path, addition in ((manifest, declaration), (registry, gate)):
        updated = git_blob(std, overlay, path)
        require(updated.count(addition) == 1 and updated.replace(addition, b"", 1) == git_blob(std, prior, path),
                f"{name} cfg or cfg-off blob mismatch in {path}")
    if visibility_path:
        old = git_blob(std, prior, visibility_path)
        new = git_blob(std, overlay, visibility_path)
        item = b"\npub(super) fn u64_less("
        require(new.count(item) == 1 and new.replace(item, b"\nfn u64_less(", 1) == old,
                "historical u64 comparator changed beyond its visibility")
    return paths


def check_overlay_layout(std, overlay):
    consumer = CONSUMER_OVERLAY[0]
    composite = COMPOSITE_OVERLAY[0]
    n18_providers = N18_N19_PROVIDERS_OVERLAY[0]
    n18_consumer_r1 = N18_N19_CONSUMER_R1[0]
    n18_consumer_fix1 = N18_N19_CONSUMER_FIX1[0]
    check_fix3_layout(std, FIX3_OVERLAY[0])
    check_opt_in_layout(std, FIX3_OVERLAY[0], BINDING_OVERLAY[0], "rev2_s13_binding", CFG[:4])
    check_opt_in_layout(std, BINDING_OVERLAY[0], GEOMETRIES_OVERLAY[0], "rev2_s13_geometries", CFG[:5])
    check_opt_in_layout(std, GEOMETRIES_OVERLAY[0], consumer, "rev2_n32_consumer", CFG[:6])
    check_composite_layout(std, consumer, composite)
    check_opt_in_layout(std, composite, N17_OVERLAY[0], "rev2_n17", CFG[:8])
    check_opt_in_layout(std, N17_OVERLAY[0], n18_providers, N18_N19_PROVIDERS_MODULE, CFG[:9])
    check_opt_in_layout(std, n18_providers, n18_consumer_r1, N18_N19_CONSUMER_MODULE, CFG[:10])
    consumer_module = ("library/core/src/slice/sort/shared/smallsort/verify/"
                       "rev2_n18_n19_consumer.rs")
    consumer_fix = (
        b"        // Down consumes all nine left ones, leaving the odd byte on the right.\n"
        b"        kani::cover(\n"
        b"            input_mask == N19_LEFT_REVERSE_SENTINEL,\n"
        b"            \"REV2_N19_ACTUAL_ODD_RIGHT_REMAINDER_LEFT_REVERSE_SENTINEL\",\n"
        b"        );",
        b"        // Down consumes all nine left ones. The left reverse cursor reaches S-1.\n"
        b"        let sentinel = input_mask == N19_LEFT_REVERSE_SENTINEL;\n"
        b"        kani::cover(sentinel, \"REV2_N19_ACTUAL_ODD_RIGHT_REMAINDER_LEFT_REVERSE_SENTINEL\");",
    )
    require(git(std, "diff", "--name-status", n18_consumer_r1, n18_consumer_fix1).splitlines() ==
            [f"M\t{consumer_module}"], "N18/N19 consumer FIX1 changed unexpected files")
    r1_blob = git_blob(std, n18_consumer_r1, consumer_module)
    fixed_blob = git_blob(std, n18_consumer_fix1, consumer_module)
    require(r1_blob.count(consumer_fix[0]) == 1 and
            r1_blob.replace(consumer_fix[0], consumer_fix[1], 1) == fixed_blob,
            "N18/N19 consumer FIX1 source delta mismatch")
    n20_providers = N20_N21_PROVIDERS_OVERLAY[0]
    merge_pair_fixed = MERGE_PAIR_FIXED_OVERLAY[0]
    check_opt_in_layout(std, n18_consumer_fix1, n20_providers, N20_N21_PROVIDERS_MODULE, CFG[:11])
    check_opt_in_layout(std, n20_providers, merge_pair_fixed, MERGE_PAIR_FIXED_MODULE, CFG[:12])
    prior = N20_N21_CONSUMER_OVERLAY[0]
    check_opt_in_layout(std, merge_pair_fixed, prior, N20_N21_CONSUMER_MODULE, CFG[:13])
    providers = N22_N25_PROVIDERS_OVERLAY[0]
    check_opt_in_layout(std, prior, providers, N22_N25_PROVIDERS_MODULE, CFG[:14])
    check_opt_in_layout(std, providers, N22_N25_CONSUMER_OVERLAY[0], "rev2_n22_n25_consumer", CFG[:15])
    check_opt_in_layout(std, N22_N25_CONSUMER_OVERLAY[0], HALVES_OVERLAY[0], N26_N31_HALVES_MODULE, CFG[:16])
    check_opt_in_layout(std, HALVES_OVERLAY[0], MERGE_OVERLAY[0], MERGE_MODULE, CFG[:17])
    check_opt_in_layout(std, MERGE_OVERLAY[0], N26_N31_CONSUMER_OVERLAY[0], HISTORICAL_CONSUMER_MODULE, CFG[:18])
    check_opt_in_layout(std, N26_N31_CONSUMER_OVERLAY[0], COPY_BACK_OVERLAY[0],
                        COPY_BACK_MODULE, CFG[:19], single_cfg=True)
    check_opt_in_layout(std, COPY_BACK_OVERLAY[0], U64_N13_OVERLAY[0], U64_N13_MODULE, CFG[:20], single_cfg=True)
    prior = U64_N14_N17_OVERLAY[0]
    check_opt_in_layout(std, U64_N13_OVERLAY[0], prior, U64_N14_N17_MODULE, CFG[19:21],
                        visibility_path=f"library/{U64_N13_FILE}")
    for revision in (U64_N18_N19_R1_OVERLAY[0], U64_N18_N19_FIX1_OVERLAY[0]):
        check_opt_in_layout(std, prior, revision, U64_N18_N19_MODULE, (CFG[19], CFG[21]), inline_cfg=True)
    old_final = U64_N20_N21_FINAL_OVERLAY[0]
    check_opt_in_layout(std, U64_N18_N19_FIX1_OVERLAY[0], old_final, "rev2_u64_n20_n21",
                        (CFG[19], CFG[22]), inline_cfg=True)
    providers = N22_N25_FINAL_OVERLAY[0]
    check_opt_in_layout(std, old_final, providers, U64_N22_N25_PROVIDERS_MODULE,
                        (CFG[19], CFG[23]), inline_cfg=True)
    check_opt_in_layout(std, providers, N26_N32_PROVIDERS_OVERLAY[0], U64_N26_N32_PROVIDERS_MODULE,
                        (CFG[19], CFG[24]), inline_cfg=True)
    check_opt_in_layout(std, N26_N32_PROVIDERS_OVERLAY[0], N26_N32_CONSUMER_OVERLAY[0],
                        U64_N26_N32_CONSUMER_MODULE, (CFG[19], CFG[25]), inline_cfg=True)
    check_opt_in_layout(std, N26_N32_CONSUMER_OVERLAY[0], PILOT_OVERLAY[0], PILOT_MODULE,
                        (CFG[19], CFG[26]), inline_cfg=True)
    check_appended_layout(std, PILOT_OVERLAY[0], FIX1_OVERLAY[0], FIX1_CFG, FIX1_DECLARATION)
    check_appended_layout(std, FIX1_OVERLAY[0], CLOSE_R1_OVERLAY[0], CLOSE_CFG, CLOSE_DECLARATION)
    require(git(std, "diff", "--name-status", CLOSE_R1_OVERLAY[0], CLOSE_OVERLAY[0]).splitlines() ==
            [f"M\tlibrary/{CLOSE_MODULE_FILE}"], "CLOSE FIX1 must modify only the proof module")
    check_appended_layout(std, FIX1_OVERLAY[0], CLOSE_OVERLAY[0], CLOSE_CFG, CLOSE_DECLARATION)
    check_appended_layout(std, CLOSE_OVERLAY[0], WIDE_WITNESS_OVERLAY[0], WIDE_WITNESS_CFG, WIDE_WITNESS_DECLARATION)
    check_appended_layout(std, WIDE_WITNESS_OVERLAY[0], N10_WITNESS_OVERLAY[0], N10_WITNESS_CFG, N10_WITNESS_DECLARATION)
    check_appended_layout(std, N10_WITNESS_OVERLAY[0], N12_WITNESS_OVERLAY[0], N12_WITNESS_CFG, N12_WITNESS_DECLARATION)
    check_appended_layout(std, N12_WITNESS_OVERLAY[0], WIDE_N12_N14_OVERLAY[0], WIDE_N12_N14_CFG,
                          WIDE_N12_N14_DECLARATION)
    check_appended_layout(std, WIDE_N12_N14_OVERLAY[0], N32_PILOT_OVERLAY[0], N32_PILOT_CFG, N32_DECLARATION)
    return check_appended_layout(std, N32_PILOT_OVERLAY[0], overlay, N32_CLOSURE_CFG, N32_CLOSURE_DECLARATION)


def check_appended_layout(std, prior, overlay, cfg, declaration):
    manifest = "library/core/Cargo.toml"
    module = f"library/{PILOT_MODULE_FILE}"
    paths = git(std, "diff", "--name-status", prior, overlay).splitlines()
    require(paths == [f"M\t{manifest}", f"M\t{module}"], f"{cfg} changed out-of-scope paths")
    for file in (manifest, module):
        require(git(std, "ls-tree", "--format=%(objectmode)", prior, "--", file) ==
                git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", file), f"{file} mode changed")
    manifest_addition = f"    'cfg({cfg})',\n".encode("ascii")
    current = git_blob(std, overlay, manifest)
    require(current.count(manifest_addition) == 1
            and current.replace(manifest_addition, b"", 1) == git_blob(std, prior, manifest),
            f"{cfg} check-cfg or cfg-off manifest differs")
    old = git_blob(std, prior, module)
    current = git_blob(std, overlay, module)
    declaration = declaration.encode("ascii")
    require(current.startswith(old + b"\n" + declaration) and current.count(declaration) == 1
            and current.endswith(b"\n}\n"), f"{cfg} must append exactly one opt-in submodule")
    return paths


def source_file_matches(observed, expected):
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    observed = observed.replace("\\", "/")
    expected = expected.replace("\\", "/")
    return observed == expected or observed.endswith("/" + expected)


def check_source_bindings(std, request, *, deadline=None):
    """Read source blobs and assert the literal at each 1-based byte coordinate."""
    overlay = request["overlay"][0]
    bindings = request["source_bindings"]
    require("historical_blobs" in bindings, "missing historical_blobs in source bindings")
    sources = {}
    for file, blob in bindings["blobs"].items():
        require(git(std, "rev-parse", f"{overlay}:library/{file}", deadline=deadline) == blob,
                f"pinned source blob differs for {file}")
    for revision, files in bindings["historical_blobs"].items():
        for file, blob in files.items():
            historical_n13 = revision == U64_N13_OVERLAY[0] and file == U64_N13_FILE
            historical_pilot = (revision in (PILOT_OVERLAY[0], FIX1_OVERLAY[0])
                                and file in (PILOT_MODULE_FILE, "core/Cargo.toml"))
            historical_close = (revision == CLOSE_R1_OVERLAY[0] and file == CLOSE_MODULE_FILE or
                                revision in (CLOSE_OVERLAY[0], WIDE_WITNESS_OVERLAY[0], N10_WITNESS_OVERLAY[0],
                                             N12_WITNESS_OVERLAY[0], WIDE_N12_N14_OVERLAY[0], N32_PILOT_OVERLAY[0])
                                and file in (CLOSE_MODULE_FILE, "core/Cargo.toml"))
            require((historical_n13 or historical_pilot or historical_close or bindings["blobs"].get(file) == blob) and
                    git(std, "rev-parse", f"{revision}:library/{file}", deadline=deadline) == blob,
                    f"historical source blob differs at {revision}:{file}")
    for anchor in bindings["coordinates"]:
        file, line, column, token = (anchor[field] for field in ("file", "line", "column", "token"))
        require(file in bindings["blobs"] and type(line) is int and line > 0
                and type(column) is int and column > 0, "invalid pinned source coordinate")
        if file not in sources:
            sources[file] = git_blob(std, overlay, f"library/{file}").splitlines()
        lines = sources[file]
        require(line <= len(lines) and lines[line - 1][column - 1:].startswith(token.encode("utf-8")),
                f"pinned source coordinate differs at {file}:{line}:{column}")
    source = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8")
    swaps = re.compile(r"(?m)^([ ]*)swap_if_less\(v_base, (\d+), (\d+), is_less\);$")
    for length, count in ((13, 45), (9, 25)):
        body = re.search(rf"(?ms)^fn sort{length}_optimal<.*?^}}", source)
        require(body is not None, f"missing actual sort{length} body")
        observed = [
            {"line": source.count("\n", 0, body.start() + match.start()) + 1,
             "column": len(match[1]) + 1, "a": int(match[2]), "b": int(match[3])}
            for match in swaps.finditer(body[0])
        ]
        require(len(observed) == body[0].count("swap_if_less(") == count
                and all(0 <= pair["a"] < pair["b"] < length for pair in observed)
                and observed == bindings[f"sort{length}_swaps"], f"actual sort{length} swap schedule mismatch")
    return bindings


def check_native_coordinates(std, overlay, rows, *, module_file=MODULE_FILE, prefix=None):
    """Bind every required assertion/cover coordinate to the pinned source blobs."""
    module_source = git_blob(std, overlay, f"library/{module_file}").decode("utf-8")
    comparator_source = git_blob(std, overlay, f"library/{COMPARATOR_FILE}").decode("utf-8")
    module_calls = labelled_calls(module_source)
    comparator_calls = labelled_calls(comparator_source)
    require(COMPARATOR_COORDINATE in comparator_calls.get(COMPARATOR_LABEL, []),
            "actual comparator cover coordinate differs from pinned FnMut source")
    observed = set()
    prefix = prefix or {MODULE_FILE: PREFIX, U64_N13_FILE: U64_N13_PREFIX,
              U64_N14_N17_FILE: U64_N14_N17_PREFIX, U64_N18_N19_FILE: U64_N18_N19_PREFIX,
              U64_N20_N21_FILE: U64_N20_N21_PREFIX,
              U64_N22_N25_PROVIDERS_FILE: U64_N22_N25_PROVIDERS_PREFIX,
              U64_N26_N32_CONSUMER_FILE: U64_N26_N32_CONSUMER_PREFIX,
              PILOT_MODULE_FILE: PILOT_PREFIX}.get(module_file)
    fix1 = prefix == FIX1_PREFIX
    close = prefix == CLOSE_PREFIX
    combined = prefix == WIDE_N12_N14_PREFIX
    n32 = prefix == N32_PREFIX
    closure = prefix == N32_CLOSURE_PREFIX
    witness = prefix in (WIDE_WITNESS_PREFIX, N10_WITNESS_PREFIX, N12_WITNESS_PREFIX)
    declaration = {FIX1_PREFIX: FIX1_DECLARATION, CLOSE_PREFIX: CLOSE_DECLARATION,
                   WIDE_WITNESS_PREFIX: WIDE_WITNESS_DECLARATION,
                   N10_WITNESS_PREFIX: N10_WITNESS_DECLARATION,
                   N12_WITNESS_PREFIX: N12_WITNESS_DECLARATION,
                   WIDE_N12_N14_PREFIX: WIDE_N12_N14_DECLARATION,
                   N32_PREFIX: N32_DECLARATION,
                   N32_CLOSURE_PREFIX: N32_CLOSURE_DECLARATION}.get(prefix)
    if declaration:
        require(module_file == PILOT_MODULE_FILE and module_source.count(declaration) == 1,
                "missing or ambiguous opt-in module source")
        module_start = module_source.count("\n", 0, module_source.index(declaration)) + 1
        module_calls = {
            label: scoped for label, coords in module_calls.items()
            if (scoped := [(line, col) for line, col in coords
                           if line > module_start or label == FIX1_WIDE_COMPARATOR_LABEL])
        }
    typed = prefix is not None
    if typed:
        u64_source = git_blob(std, overlay, f"library/{U64_N13_FILE}").decode("utf-8")
        require(labelled_calls(u64_source).get(U64_COMPARATOR_LABEL) == [U64_COMPARATOR_COORDINATE],
                "shared u64 comparator cover moved")
    lines = module_source.splitlines()
    indent = r" {0,4}" if declaration else ""
    definition = re.compile(rf"^{indent}(?:pub\(super\) )?(?:unsafe )?fn (\w+)")
    for row in rows:
        native = row.get("native_evidence")
        if not native:
            continue
        failure = row.get("expected_failure")
        if failure:
            anchor = native["coordinates"].get(failure["label"])
            keys = ("file", "line", "column", "function", "class") if typed else (
                "file", "line", "column", "function")
            require(anchor is not None and all(failure[key] == anchor[key] for key in keys),
                    f"{row['id']} failure coordinate differs from the pinned post coordinate")
        for label, coordinate in native["coordinates"].items():
            file = coordinate["file"]
            expected = (coordinate["line"], coordinate["column"])
            if label == COMPARATOR_LABEL:
                require(file == COMPARATOR_FILE and expected == COMPARATOR_COORDINATE,
                        f"{row['id']} comparator coordinate differs from the pinned FnMut source")
                continue
            if typed and label == U64_COMPARATOR_LABEL:
                require(file == U64_N13_FILE and expected == U64_COMPARATOR_COORDINATE
                        and coordinate["function"] == U64_N13_PREFIX + "u64_less"
                        and coordinate["class"] == "cover" and label in row["covers"],
                        f"{row['id']} shared u64 comparator coordinate mismatch")
                if module_file == U64_N13_FILE:
                    observed.add(label)
                continue
            require(file == module_file and module_calls.get(label) == [expected],
                    f"{row['id']} {label}: expected {expected}, source has {module_calls.get(label, [])}")
            if typed:
                line, column = expected
                cls = "cover" if label in row["covers"] else "assertion"
                call = "cover" if cls == "cover" else "assert"
                name = next(match[1] for entry in reversed(lines[:line])
                            if (match := definition.match(entry)))
                if name == "check_s13":
                    name += "::<true>" if failure else "::<false>"
                if name == "check_network":
                    name += f"::<{NETWORK_SLOT_LENGTHS[row['id']]}>"
                if name == "check_sort9_bits":
                    base, length = U64_N18_N19_SORT9_GEOMETRIES[row["id"]]
                    name += f"::<{base}, {length}>"
                if name == "check_insert":
                    if module_file == U64_N20_N21_FILE:
                        base, rel = U64_N20_N21_INSERT_GEOMETRIES[row["id"]]
                        name += f"::<{base}, {rel}>"
                    elif module_file == U64_N22_N25_PROVIDERS_FILE:
                        _, rel = INSERT_GEOMETRIES[row["id"]]
                        name += f"::<{rel}>"
                    else:
                        _, rel = INSERT_GEOMETRIES[row["id"]]
                        name += f"::<{rel}>"
                if module_file == U64_N26_N32_CONSUMER_FILE:
                    length = int(row["id"].split("-")[1][1:])
                    name += f"::<{length}>"
                scope = PILOT_PREFIX if declaration and line < module_start else prefix
                require(coordinate["class"] == cls and coordinate["function"] == scope + name
                        and lines[line - 1][column - 1:].startswith(f"kani::{call}("),
                        f"{row['id']} {label}: native function or class differs from the pinned source")
            observed.add(label)
    pilot_slots = {
        CLOSE_PREFIX: (CLOSE_SLOT_IDS, {}),
        FIX1_PREFIX: (FIX1_SLOT_IDS, FIX1_CHECK_TARGETS),
        WIDE_WITNESS_PREFIX: ((WIDE_WITNESS_SLOT_ID,), {}),
        N10_WITNESS_PREFIX: ((N10_WITNESS_SLOT_ID,), {}),
        N12_WITNESS_PREFIX: ((N12_WITNESS_SLOT_ID,), {}),
        WIDE_N12_N14_PREFIX: (WIDE_N12_N14_SLOT_IDS, WIDE_N12_N14_CHECK_TARGETS),
        N32_PREFIX: (N32_SLOT_IDS, N32_CHECK_TARGETS),
        N32_CLOSURE_PREFIX: (N32_CLOSURE_SLOT_IDS, {}),
    }
    check_modules = {
        MODULE_FILE: (U64_N26_N32_PROVIDER_SLOT_IDS, PROVIDER_CHECK_TARGETS),
        U64_N22_N25_PROVIDERS_FILE: (U64_N22_N25_PROVIDER_SLOT_IDS, U64_N22_N25_PROVIDER_CHECK_TARGETS),
        U64_N20_N21_FILE: (U64_N20_N21_SLOT_IDS, U64_N20_N21_CHECK_TARGETS),
        U64_N18_N19_FILE: (U64_N18_N19_SLOT_IDS, U64_N18_N19_CHECK_TARGETS),
        U64_N26_N32_CONSUMER_FILE: (U64_N26_N32_CONSUMER_SLOT_IDS, {}),
        PILOT_MODULE_FILE: pilot_slots.get(prefix, (PILOT_SLOT_IDS, PILOT_CHECK_TARGETS)),
    }
    if module_file in check_modules:
        slots, targets = check_modules[module_file]
        for row in rows:
            if row["id"] in slots:
                check_provider_definition(module_source, row, module_file=module_file, prefix=prefix,
                                          check=targets.get(row["id"]))
    if fix1:
        check_fix1_copy_sites(std, overlay, rows, module_source)
    elif n32:
        check_n32_pilot_source(module_source)
        check_n32_copy_sites(std, overlay, rows, module_source)
    elif closure:
        check_n32_closure_source(module_source)
        check_literal_witness_source(module_source, LITERAL_WITNESSES[N32_CLOSURE_PREFIX])
        check_n32_closure_copy_sites(std, overlay, rows)
    elif combined:
        check_wide_n12_n14_source(module_source)
        check_literal_witness_source(module_source, LITERAL_WITNESSES[WIDE_N12_N14_PREFIX])
        check_wide_n12_n14_copy_sites(std, overlay, rows, module_source)
    elif close or witness:
        if close:
            check_close_fill_bounds(module_source)
        if prefix in LITERAL_WITNESSES:
            check_literal_witness_source(module_source, LITERAL_WITNESSES[prefix])
        for row in rows:
            require(row["native_evidence"]["copy_sites"] == close_copy_sites(std, overlay, row["id"], module_source),
                    f"{row['id']} CLOSE local or actual typed-copy sites differ")
    elif module_file == PILOT_MODULE_FILE:
        check_pilot_copy_sites(std, overlay, rows, module_source)
    require(observed == set(module_calls), f"{module_file} has extra or missing labelled calls")
    return True


def check_close_fill_bounds(source):
    """Check the literal loop schedule against the array declarations in the three fill roots."""
    for rel in (5, 6, 7):
        name = f"gen_n16_wide_fill_r48_rel{rel}"
        body = re.search(rf"(?ms)^    fn {name}\(\) \{{\n(.*?)^    \}}$", source)
        require(body is not None, f"{name} definition missing")
        scratch = re.search(r"(?m)^        let mut scratch = \[MaybeUninit::<Wide>::uninit\(\); (\d+)\];$", body[1])
        old = re.search(r"(?ms)^        let old = unsafe \{\n            \[\n(.*?)^            \]\n", body[1])
        require(scratch is not None and int(scratch[1]) == 48 and old is not None,
                f"{name} scratch48 or old array declaration differs")
        entries = old[1].splitlines()
        prefix_len = len(entries)
        require(prefix_len == rel and [line.strip() for line in entries] ==
                [f"scratch[{index}].assume_init()," for index in range(8, 8 + prefix_len)],
                f"{name} old array length or prefix differs")
        tail = 8 + prefix_len
        loops = [line.strip() for line in body[1].splitlines() if line.lstrip().startswith("for ")]
        require(loops == [
            f"for i in 0..{tail} {{", f"for i in {tail + 1}..32 {{", f"for i in 32..{scratch[1]} {{",
            f"for i in 1..{prefix_len} {{", f"for i in 0..{prefix_len} {{", f"for j in 0..{prefix_len + 1} {{",
        ], f"{name} literal loop bounds differ from array lengths (old={prefix_len}, scratch={scratch[1]})")


N10_WITNESS_LEFT = (2, 16, 0x1111_2222_3333_4444)
N10_WITNESS_RIGHT = (3, 17, 0xAAAA_BBBB_CCCC_DDDD)
N10_WITNESS_KEYS = (1, 0, 1, 0, 0, 1, 0, 1, 0, 0)
N10_WITNESS_SWAP = (2, 3)
N12_WITNESS_KEYS = (1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0)
N12_WITNESS_SWAP = (3, 4)
N14_WITNESS_KEYS = (1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0)
N14_WITNESS_SWAP = (4, 5)
# N32: in each half of S the first four keys are 1,0,1,0 and the other twelve are 1. Tags 16 and 17 are
# active records here, so the two canaries carry tags 32 and 33.
N32_WITNESS_KEYS = (1, 0, 1, 0, *(1,) * 12) * 2
N32_WITNESS_SWAP = (1, 2)
N32_WITNESS_LEFT = (2, 32, 0x1111_2222_3333_4444)
N32_WITNESS_RIGHT = (3, 33, 0xAAAA_BBBB_CCCC_DDDD)
LITERAL_WITNESSES = {
    N10_WITNESS_PREFIX: {"name": "N10", "declaration": N10_WITNESS_DECLARATION, "keys": "N10_WITNESS_KEYS",
                         "swap": "N10_WITNESS_SWAP"},
    N12_WITNESS_PREFIX: {"name": "N12", "declaration": N12_WITNESS_DECLARATION, "keys": "N12_WITNESS_KEYS",
                         "swap": "N12_WITNESS_SWAP"},
    WIDE_N12_N14_PREFIX: {"name": "N14", "declaration": WIDE_N12_N14_DECLARATION, "keys": "N14_WITNESS_KEYS",
                          "swap": "N14_WITNESS_SWAP", "marker": N14_WITNESS_MARKER},
    N32_CLOSURE_PREFIX: {"name": "N32", "declaration": N32_CLOSURE_DECLARATION, "keys": "N32_WITNESS_KEYS",
                         "swap": "N32_WITNESS_SWAP", "marker": N32_WIDE_WITNESS_MARKER,
                         "left": N32_WITNESS_LEFT, "right": N32_WITNESS_RIGHT},
}


def check_n10_witness_source(source):
    return check_literal_witness_source(source, LITERAL_WITNESSES[N10_WITNESS_PREFIX])


def check_n12_witness_source(source):
    return check_literal_witness_source(source, LITERAL_WITNESSES[N12_WITNESS_PREFIX])


def check_n14_witness_source(source):
    return check_literal_witness_source(source, LITERAL_WITNESSES[WIDE_N12_N14_PREFIX])


def check_literal_witness_source(source, geometry):
    """Recompute both permutations from the literal input and bind every literal loop, index and observer."""
    name, declaration = geometry["name"], geometry["declaration"]
    keys, swap = globals()[geometry["keys"]], globals()[geometry["swap"]]
    # Historical witnesses share the N10 canaries; N32 pins its own because tags 16 and 17 are active there.
    left_canary, right_canary = geometry.get("left", N10_WITNESS_LEFT), geometry.get("right", N10_WITNESS_RIGHT)
    require(source.count(declaration) == 1, f"{name} witness module declaration missing or ambiguous")
    start = source.index(declaration)
    body = source[start:]
    nested = body.find("\n#[cfg(", len(declaration))
    if nested != -1:
        body = body[:nested + 1]
    if "marker" in geometry:
        # The witness is the tail of a combined module. Read only that tail.
        require(body.count(geometry["marker"]) == 1, f"{name} witness marker missing or ambiguous")
        body = body[body.index(geometry["marker"]):]
    # A literal witness has no nondeterminism, assumption, stub, contract or byte comparison.
    for token in ("kani::any", "kani::assume", "kani::stub", "stub_verified", "proof_for_contract", "cfg_attr",
                  "memcmp", "requires(", "modifies("):
        require(token not in body, f"{name} witness body contains {token}")
    require(body.count("#[kani::proof]") == 1, f"{name} witness must be exactly one plain Proof")
    lines = body.splitlines()
    literal = re.compile(r"^    const (LEFT|RIGHT): Wide = Wide \{ key: (\d+), tag: (\d+), payload: (0x[0-9a-f_]+) \};$")
    canaries = {match[1]: (int(match[2]), int(match[3]), int(match[4].replace("_", ""), 16))
                for line in lines if (match := literal.match(line))}
    require(canaries == {"LEFT": left_canary, "RIGHT": right_canary}, f"{name} canary literals differ")
    require("        Wide { key, tag, payload: 0x8000_0000_0000_0100 + tag }\n" in body,
            f"{name} payload constructor differs")
    entries = re.search(r"(?ms)^    const INPUT: \[Wide; (\d+)\] = \[\n(.*?)^    \];$", body)
    require(entries is not None, f"{name} INPUT declaration missing")
    items = [line.strip() for line in entries[2].splitlines()]
    record = re.compile(r"^input_record\((\d+), (\d+)\),$")
    parsed = [(int(match[1]), int(match[2])) for item in items[1:-1] if (match := record.match(item))]
    length = len(keys)
    require(int(entries[1]) == len(items) == length + 2 and items[0] == "LEFT," and items[-1] == "RIGHT,"
            and parsed == [(key, tag) for tag, key in enumerate(keys)],
            f"{name} INPUT length, keys, tags or canary positions differ")
    records = [left_canary, *((key, tag, 0x8000_0000_0000_0100 + tag) for key, tag in parsed), right_canary]
    require(len({record[1] for record in records}) == len(records)
            and left_canary not in records[1:-1] and right_canary not in records[1:-1],
            f"{name} records are not distinguishable from the canaries")
    expected = sorted(range(1, length + 1), key=lambda index: records[index][0])
    corrupted = list(expected)
    a, b = swap
    corrupted[a], corrupted[b] = corrupted[b], corrupted[a]
    half = length // 2
    require(records[expected[a]][0] == records[expected[b]][0] and b == a + 1
            and records[expected[a]][1] < half <= records[expected[b]][1],
            f"{name} swap is not one adjacent cross-half pair of equal keys")
    inversions = [i for i in range(length - 1) if records[corrupted[i]][0] == records[corrupted[i + 1]][0]
                  and records[corrupted[i]][1] > records[corrupted[i + 1]][1]]
    require(inversions == [a] and all(records[corrupted[i]][0] <= records[corrupted[i + 1]][0]
                                       for i in range(length - 1)),
            f"{name} corruption must keep key order and create exactly one equal-key tag inversion")
    for array, order in (("EXPECTED", expected), ("CORRUPTED", corrupted)):
        found = re.search(rf"(?ms)^    const {array}: \[Wide; (\d+)\] = \[\n(.*?)^    \];$", body)
        require(found is not None and int(found[1]) == length and
                re.findall(r"INPUT\[(\d+)\]", found[2]) == [str(index) for index in order] and
                re.sub(r"INPUT\[\d+\]|[\s,]", "", found[2]) == "", f"{name} {array} order differs")
    loops = [line.strip() for line in lines if line.lstrip().startswith(("for ", "while ", "loop"))]
    unwind = re.findall(r"(?m)^    #\[kani::unwind\((\d+)\)\]$", body)
    require(loops == [f"for i in 1..{length} {{"] and unwind == ["36"] and length < 36,
            f"{name} literal loop bounds differ from the array lengths or unwind36")
    require(f"    fn observe(v: &[Wide; {length + 2}], expected: &[Wide; {length}]) -> (bool, bool, bool) {{" in body
            and "        let mut exact = same_wide(v[1], expected[0]);\n" in body
            and "            let (a, b) = (v[i], v[i + 1]);\n" in body
            and "            exact &= same_wide(b, expected[i]);\n" in body,
            f"{name} observer indices differ from the array lengths")
    call = f"<Wide as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..{length + 1}], &mut less);"
    require(body.count(call) == 1, f"{name} actual unstable call range differs")
    left, right = records[expected[a]], records[expected[b]]
    swap_pair = (f"            v[{a + 1}].key == {left[0]} && v[{b + 1}].key == {right[0]} && "
                 f"v[{a + 1}].tag == {left[1]} && v[{b + 1}].tag == {right[1]},\n")
    tie = f"            v[{a + 1}].key == v[{b + 1}].key && v[{a + 1}].tag < {half} && v[{b + 1}].tag >= {half},\n"
    exchange = f"        let left = v[{a + 1}];\n        v[{a + 1}] = v[{b + 1}];\n        v[{b + 1}] = left;\n"
    frame = f"same_wide(v[0], LEFT) && same_wide(v[{length + 1}], RIGHT)"
    require(body.count(swap_pair) == 1 and body.count(tie) == 1 and body.count(exchange) == 1
            and body.count(frame) == 2, f"{name} swap pair, tie cover, exchange or frame indices differ")
    # Each observer reads the array its phase claims: EXPECTED after the call, CORRUPTED after the exchange.
    before = "        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n"
    after = "        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n"
    require(body.count(before) == 1 and body.count(after) == 1 and body.count("observe(&v, ") == 2
            and body.index(call) < body.index(before) < body.index(exchange) < body.index(after),
            f"{name} observers do not read EXPECTED before and CORRUPTED after the exchange")
    return {"expected": expected, "corrupted": corrupted}


def wide_n12_n14_check_text(n, direction):
    """Render one exact merge Check wrapper and harness from its geometry only."""
    m = n // 2
    label = f"GEN_N{n}_WIDE_{direction.upper()}"
    target = f"actual_merge_{direction}_wide_n{n}"
    up = direction == "up"
    counter, side, other = ("a", "left", "right") if up else ("c", "left", "right")
    count_bound = f"k < {m} && {counter} <= k"
    modifies = "s.wrapping_add(k)" if up else f"s.wrapping_add({n - 1} - k)"
    if up:
        body = (f"        let b = k - a;\n"
                f"        let mut less = wide_less;\n"
                f"        // SAFETY: The count bounds put both reads in initialized D halves and\n"
                f"        // the destination in the separate writable S allocation.\n"
                f"        unsafe {{\n"
                f"            let up_left = d.add(a);\n"
                f"            let up_right = d.add({m} + b);\n"
                f"            let up_dst = s.add(k);\n")
        cursor = (f"            let (left, right, dst) = merge_up(up_left, up_right, up_dst, &mut less);\n"
                  f"            let takes_left = (*up_left).key <= (*up_right).key;\n"
                  f"            kani::assert(\n"
                  f"                left == up_left.add(takes_left as usize)\n"
                  f"                    && right == up_right.add((!takes_left) as usize)\n"
                  f"                    && dst == s.add(k + 1),\n"
                  f"                \"{label}_CURSORS\",\n"
                  f"            );\n")
    else:
        body = (f"        let d_count = k - c;\n"
                f"        let mut less = wide_less;\n"
                f"        // SAFETY: The count bounds put both reads in initialized D halves and\n"
                f"        // the destination in the separate writable S allocation.\n"
                f"        unsafe {{\n"
                f"            let down_left = d.add({m - 1} - c);\n"
                f"            let down_right = d.add({n - 1} - d_count);\n"
                f"            let down_dst = s.add({n - 1} - k);\n")
        cursor = (f"            let (left, right, dst) = merge_down(down_left, down_right, down_dst, &mut less);\n"
                  f"            let takes_left = (*down_left).key > (*down_right).key;\n"
                  f"            kani::assert(\n"
                  f"                left == down_left.wrapping_sub(takes_left as usize)\n"
                  f"                    && right == down_right.wrapping_sub((!takes_left) as usize)\n"
                  f"                    && dst == s.add({n - 2} - k),\n"
                  f"                \"{label}_CURSORS\",\n"
                  f"            );\n")
    d = direction
    wrapper = (f"    #[cfg_attr(\n        kani,\n        kani::requires({count_bound}),\n"
               f"        kani::requires(ub_checks::can_dereference(ptr::slice_from_raw_parts(d, {n}))),\n"
               f"        kani::requires(ub_checks::can_write(ptr::slice_from_raw_parts_mut(s, {n}))),\n"
               f"        kani::requires(!ub_checks::same_allocation(d, s)),\n"
               f"        kani::modifies({modifies})\n    )]\n"
               f"    unsafe fn {target}(d: *const Wide, s: *mut Wide, k: usize, {counter}: usize) {{\n"
               + body +
               f"            kani::assert(\n"
               f"                ub_checks::can_dereference({d}_left) && ub_checks::can_dereference({d}_right),\n"
               f"                \"{label}_READ\",\n"
               f"            );\n"
               f"            kani::assert(ub_checks::can_write({d}_dst), \"{label}_WRITE\");\n"
               f"            kani::assert(\n"
               f"                !ub_checks::same_allocation({d}_left, {d}_dst)\n"
               f"                    && !ub_checks::same_allocation({d}_right, {d}_dst),\n"
               f"                \"{label}_DISJOINT\",\n"
               f"            );\n"
               + cursor +
               f"        }}\n    }}\n")
    if up:
        sources = (f"        let (up_left, up_right) =\n"
                   f"            unsafe {{ (scratch_before[a].assume_init(), scratch_before[{m} + (k - a)].assume_init()) }};\n"
                   f"        let takes_left = up_left.key <= up_right.key;\n"
                   f"        let expected = if takes_left {{ up_left }} else {{ up_right }};\n")
        value = "1 + k"
    else:
        sources = (f"        let (down_left, down_right) = unsafe {{\n"
                   f"            (scratch_before[{m - 1} - c].assume_init(), scratch_before[{n - 1} - (k - c)].assume_init())\n"
                   f"        }};\n"
                   f"        let takes_left = down_left.key > down_right.key;\n"
                   f"        let expected = if takes_left {{ down_left }} else {{ down_right }};\n")
        value = f"{n} - k"
    harness = (f"    #[kani::proof_for_contract({target})]\n    #[kani::unwind(36)]\n"
               f"    fn gen_n{n}_wide_merge_{direction}() {{\n"
               f"        let mut v = wide_array::<{n + 2}>();\n"
               f"        let v_before = v;\n"
               f"        let mut scratch = wide_scratch48();\n"
               f"        let scratch_before = scratch;\n"
               f"        let k = usize::from(kani::any::<u8>());\n"
               f"        let {counter} = usize::from(kani::any::<u8>());\n"
               f"        kani::assume({count_bound});\n"
               f"        // SAFETY: The constrained source positions and all {n} destination\n"
               f"        // records satisfy the wrapper contract; V and D are separate arrays.\n"
               + sources +
               f"        let s = v[1..{n + 1}].as_mut_ptr();\n"
               f"        let d = scratch.as_mut_ptr().cast::<Wide>();\n"
               f"        // SAFETY: D[0..{n}] is initialized and S[0..{n}] is writable in\n"
               f"        // distinct allocations, with the counter assumptions above.\n"
               f"        unsafe {{ {target}(d, s, k, {counter}) }};\n\n"
               f"        kani::assert(same_wide(v[{value}], expected), \"{label}_VALUE\");\n"
               f"        let mut v_frame = true;\n"
               f"        for i in 0..{n + 2} {{\n"
               f"            if i != {value} {{\n"
               f"                v_frame &= same_wide(v[i], v_before[i]);\n"
               f"            }}\n        }}\n"
               f"        kani::assert(v_frame, \"{label}_V_FRAME\");\n"
               f"        kani::assert(scratch48_frame(&scratch, &scratch_before), \"{label}_SCRATCH_FRAME\");\n"
               f"        kani::cover(takes_left, \"{label}_TAKES_LEFT\");\n"
               f"        kani::cover(!takes_left, \"{label}_TAKES_RIGHT\");\n"
               f"        kani::cover(\n"
               f"            {d}_left.key == {d}_right.key && {d}_left.tag != {d}_right.tag,\n"
               f"            \"{label}_TIE\",\n        );\n"
               f"        kani::cover(k == 0, \"{label}_K_ZERO\");\n"
               f"        kani::cover(k == {m - 1}, \"{label}_K_LAST\");\n"
               f"        kani::cover(true, \"{label}_RETURNED\");\n    }}\n")
    return wrapper + "\n" + harness


WIDE_N12_N14_HELPERS = (
    "    use super::super::super::UnstableSmallSortTypeImpl;\n"
    "    use super::*;\n\n"
    "    fn wide_array<const L: usize>() -> [Wide; L] {\n"
    "        let mut v = [Wide { key: 0, tag: 0, payload: 0 }; L];\n"
    "        for i in 0..L {\n            v[i] = any_wide();\n        }\n        v\n    }\n\n"
    "    fn wide_scratch48() -> [MaybeUninit<Wide>; 48] {\n"
    "        let mut scratch = [MaybeUninit::<Wide>::uninit(); 48];\n"
    "        for i in 0..32 {\n            scratch[i].write(any_wide());\n        }\n"
    "        for i in 32..48 {\n            scratch[i].write(any_wide());\n        }\n        scratch\n    }\n\n"
    "    fn scratch48_frame(\n        scratch: &[MaybeUninit<Wide>; 48],\n"
    "        before: &[MaybeUninit<Wide>; 48],\n    ) -> bool {\n"
    "        let mut frame = true;\n"
    "        for i in 0..32 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { same_wide(scratch[i].assume_init(), before[i].assume_init()) };\n        }\n"
    "        for i in 32..48 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { same_wide(scratch[i].assume_init(), before[i].assume_init()) };\n        }\n"
    "        frame\n    }\n\n"
)


def check_wide_n12_n14_source(source):
    """Bind the combined module head to the geometry-rendered Checks, then leave the tail to the witness gate."""
    require(source.count(WIDE_N12_N14_DECLARATION) == 1 and source.count(N14_WITNESS_MARKER) == 1,
            "Wide N12/N14 module declaration or witness marker missing or ambiguous")
    start = source.index(WIDE_N12_N14_DECLARATION) + len(WIDE_N12_N14_DECLARATION)
    head = source[start:source.index(N14_WITNESS_MARKER)]
    expected = WIDE_N12_N14_HELPERS + "".join(
        wide_n12_n14_check_text(n, direction) + "\n" for n, direction in WIDE_N12_N14_CHECK_GEOMETRY.values())
    require(head == expected, "Wide N12/N14 Check wrappers or harnesses differ from their N/m geometry")
    # Only the module itself closes at column 0 after its declaration, and it closes the file.
    require(source.endswith("\n}\n") and source[start:].count("\n}\n") == 1 and "\n#[cfg(" not in source[start:],
            "Wide N12/N14 module must be the last opt-in module of the file")
    return expected


def check_wide_n12_n14_copy_sites(std, overlay, rows, module_source):
    """Each Check reaches one actual directional copy; the witness reaches every actual Wide copy site."""
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    for row in rows:
        slot = row["id"]
        if slot == N14_WITNESS_SLOT_ID:
            require(row["native_evidence"]["copy_sites"] == close_copy_sites(std, overlay, slot, module_source),
                    f"{slot} actual typed-copy sites differ")
            continue
        _, direction = WIDE_N12_N14_CHECK_GEOMETRY[slot]
        check = WIDE_N12_N14_CHECK_TARGETS[slot]
        body = re.search(rf"(?ms)^    unsafe fn {check}\(.*?^    }}", module_source)
        expected = copy_site(SMALLSORT_FILE, smallsort, WIDE_N12_N14_COPY_LINES[direction])
        require(body is not None and re.findall(r"= (merge_(?:up|down))\(", body[0]) == [f"merge_{direction}"]
                and "ptr::copy_nonoverlapping(" not in body[0]
                and row["check_evidence"].get("copy_sites") == [expected], f"{slot} actual copy site or direction differs")




def n32_types(kind):
    """Type-dependent fragments: element type, V34 constructor, comparator, comparisons."""
    if kind == "u64":
        return {"ty": "u64", "label": "U64", "less": "u64_less", "v": "let mut v: [u64; 34] = kani::any();",
                "zero": "0u64", "scratch": "u64_scratch48", "frame": "u64_scratch48_frame",
                "key": lambda e: e, "same": lambda a, b: f"{a} == {b}"}
    return {"ty": "Wide", "label": "WIDE", "less": "wide_less", "v": "let mut v = wide_v34();",
            "zero": "Wide { key: 0, tag: 0, payload: 0 }", "scratch": "wide_scratch48",
            "frame": "wide_scratch48_frame", "key": lambda e: f"{e}.key",
            "same": lambda a, b: f"same_wide({a}, {b})"}


def n32_v_frame(t, name, skip=None):
    """V34 frame in the two literal passes 0..17 and 17..34, optionally without one written index."""
    out = f"        let mut {name} = true;\n"
    for lo, hi in ((0, 17), (17, 34)):
        cmp = t["same"]("v[i]", "before[i]" if skip is None else "v_before[i]")
        if skip is None:
            out += f"        for i in {lo}..{hi} {{\n            {name} &= {cmp};\n        }}\n"
        else:
            out += (f"        for i in {lo}..{hi} {{\n            if i != {skip} {{\n"
                    f"                {name} &= {cmp};\n            }}\n        }}\n")
    return out


N32_HELPERS = (
    "    use super::*;\n\n"
    "    fn wide_v34() -> [Wide; 34] {\n"
    "        let mut v = [Wide { key: 0, tag: 0, payload: 0 }; 34];\n"
    "        for i in 0..17 {\n            v[i] = any_wide();\n        }\n"
    "        for i in 17..34 {\n            v[i] = any_wide();\n        }\n        v\n    }\n\n"
    "    fn u64_scratch48() -> [MaybeUninit<u64>; 48] {\n"
    "        let mut scratch = [MaybeUninit::<u64>::uninit(); 48];\n"
    "        for i in 0..32 {\n            scratch[i].write(kani::any());\n        }\n"
    "        for i in 32..48 {\n            scratch[i].write(kani::any());\n        }\n        scratch\n    }\n\n"
    "    fn wide_scratch48() -> [MaybeUninit<Wide>; 48] {\n"
    "        let mut scratch = [MaybeUninit::<Wide>::uninit(); 48];\n"
    "        for i in 0..32 {\n            scratch[i].write(any_wide());\n        }\n"
    "        for i in 32..48 {\n            scratch[i].write(any_wide());\n        }\n        scratch\n    }\n\n"
    "    fn u64_scratch48_frame(\n        scratch: &[MaybeUninit<u64>; 48],\n"
    "        before: &[MaybeUninit<u64>; 48],\n    ) -> bool {\n"
    "        let mut frame = true;\n"
    "        for i in 0..32 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { scratch[i].assume_init() == before[i].assume_init() };\n        }\n"
    "        for i in 32..48 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { scratch[i].assume_init() == before[i].assume_init() };\n        }\n"
    "        frame\n    }\n\n"
    "    fn wide_scratch48_frame(\n        scratch: &[MaybeUninit<Wide>; 48],\n"
    "        before: &[MaybeUninit<Wide>; 48],\n    ) -> bool {\n"
    "        let mut frame = true;\n"
    "        for i in 0..32 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { same_wide(scratch[i].assume_init(), before[i].assume_init()) };\n        }\n"
    "        for i in 32..48 {\n            // SAFETY: Both snapshots of this interval were initialized.\n"
    "            frame &= unsafe { same_wide(scratch[i].assume_init(), before[i].assume_init()) };\n        }\n"
    "        frame\n    }\n\n"
)


def n32_s8_text():
    """Actual right sort8_stable of :300-305 at len=32: S+16 -> D+16 with tmp D+40 in one D48."""
    t = n32_types("u64")
    label = "GEN_N32_U64_S8_R48"
    return (
        "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_u64_s8_r48_full() {\n"
        "        let mut v: [u64; 34] = kani::any();\n"
        "        let before = v;\n"
        "        let probe: u64 = kani::any();\n"
        "        let mut scratch = [MaybeUninit::<u64>::uninit(); 48];\n"
        "        for i in 0..16 {\n            scratch[i].write(kani::any());\n        }\n"
        "        for i in 24..40 {\n            scratch[i].write(kani::any());\n        }\n"
        "        let scratch_before = scratch;\n"
        "        let s = v[1..33].as_mut_ptr();\n"
        "        let d = scratch.as_mut_ptr().cast::<u64>();\n"
        "        let mut less = u64_less;\n"
        "        // SAFETY: The eight initialized source words S[16..24] are in the separate V34.\n"
        "        // The writable D[16..24] and D[40..48] are disjoint intervals of scratch48.\n"
        "        unsafe { sort8_stable(s.add(16), d.add(16), d.add(40), &mut less) };\n\n"
        "        let mut ordered = true;\n"
        "        let mut tmp_left_ordered = true;\n"
        "        let mut tmp_right_ordered = true;\n"
        "        let mut input_count = 0;\n"
        "        let mut output_count = 0;\n"
        "        let mut adjacent_equal = false;\n"
        "        let mut inversion = false;\n"
        "        for i in 0..8 {\n"
        "            input_count += usize::from(before[17 + i] == probe);\n"
        "            // SAFETY: A normal return writes each output word.\n"
        "            output_count += usize::from(unsafe { scratch[16 + i].assume_init() } == probe);\n"
        "        }\n"
        "        for i in 0..7 {\n"
        "            adjacent_equal |= before[17 + i] == before[18 + i];\n"
        "            inversion |= before[17 + i] > before[18 + i];\n"
        "            // SAFETY: Both words are in the initialized output interval.\n"
        "            ordered &= unsafe { scratch[16 + i].assume_init() <= scratch[17 + i].assume_init() };\n"
        "        }\n"
        "        for i in 0..3 {\n"
        "            // SAFETY: The two inner sort4 calls initialize both temporary blocks.\n"
        "            unsafe {\n"
        "                tmp_left_ordered &= scratch[40 + i].assume_init() <= scratch[41 + i].assume_init();\n"
        "                tmp_right_ordered &= scratch[44 + i].assume_init() <= scratch[45 + i].assume_init();\n"
        "            }\n"
        "        }\n"
        + n32_v_frame(t, "v_frame") +
        "        let mut scratch_frame = true;\n"
        "        for i in 0..16 {\n"
        "            // SAFETY: Both frame intervals were initialized before the call.\n"
        "            unsafe {\n"
        "                scratch_frame &= scratch[i].assume_init() == scratch_before[i].assume_init();\n"
        "                scratch_frame &=\n"
        "                    scratch[24 + i].assume_init() == scratch_before[24 + i].assume_init();\n"
        "            }\n"
        "        }\n"
        f"        kani::assert(ordered, \"{label}_SORTED\");\n"
        f"        kani::assert(input_count == output_count, \"{label}_PROBE_MULTIPLICITY\");\n"
        f"        kani::assert(tmp_left_ordered, \"{label}_TMP_LEFT_SORTED\");\n"
        f"        kani::assert(tmp_right_ordered, \"{label}_TMP_RIGHT_SORTED\");\n"
        f"        kani::assert(v_frame, \"{label}_V_FRAME\");\n"
        f"        kani::assert(scratch_frame, \"{label}_SCRATCH_FRAME\");\n"
        f"        kani::cover(inversion, \"{label}_MIXED_INVERSION\");\n"
        f"        kani::cover(adjacent_equal, \"{label}_EQUAL_INPUT\");\n"
        f"        kani::cover(true, \"{label}_RETURNED\");\n"
        "    }\n"
    )


def n32_fill_text(kind):
    """Right fill rel15 at offset=16, i=15: ordered D[16..31], copy S[31] to uninit D[31], actual insert_tail."""
    t = n32_types(kind)
    label = f"GEN_N32_{t['label']}_FILL_REL15"
    init = "kani::any()" if kind == "u64" else "any_wide()"
    key = t["key"]
    if kind == "u64":
        equal_name, equal_update = "equal", "            equal |= old[i] == x;\n"
        equal_label = f"{label}_EQUAL_KEY"
    else:
        equal_name = "equal_distinct"
        equal_update = "            equal_distinct |= old[i].key == x.key && old[i].tag != x.tag;\n"
        equal_label = f"{label}_EQUAL_DISTINCT"
    same = t["same"]
    snapshot = same("scratch[i].assume_init()", "scratch_before[i].assume_init()")
    # rustfmt keeps the u64 update on one line and breaks the longer Wide update after `&=`.
    frame_update = (f"            scratch_frame &= unsafe {{ {snapshot} }};\n" if kind == "u64" else
                    f"            scratch_frame &=\n                unsafe {{ {snapshot} }};\n")
    return (
        f"    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_{kind}_fill_r48_rel15() {{\n"
        f"        {t['v']}\n"
        "        let before = v;\n"
        "        let x = before[32];\n"
        f"        let mut scratch = [MaybeUninit::<{t['ty']}>::uninit(); 48];\n"
        f"        for i in 0..31 {{\n            scratch[i].write({init});\n        }}\n"
        f"        for i in 32..48 {{\n            scratch[i].write({init});\n        }}\n"
        "        let scratch_before = scratch;\n"
        f"        let mut old = [{t['zero']}; 15];\n"
        "        for i in 0..15 {\n"
        "            // SAFETY: D[16..31] was initialized above. D[31] is not read here.\n"
        "            old[i] = unsafe { scratch[16 + i].assume_init() };\n"
        "        }\n"
        "        let mut sorted_prefix = true;\n"
        "        for i in 1..15 {\n"
        f"            sorted_prefix &= {key('old[i - 1]')} <= {key('old[i]')};\n"
        "        }\n"
        "        kani::assume(sorted_prefix);\n"
        "        let mut pos = 0;\n"
        f"        let mut {equal_name} = false;\n"
        "        for i in 0..15 {\n"
        f"            pos += usize::from({key('old[i]')} <= {key('x')});\n"
        + equal_update +
        "        }\n"
        "        let s = v[1..33].as_mut_ptr();\n"
        f"        let d = scratch.as_mut_ptr().cast::<{t['ty']}>();\n"
        f"        let mut less = {t['less']};\n"
        "        // SAFETY: V34 and D48 are disjoint. The sorted prefix and the source\n"
        "        // record are initialized, and D[31] is writable before initialization.\n"
        "        unsafe {\n"
        "            // Transcription of smallsort.rs:329 at offset=16, i=15.\n"
        "            ptr::copy_nonoverlapping(s.add(31), d.add(31), 1);\n"
        "            insert_tail(d.add(16), d.add(31), &mut less);\n"
        "        }\n\n"
        "        let mut exact = true;\n"
        "        for j in 0..16 {\n"
        "            let expected = if j < pos {\n                old[j]\n            } else if j == pos {\n"
        "                x\n            } else {\n                old[j - 1]\n            };\n"
        "            // SAFETY: The prefix and the copied record of D[16..32] are initialized.\n"
        f"            exact &= {same('unsafe { scratch[16 + j].assume_init() }', 'expected')};\n"
        "        }\n"
        + n32_v_frame(t, "v_frame") +
        "        let mut scratch_frame = true;\n"
        "        for i in 0..16 {\n"
        "            // SAFETY: This interval was initialized before both snapshots.\n"
        + frame_update +
        "        }\n"
        "        for i in 32..48 {\n"
        "            // SAFETY: This interval was initialized before both snapshots.\n"
        + frame_update +
        "        }\n"
        f"        kani::assert(exact, \"{label}_EXACT_UPPER_BOUND\");\n"
        f"        kani::assert(v_frame, \"{label}_V_FRAME\");\n"
        f"        kani::assert(scratch_frame, \"{label}_SCRATCH_FRAME\");\n"
        f"        kani::cover(pos == 15, \"{label}_NO_SHIFT\");\n"
        f"        kani::cover(pos < 15, \"{label}_SHIFT\");\n"
        f"        kani::cover({equal_name}, \"{equal_label}\");\n"
        f"        kani::cover(true, \"{label}_RETURNED\");\n"
        "    }\n"
    )


def n32_check_text(kind, direction):
    """One exact merge Check wrapper and harness in the 16+16 geometry, from type and direction only."""
    n, m = 32, 16
    t = n32_types(kind)
    ty, key = t["ty"], t["key"]
    label = f"GEN_N32_{t['label']}_{direction.upper()}"
    target = f"actual_merge_{direction}_{kind}_n32"
    up = direction == "up"
    counter = "a" if up else "c"
    count_bound = f"k < {m} && {counter} <= k"
    modifies = "s.wrapping_add(k)" if up else f"s.wrapping_add({n - 1} - k)"
    d = direction
    if up:
        body = ("        let b = k - a;\n"
                f"        let mut less = {t['less']};\n"
                "        // SAFETY: The count bounds put both reads in initialized D halves and\n"
                "        // the destination in the separate writable S allocation.\n"
                "        unsafe {\n"
                "            let up_left = d.add(a);\n"
                f"            let up_right = d.add({m} + b);\n"
                "            let up_dst = s.add(k);\n")
        cursor = ("            let (left, right, dst) = merge_up(up_left, up_right, up_dst, &mut less);\n"
                  f"            let takes_left = {key('(*up_left)')} <= {key('(*up_right)')};\n"
                  "            kani::assert(\n"
                  "                left == up_left.add(takes_left as usize)\n"
                  "                    && right == up_right.add((!takes_left) as usize)\n"
                  "                    && dst == s.add(k + 1),\n"
                  f"                \"{label}_CURSORS\",\n"
                  "            );\n")
    else:
        body = ("        let d_count = k - c;\n"
                f"        let mut less = {t['less']};\n"
                "        // SAFETY: The count bounds put both reads in initialized D halves and\n"
                "        // the destination in the separate writable S allocation.\n"
                "        unsafe {\n"
                f"            let down_left = d.add({m - 1} - c);\n"
                f"            let down_right = d.add({n - 1} - d_count);\n"
                f"            let down_dst = s.add({n - 1} - k);\n")
        cursor = ("            let (left, right, dst) = merge_down(down_left, down_right, down_dst, &mut less);\n"
                  f"            let takes_left = {key('(*down_left)')} > {key('(*down_right)')};\n"
                  "            kani::assert(\n"
                  "                left == down_left.wrapping_sub(takes_left as usize)\n"
                  "                    && right == down_right.wrapping_sub((!takes_left) as usize)\n"
                  f"                    && dst == s.add({n - 2} - k),\n"
                  f"                \"{label}_CURSORS\",\n"
                  "            );\n")
    wrapper = (f"    #[cfg_attr(\n        kani,\n        kani::requires({count_bound}),\n"
               f"        kani::requires(ub_checks::can_dereference(ptr::slice_from_raw_parts(d, {n}))),\n"
               f"        kani::requires(ub_checks::can_write(ptr::slice_from_raw_parts_mut(s, {n}))),\n"
               "        kani::requires(!ub_checks::same_allocation(d, s)),\n"
               f"        kani::modifies({modifies})\n    )]\n"
               f"    unsafe fn {target}(d: *const {ty}, s: *mut {ty}, k: usize, {counter}: usize) {{\n"
               + body +
               "            kani::assert(\n"
               f"                ub_checks::can_dereference({d}_left) && ub_checks::can_dereference({d}_right),\n"
               f"                \"{label}_READ\",\n"
               "            );\n"
               f"            kani::assert(ub_checks::can_write({d}_dst), \"{label}_WRITE\");\n"
               "            kani::assert(\n"
               f"                !ub_checks::same_allocation({d}_left, {d}_dst)\n"
               f"                    && !ub_checks::same_allocation({d}_right, {d}_dst),\n"
               f"                \"{label}_DISJOINT\",\n"
               "            );\n"
               + cursor +
               "        }\n    }\n")
    if up:
        sources = ("        let (up_left, up_right) = unsafe {\n"
                   f"            (scratch_before[a].assume_init(), scratch_before[{m} + (k - a)].assume_init())\n"
                   "        };\n"
                   f"        let takes_left = {key('up_left')} <= {key('up_right')};\n"
                   "        let expected = if takes_left { up_left } else { up_right };\n")
        value = "1 + k"
    else:
        sources = ("        let (down_left, down_right) = unsafe {\n"
                   f"            (scratch_before[{m - 1} - c].assume_init(), scratch_before[{n - 1} - (k - c)].assume_init())\n"
                   "        };\n"
                   f"        let takes_left = {key('down_left')} > {key('down_right')};\n"
                   "        let expected = if takes_left { down_left } else { down_right };\n")
        value = f"{n} - k"
    tie = (f"{d}_left == {d}_right" if kind == "u64"
           else f"{d}_left.key == {d}_right.key && {d}_left.tag != {d}_right.tag")
    harness = (f"    #[kani::proof_for_contract({target})]\n    #[kani::unwind(36)]\n"
               f"    fn gen_n32_{kind}_merge_{direction}() {{\n"
               f"        {t['v']}\n"
               "        let v_before = v;\n"
               f"        let mut scratch = {t['scratch']}();\n"
               "        let scratch_before = scratch;\n"
               "        let k = usize::from(kani::any::<u8>());\n"
               f"        let {counter} = usize::from(kani::any::<u8>());\n"
               f"        kani::assume({count_bound});\n"
               f"        // SAFETY: The constrained source positions and all {n} destination\n"
               "        // records satisfy the wrapper contract; V and D are separate arrays.\n"
               + sources +
               f"        let s = v[1..{n + 1}].as_mut_ptr();\n"
               f"        let d = scratch.as_mut_ptr().cast::<{ty}>();\n"
               f"        // SAFETY: D[0..{n}] is initialized and S[0..{n}] is writable in\n"
               "        // distinct allocations, with the counter assumptions above.\n"
               f"        unsafe {{ {target}(d, s, k, {counter}) }};\n\n"
               f"        kani::assert({t['same'](f'v[{value}]', 'expected')}, \"{label}_VALUE\");\n"
               + n32_v_frame(t, "v_frame", skip=value) +
               f"        kani::assert(v_frame, \"{label}_V_FRAME\");\n"
               "        kani::assert(\n"
               f"            {t['frame']}(&scratch, &scratch_before),\n"
               f"            \"{label}_SCRATCH_FRAME\",\n"
               "        );\n"
               f"        kani::cover(takes_left, \"{label}_TAKES_LEFT\");\n"
               f"        kani::cover(!takes_left, \"{label}_TAKES_RIGHT\");\n"
               + (f"        kani::cover({tie}, \"{label}_TIE\");\n" if kind == "u64" else
                  f"        kani::cover(\n            {tie},\n            \"{label}_TIE\",\n        );\n") +
               f"        kani::cover(k == 0, \"{label}_K_ZERO\");\n"
               f"        kani::cover(k == {m - 1}, \"{label}_K_LAST\");\n"
               f"        kani::cover(true, \"{label}_RETURNED\");\n    }}\n")
    return wrapper + "\n" + harness


N32_CHECK_ORDER = (("u64", "up"), ("u64", "down"), ("wide", "up"), ("wide", "down"))


def n32_module_text(declaration=None):
    """The whole appended module, from its declaration to the closing brace that ends the file."""
    declaration = N32_DECLARATION if declaration is None else declaration
    items = [n32_s8_text(), n32_fill_text("u64"), n32_fill_text("wide"),
             *(n32_check_text(kind, direction) for kind, direction in N32_CHECK_ORDER)]
    return declaration + N32_HELPERS + "\n".join(items) + "}\n"

def check_n32_pilot_source(source):
    """Bind the appended N32 module byte for byte to its geometry render. It must close the file."""
    require(source.count(N32_DECLARATION) == 1, "N32 pilot module declaration missing or ambiguous")
    start = source.index(N32_DECLARATION)
    expected = n32_module_text()
    require(source[start:] == expected, "N32 pilot module differs from its V34/D48 geometry render")
    # Invariant of the render, not a source check: the rel15 post reads old[j] only for j < pos <= 15 and
    # old[j - 1] only for j > pos >= 0, so every index stays in 0..15. The byte-for-byte match above pins
    # that text; Kani's bounds checks enforce it at verification. The self-check below guards the renderer.
    fill = n32_fill_text("u64")
    require(fill.count("for i in 0..15 {") == 2 and fill.count("for j in 0..16 {") == 1
            and "scratch[31]" not in fill and fill.count("scratch[16 + i].assume_init()") == 1,
            "rel15 snapshot must read exactly D[16..31]")
    return expected


def check_n32_copy_sites(std, overlay, rows, module_source):
    """S8 reaches sort4 and the length-8 merge; each fill binds its local copy, the gap shift and the guard."""
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    module = module_source.splitlines()
    sort4 = [copy_site(SMALLSORT_FILE, smallsort, line) for line in range(832, 836)]
    merge = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (885, 918)]
    gap = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (722, 362)]
    start = module_source.count("\n", 0, module_source.index(N32_DECLARATION)) + 1
    local = [i for i, line in enumerate(module, 1)
             if i > start and line.strip() == "ptr::copy_nonoverlapping(s.add(31), d.add(31), 1);"]
    require(len(local) == 2 and all(module[i].strip() == "insert_tail(d.add(16), d.add(31), &mut less);"
                                    for i in local), "N32 fills require one local copy and insert_tail each")
    for row in rows:
        slot = row["id"]
        kind, role = N32_GEOMETRY[slot]
        if role == "s8":
            expected = sort4 + merge
        elif role == "fill":
            site = copy_site(PILOT_MODULE_FILE, module, local[0 if kind == "u64" else 1])
            site["transcribes"] = copy_site(SMALLSORT_FILE, smallsort, 329)
            expected = [site, *gap]
        else:
            check = N32_CHECK_TARGETS[slot]
            body = re.search(rf"(?ms)^    unsafe fn {check}\(.*?^    }}", module_source)
            require(body is not None and re.findall(r"= (merge_(?:up|down))\(", body[0]) == [f"merge_{role}"]
                    and "ptr::copy_nonoverlapping(" not in body[0]
                    and row["check_evidence"].get("copy_sites") == [copy_site(SMALLSORT_FILE, smallsort,
                                                                              N32_COPY_LINES[role])],
                    f"{slot} actual copy site or direction differs")
            continue
        require(row["check"] is None and row["native_evidence"].get("copy_sites") == expected,
                f"{slot} local or actual typed-copy sites differ")


def rust_packed(items, indent=8, width=100):
    """rustfmt's mixed layout for short array items under use_small_heuristics=Max."""
    lines, line = [], ""
    for item in items:
        piece = f"{item},"
        candidate = f"{line} {piece}" if line else piece
        if line and indent + len(candidate) > width:
            lines.append(line)
            candidate = piece
        line = candidate
    lines.append(line)
    return "".join(" " * indent + entry + "\n" for entry in lines)


def n32_s8_left_text():
    """Actual left sort8_stable of :299 at len=32: S -> D with tmp D+32 in one D48."""
    label = "GEN_N32_U64_S8_L48"
    return (
        "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_u64_s8_l48_full() {\n"
        "        let mut v: [u64; 34] = kani::any();\n"
        "        let before = v;\n"
        "        let probe: u64 = kani::any();\n"
        "        let mut scratch = [MaybeUninit::<u64>::uninit(); 48];\n"
        "        for i in 8..32 {\n            scratch[i].write(kani::any());\n        }\n"
        "        for i in 40..48 {\n            scratch[i].write(kani::any());\n        }\n"
        "        let scratch_before = scratch;\n"
        "        let s = v[1..33].as_mut_ptr();\n"
        "        let d = scratch.as_mut_ptr().cast::<u64>();\n"
        "        let mut less = u64_less;\n"
        "        // SAFETY: The eight initialized source words S[0..8] are in the separate V34.\n"
        "        // The writable D[0..8] and D[32..40] are disjoint intervals of scratch48.\n"
        "        unsafe { sort8_stable(s, d, d.add(32), &mut less) };\n\n"
        "        let mut ordered = true;\n"
        "        let mut tmp_left_ordered = true;\n"
        "        let mut tmp_right_ordered = true;\n"
        "        let mut input_count = 0;\n"
        "        let mut output_count = 0;\n"
        "        let mut adjacent_equal = false;\n"
        "        let mut inversion = false;\n"
        "        for i in 0..8 {\n"
        "            input_count += usize::from(before[1 + i] == probe);\n"
        "            // SAFETY: A normal return writes each output word.\n"
        "            output_count += usize::from(unsafe { scratch[i].assume_init() } == probe);\n"
        "        }\n"
        "        for i in 0..7 {\n"
        "            adjacent_equal |= before[1 + i] == before[2 + i];\n"
        "            inversion |= before[1 + i] > before[2 + i];\n"
        "            // SAFETY: Both words are in the initialized output interval.\n"
        "            ordered &= unsafe { scratch[i].assume_init() <= scratch[1 + i].assume_init() };\n"
        "        }\n"
        "        for i in 0..3 {\n"
        "            // SAFETY: The two inner sort4 calls initialize both temporary blocks.\n"
        "            unsafe {\n"
        "                tmp_left_ordered &= scratch[32 + i].assume_init() <= scratch[33 + i].assume_init();\n"
        "                tmp_right_ordered &= scratch[36 + i].assume_init() <= scratch[37 + i].assume_init();\n"
        "            }\n"
        "        }\n"
        + n32_v_frame(n32_types("u64"), "v_frame") +
        "        let mut scratch_frame = true;\n"
        + "".join(
            f"        for i in {lo}..{hi} {{\n"
            "            // SAFETY: This frame interval was initialized before the call.\n"
            "            scratch_frame &= unsafe { scratch[i].assume_init() == scratch_before[i].assume_init() };\n"
            "        }\n" for lo, hi in ((8, 32), (40, 48))) +
        f"        kani::assert(ordered, \"{label}_SORTED\");\n"
        f"        kani::assert(input_count == output_count, \"{label}_PROBE_MULTIPLICITY\");\n"
        f"        kani::assert(tmp_left_ordered, \"{label}_TMP_LEFT_SORTED\");\n"
        f"        kani::assert(tmp_right_ordered, \"{label}_TMP_RIGHT_SORTED\");\n"
        f"        kani::assert(v_frame, \"{label}_V_FRAME\");\n"
        f"        kani::assert(scratch_frame, \"{label}_SCRATCH_FRAME\");\n"
        f"        kani::cover(inversion, \"{label}_MIXED_INVERSION\");\n"
        f"        kani::cover(adjacent_equal, \"{label}_EQUAL_INPUT\");\n"
        f"        kani::cover(true, \"{label}_RETURNED\");\n"
        "    }\n"
    )


# Stable u64 control: in each half of S the first eight words are 1,0,1,0,1,0,1,0 and the other eight are 1.
N32_U64_WITNESS_WORDS = (1, 0, 1, 0, 1, 0, 1, 0, *(1,) * 8) * 2
N32_U64_WITNESS_CANARIES = (0x1111_2222_3333_4444, 0xAAAA_BBBB_CCCC_DDDD)
N32_U64_WITNESS_FLIP = 8  # v[8] is S[7], the last zero of the sorted output.


def n32_u64_witness_masks():
    """Recompute the input ones, sorted mask and corrupted mask from the literal words alone."""
    words = N32_U64_WITNESS_WORDS
    ones = sum(words)
    output = sorted(words)
    mask = sum(1 << i for i, word in enumerate(output) if word == 1)
    flipped = list(output)
    flipped[N32_U64_WITNESS_FLIP - 1] ^= 1
    corrupted = sum(1 << i for i, word in enumerate(flipped) if word == 1)
    require(len(words) == 32 and set(words) == {0, 1} and ones == 24 and mask == 0xFFFF_FF00
            and corrupted == 0xFFFF_FF80 and bin(corrupted).count("1") == ones + 1
            and all(flipped[i] <= flipped[i + 1] for i in range(31)) and output[N32_U64_WITNESS_FLIP - 1] == 0
            and output[N32_U64_WITNESS_FLIP] == 1,
            "N32 u64 witness must keep order and break only the multiplicity of ones")
    return ones, mask, corrupted


def n32_u64_witness_text():
    ones, mask, corrupted = n32_u64_witness_masks()
    left, right = N32_U64_WITNESS_CANARIES
    label = "GEN_N32_STABLE_U64"
    frame = "v[0] == U64_LEFT && v[33] == U64_RIGHT"
    return (
        f"    const U64_LEFT: u64 = {rust_hex(left)};\n"
        f"    const U64_RIGHT: u64 = {rust_hex(right)};\n\n"
        "    // Literal V34: S[0..8] and S[16..24] are 1,0,1,0,1,0,1,0, every other S word is 1.\n"
        "    const U64_INPUT: [u64; 34] = [\n"
        + rust_packed(["U64_LEFT", *map(str, N32_U64_WITNESS_WORDS), "U64_RIGHT"]) +
        "    ];\n\n"
        "    fn stable_u64_mask(v: &[u64; 34]) -> (u32, bool, bool) {\n"
        "        let mut mask = 0;\n"
        "        let mut canonical = true;\n"
        "        let mut ordered = true;\n"
        "        for i in 0..32 {\n"
        "            mask |= u32::from(v[1 + i] == 1) << i;\n"
        "            canonical &= v[1 + i] == 0 || v[1 + i] == 1;\n"
        "        }\n"
        "        for i in 1..32 {\n"
        "            ordered &= v[i] <= v[i + 1];\n"
        "        }\n"
        "        (mask, canonical, ordered)\n"
        "    }\n\n"
        "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_stable_u64_witness_literal_corrupt() {\n"
        "        let mut v = U64_INPUT;\n"
        "        let mut ones = 0;\n"
        "        for i in 0..32 {\n"
        "            ones += u32::from(U64_INPUT[1 + i] == 1);\n"
        "        }\n"
        "        let mut scratch = [MaybeUninit::<u64>::uninit(); 48];\n"
        "        let mut less = u64_less;\n"
        "        <u64 as StableSmallSortTypeImpl>::small_sort(&mut v[1..33], &mut scratch, &mut less);\n"
        "        kani::cover(true, \"AFTER_STABLE_N32_RETURN\");\n\n"
        "        let (mask, canonical, ordered) = stable_u64_mask(&v);\n"
        f"        kani::assert(canonical, \"{label}_BEFORE_CANONICAL\");\n"
        f"        kani::assert(ordered, \"{label}_BEFORE_ORDER\");\n"
        "        kani::assert(\n"
        f"            ones == {ones} && mask.count_ones() == ones,\n"
        f"            \"{label}_BEFORE_MULTIPLICITY\",\n"
        "        );\n"
        f"        kani::assert(mask == {rust_hex(mask)}, \"{label}_BEFORE_MASK\");\n"
        f"        kani::assert({frame}, \"{label}_BEFORE_FRAME\");\n\n"
        f"        v[{N32_U64_WITNESS_FLIP}] ^= 1u64;\n"
        "        let (mask, canonical, ordered) = stable_u64_mask(&v);\n"
        f"        kani::assert(canonical, \"{label}_AFTER_CANONICAL\");\n"
        f"        kani::assert(ordered, \"{label}_AFTER_ORDER\");\n"
        f"        kani::assert(mask == {rust_hex(corrupted)}, \"{label}_AFTER_MASK\");\n"
        f"        kani::assert({frame}, \"{label}_AFTER_FRAME\");\n"
        f"        kani::assert(mask.count_ones() == ones, \"{label}_MULTIPLICITY\");\n"
        "    }\n"
    )


def rust_hex(value):
    """Lower-case hexadecimal literal with underscores every four digits, as written in the module."""
    digits = f"{value:x}"
    groups = []
    while digits:
        groups.insert(0, digits[-4:])
        digits = digits[:-4]
    return "0x" + "_".join(groups)


def n32_wide_witness_text():
    """The Wide witness tail, from its keys, swap and canaries; check_literal_witness_source re-derives it."""
    keys, (a, b) = N32_WITNESS_KEYS, N32_WITNESS_SWAP
    length, half = len(keys), len(keys) // 2
    expected = sorted(range(1, length + 1), key=lambda index: keys[index - 1])
    corrupted = list(expected)
    corrupted[a], corrupted[b] = corrupted[b], corrupted[a]
    tags = [index - 1 for index in expected]
    canary = lambda name, record: (f"    const {name}: Wide = Wide {{ key: {record[0]}, tag: {record[1]}, "
                                   f"payload: {rust_hex(record[2])} }};\n")
    label = "GEN_N32_WIDE"
    frame = f"same_wide(v[0], LEFT) && same_wide(v[{length + 1}], RIGHT)"
    return (
        N32_WIDE_WITNESS_MARKER
        + canary("LEFT", N32_WITNESS_LEFT) + canary("RIGHT", N32_WITNESS_RIGHT) +
        "\n    const fn input_record(key: u64, tag: u64) -> Wide {\n"
        "        Wide { key, tag, payload: 0x8000_0000_0000_0100 + tag }\n    }\n\n"
        f"    const INPUT: [Wide; {length + 2}] = [\n        LEFT,\n"
        + "".join(f"        input_record({key}, {tag}),\n" for tag, key in enumerate(keys)) +
        "        RIGHT,\n    ];\n\n"
        "    // Indices in INPUT, including its left canary at index zero.\n"
        f"    const EXPECTED: [Wide; {length}] = [\n" + rust_packed(f"INPUT[{i}]" for i in expected) + "    ];\n\n"
        f"    const CORRUPTED: [Wide; {length}] = [\n" + rust_packed(f"INPUT[{i}]" for i in corrupted) + "    ];\n\n"
        f"    fn observe(v: &[Wide; {length + 2}], expected: &[Wide; {length}]) -> (bool, bool, bool) {{\n"
        "        let mut exact = same_wide(v[1], expected[0]);\n"
        "        let mut ordered = true;\n"
        "        let mut stable = true;\n"
        f"        for i in 1..{length} {{\n"
        "            let (a, b) = (v[i], v[i + 1]);\n"
        "            exact &= same_wide(b, expected[i]);\n"
        "            ordered &= a.key <= b.key;\n"
        "            stable &= a.key != b.key || a.tag < b.tag;\n"
        "        }\n"
        "        (ordered, exact, stable)\n"
        "    }\n\n"
        "    #[kani::proof]\n    #[kani::unwind(36)]\n    fn gen_n32_wide_witness_literal_corrupt() {\n"
        "        let mut v = INPUT;\n"
        "        let mut less = wide_less;\n"
        f"        <Wide as UnstableSmallSortTypeImpl>::small_sort(&mut v[1..{length + 1}], &mut less);\n"
        "        kani::cover(true, \"AFTER_WIDE_N32_RETURN\");\n\n"
        "        let (ordered, exact, stable) = observe(&v, &EXPECTED);\n"
        f"        kani::assert(ordered, \"{label}_BEFORE_ORDER\");\n"
        f"        kani::assert(exact, \"{label}_BEFORE_RECORDS_BY_TAG\");\n"
        f"        kani::assert(stable, \"{label}_BEFORE_STABLE_EQUAL_KEYS\");\n"
        "        kani::assert(\n"
        f"            v[{a + 1}].key == {keys[tags[a]]} && v[{b + 1}].key == {keys[tags[b]]} && "
        f"v[{a + 1}].tag == {tags[a]} && v[{b + 1}].tag == {tags[b]},\n"
        f"            \"{label}_BEFORE_SWAP_PAIR\",\n"
        "        );\n"
        f"        kani::assert({frame}, \"{label}_BEFORE_FRAME\");\n"
        "        kani::cover(\n"
        f"            v[{a + 1}].key == v[{b + 1}].key && v[{a + 1}].tag < {half} && v[{b + 1}].tag >= {half},\n"
        f"            \"{label}_WITNESS_CROSS_HALF_TIE\",\n"
        "        );\n\n"
        f"        let left = v[{a + 1}];\n        v[{a + 1}] = v[{b + 1}];\n        v[{b + 1}] = left;\n"
        "        let (ordered, exact, stable) = observe(&v, &CORRUPTED);\n"
        f"        kani::assert(ordered, \"{label}_AFTER_ORDER\");\n"
        f"        kani::assert(exact, \"{label}_AFTER_RECORDS_BY_TAG\");\n"
        f"        kani::assert({frame}, \"{label}_AFTER_FRAME\");\n"
        f"        kani::assert(stable, \"{label}_STABLE_EQUAL_KEYS\");\n"
        "    }\n"
    )


def n32_closure_module_text(declaration=None):
    """The whole appended closure module, from its declaration to the closing brace that ends the file."""
    declaration = N32_CLOSURE_DECLARATION if declaration is None else declaration
    head = ("    use super::super::super::{StableSmallSortTypeImpl, UnstableSmallSortTypeImpl};\n"
            "    use super::*;\n\n")
    items = [n32_s8_left_text(), n32_u64_witness_text(), n32_wide_witness_text()]
    return declaration + head + "\n".join(items) + "}\n"


def check_n32_closure_source(source):
    """Bind the appended closure module byte for byte to its render. It must close the file."""
    require(source.count(N32_CLOSURE_DECLARATION) == 1, "N32 closure module declaration missing or ambiguous")
    start = source.index(N32_CLOSURE_DECLARATION)
    expected = n32_closure_module_text()
    require(source[start:] == expected, "N32 closure module differs from its V34/D48 render")
    tail = source[start:]
    # The left S8 reads S[0..8] and writes only D[0..8] and its tmp D[32..40]; the frame covers the rest of D48.
    s8 = n32_s8_left_text()
    require(s8.count("sort8_stable(s, d, d.add(32), &mut less)") == 1 and "for i in 8..32 {" in s8
            and "for i in 40..48 {" in s8 and "kani::assume" not in s8, "left S8 geometry differs")
    # Both controls are literal: no nondeterminism, assumption, stub or contract after the S8 root.
    controls = tail[tail.index("    const U64_LEFT: u64"):]
    for token in ("kani::any", "kani::assume", "kani::stub", "stub_verified", "proof_for_contract", "cfg_attr",
                  "requires(", "modifies(", "memcmp"):
        require(token not in controls, f"N32 closure controls contain {token}")
    # Every literal loop is shorter than unwind 36.
    bounds = [(int(lo), int(hi)) for lo, hi in re.findall(r"for [ij] in (\d+)\.\.(\d+) \{", tail)]
    require(bounds and all(hi - lo < 36 for lo, hi in bounds), "N32 closure loop exceeds unwind36")
    n32_u64_witness_masks()
    return expected


def check_n32_closure_copy_sites(std, overlay, rows):
    """Typed-copy sites reached by each actual route at N32. Insert shift and gap-guard sites are not reached."""
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    sort4 = [copy_site(SMALLSORT_FILE, smallsort, line) for line in range(832, 836)]
    merge = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (885, 918)]
    fill = [copy_site(SMALLSORT_FILE, smallsort, 329)]
    for row in rows:
        _, role, _, _ = N32_CLOSURE_GEOMETRY[row["id"]]
        expected = sort4 + merge if role == "s8" else sort4 + fill + merge
        require(row["check"] is None and row["native_evidence"].get("copy_sites") == expected,
                f"{row['id']} actual typed-copy sites differ")


def copy_site(file, lines, line):
    token = lines[line - 1].lstrip(" ")
    require(token.startswith("ptr::copy_nonoverlapping("), f"copy moved at {file}:{line}")
    return {"file": file, "line": line, "column": len(lines[line - 1]) - len(token) + 1, "token": token}


def check_fix1_copy_sites(std, overlay, rows, module_source):
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    directions = dict(zip(FIX1_SLOT_IDS, (("up", 885), ("down", 918))))
    for row in rows:
        slot = row["id"]
        direction, line = directions[slot]
        check = FIX1_CHECK_TARGETS[slot]
        body = re.search(rf"(?ms)^    unsafe fn {check}\(.*?^    }}", module_source)
        expected = copy_site(SMALLSORT_FILE, smallsort, line)
        require(body is not None and re.findall(r"= (merge_(?:up|down))\(", body[0]) == [f"merge_{direction}"]
                and "ptr::copy_nonoverlapping(" not in body[0]
                and row["check_evidence"].get("copy_sites") == [expected], f"{slot} actual copy site or direction differs")


def check_pilot_copy_sites(std, overlay, rows, module_source):
    """Keep the local fill copy distinct from the actual caller it transcribes."""
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    module = module_source.splitlines()
    sort4 = [copy_site(SMALLSORT_FILE, smallsort, line) for line in range(832, 836)]
    merge = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (885, 918)]
    local = [i for i, line in enumerate(module, 1)
             if line.strip() == "ptr::copy_nonoverlapping(s.add(12), d.add(12), 1);"]
    require(len(local) == 1, "pilot requires one local copy at offset 8, rel4")
    transcription = copy_site(PILOT_MODULE_FILE, module, local[0])
    transcription["transcribes"] = copy_site(SMALLSORT_FILE, smallsort, 329)
    fill = [transcription, *[copy_site(SMALLSORT_FILE, smallsort, line) for line in (722, 362)]]
    expected = dict(zip(PILOT_SLOT_IDS, (sort4 + merge, sort4 + merge, sort4, fill, merge, merge)))
    for row in rows:
        evidence = row["check_evidence"] if row["check"] else row["native_evidence"]
        require(evidence.get("copy_sites") == expected[row["id"]], f"{row['id']} copy sites differ")


def close_copy_sites(std, overlay, slot, module_source):
    smallsort = git_blob(std, overlay, f"library/{SMALLSORT_FILE}").decode("utf-8").splitlines()
    sort4 = [copy_site(SMALLSORT_FILE, smallsort, line) for line in range(832, 836)]
    merge = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (885, 918)]
    fill = [copy_site(SMALLSORT_FILE, smallsort, line) for line in (722, 362)]
    if slot in CLOSE_U64_SLOTS:
        return sort4 + merge
    if slot == CLOSE_SLOT_IDS[1]:
        return sort4
    if slot == CLOSE_SLOT_IDS[5] or slot in WITNESS_SLOT_IDS:
        return sort4 + [copy_site(SMALLSORT_FILE, smallsort, 329)] + fill + merge
    tail = 8 + int(slot[-1])
    module = module_source.splitlines()
    local = [i for i, line in enumerate(module, 1)
             if line.strip() == f"ptr::copy_nonoverlapping(s.add({tail}), d.add({tail}), 1);"]
    require(len(local) == 1, f"{slot} requires one local copy at offset 8")
    require(module[local[0]].strip() == f"insert_tail(d.add(8), d.add({tail}), &mut less);",
            f"{slot} actual insert_tail has the wrong geometry")
    transcribes = copy_site(PILOT_MODULE_FILE, module, local[0])
    transcribes["transcribes"] = copy_site(SMALLSORT_FILE, smallsort, 329)
    return [transcribes, *fill]


def check_provider_definition(source, row, *, module_file, prefix, check):
    """Recover the exact Proof/Check root and the writable objects from source."""
    selector = row["selector"].removeprefix(prefix)
    attribute = f"proof_for_contract({check})" if check else "proof"
    indent = "    " if prefix in (FIX1_PREFIX, CLOSE_PREFIX, WIDE_WITNESS_PREFIX, N10_WITNESS_PREFIX,
                                   N12_WITNESS_PREFIX, WIDE_N12_N14_PREFIX, N32_PREFIX,
                                   N32_CLOSURE_PREFIX) else ""
    require(row["check"] == check and
            f"{indent}#[kani::{attribute}]\n{indent}#[kani::unwind(36)]\n{indent}fn {selector}() {{" in source,
            f"{row['id']} source root kind or unwind differs")
    if check is None:
        return
    gate = row["check_evidence"]
    modifies = ", ".join(gate["modifies"])
    binding = re.search(rf"(?m)^{indent}#\[cfg_attr\(\n{indent}    kani,\n"
                        rf"(?:{indent}    kani::requires\([^\n]+\),\n)+"
                        rf"{indent}    kani::modifies\({re.escape(modifies)}\)\n"
                        rf"{indent}\)\]\n{indent}unsafe fn {check}\(", source)
    require(binding is not None and gate["file"] == module_file
            and gate["definition"] == gate["target_instance"] == prefix + check
            and gate["lines"] == [source.count("\n", 0, binding.start()) + 1],
            f"{row['id']} Check target or modifies anchor mismatch")
    if prefix in (FIX1_PREFIX, WIDE_N12_N14_PREFIX, N32_PREFIX):
        scopes = {FIX1_PREFIX: FIX1_MODIFIES, WIDE_N12_N14_PREFIX: WIDE_N12_N14_MODIFIES,
                  N32_PREFIX: N32_MODIFIES}[prefix]
        require(gate.get("column") == len(indent) + 1 and modifies == scopes[row["id"]],
                f"{row['id']} exact Check scope or cfg_attr column mismatch")
    if module_file == MODULE_FILE:
        if check.startswith("actual_pair_step_"):
            expected_sites = [
                {"file": SMALLSORT_FILE, "line": 885, "column": 9, "token": "ptr::copy_nonoverlapping(src, dst, 1);"},
                {"file": SMALLSORT_FILE, "line": 918, "column": 9, "token": "ptr::copy_nonoverlapping(src, dst, 1);"},
            ]
        else:
            end = source.find("\n}", binding.end())
            require(end != -1, f"{row['id']} Check body end missing")
            pattern = re.compile(r"(?m)^([ ]+)(ptr::copy_nonoverlapping\(last_src, scratch\.add\(\d+\), 1\);)$")
            copies = list(pattern.finditer(source, binding.end(), end))
            require(len(copies) == 1, f"{row['id']} expected one local center copy")
            copy = copies[0]
            expected_sites = [{
                "file": module_file, "line": source.count("\n", 0, copy.start()) + 1,
                "column": len(copy[1]) + 1, "token": copy[2],
                "transcribes": {"file": SMALLSORT_FILE, "line": 1034, "column": 13,
                                "token": "ptr::copy_nonoverlapping(last_src, dst, 1);"},
            }]
        require(gate.get("copy_sites") == expected_sites, f"{row['id']} merge copy sites differ")


def labelled_calls(source):
    """Read the call-start coordinates of literal Kani covers and assertions."""
    pattern = r'(?m)^([ ]*)(?:crate::)?kani::(?:cover|assert)\([^;]*?,\s*"([^"\n]+)"\s*,?\s*\);'
    locations = {}
    for match in re.finditer(pattern, source):
        line = source.count("\n", 0, match.start()) + 1
        column = len(match[1]) + 1
        locations.setdefault(match[2], []).append((line, column))
    return locations


def check_composite_layout(std, consumer, overlay):
    manifest = "library/core/Cargo.toml"
    module = "library/core/src/slice/sort/shared/smallsort/verify/rev2_n32_consumer.rs"
    paths = git(std, "diff", "--name-status", consumer, overlay).splitlines()
    require(paths == [f"M\t{manifest}", f"M\t{module}"], "composite overlay changed out-of-scope sources")
    for path in (manifest, module):
        require(git(std, "ls-tree", "--format=%(objectmode)", consumer, "--", path) ==
                git(std, "ls-tree", "--format=%(objectmode)", overlay, "--", path), f"{path} mode changed")
    declaration = f"    'cfg({CFG[6]})',\n".encode("ascii")
    manifest_on = git_blob(std, overlay, manifest)
    require(manifest_on.count(declaration) == 1 and manifest_on.replace(declaration, b"", 1) ==
            git_blob(std, consumer, manifest), "composite manifest changed outside the lint declaration")
    body = git_blob(std, overlay, module)
    root = (f"#[cfg({CFG[6]})]\n#[kani::proof]\n#[kani::unwind(36)]\n"
            "fn n32_composite_witness_corrupt() {\n    check_network::<true>(0x0001_0001);\n}\n\n").encode("ascii")
    for current, previous in (
        (root, b""),
        (b"check_network::<false>(kani::any());", b"check_network::<false>();"),
        (b"check_network::<true>(kani::any());", b"check_network::<true>();"),
        (b"fn check_network<const CORRUPT: bool>(input_mask: u32) {\n"
         b"    let mut backing: [u8; BACKING_LEN] = kani::any();\n",
         b"fn check_network<const CORRUPT: bool>() {\n"
         b"    let mut backing: [u8; BACKING_LEN] = kani::any();\n"
         b"    let input_mask: u32 = kani::any();\n"),
    ):
        require(body.count(current) == 1, "composite witness or shared helper is missing or duplicated")
        body = body.replace(current, previous, 1)
    require(body == git_blob(std, consumer, module), "composite overlay changed inherited harness behavior or shared post")
    return paths
