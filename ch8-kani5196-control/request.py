# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Exact inputs, case ordering, argv, and limits for the #5196 experiment."""
import json
import re

DIRECTORY = "ch8-kani5196-control"
ENTRYPOINT = f"{DIRECTORY}/campaign.py"
REQUEST = f"{DIRECTORY}/CI-REQUEST.json"
WORKFLOW = ".github/workflows/ch8-q-pilot.yml"
RESULT = "index.json"
MEMBERS = {"regular": "regular.json", "stock": "stock-export.json", "diagnostics": "observations.json"}
CHANGED = {WORKFLOW, ENTRYPOINT, *(f"{DIRECTORY}/{name}.py" for name in (
    "request", "evidence", "observations", "tool_attestation",
    "test_campaign", "test_evidence", "test_tool_attestation",
))}
PAYLOAD = CHANGED | {"ch8-q-pilot-control/run.py", "ch8-q-pilot-control/test_run.py",
                     *(f"ch8-s1-control/{name}.py" for name in (
                         "runner", "rich_evidence", "rustc_diagnostics", "s3_runtime",
                         "r5_runtime", "binding_metadata", "s2_policy", "negative_oracle",
                         "cfg_pfc", "contract_stacks", "ordinary_contracts", "s2_correspondence",
                         "lexical_bindings",
                     ))}
SOURCE = "library/core/src/slice/sort/shared/smallsort"
PREFIX = "slice::sort::shared::smallsort::verify::"
FIXTURE = "tests/expected/uninit/nested-unions/main.rs"
TOOL_FILES = {
    FIXTURE, "tests/expected/uninit/nested-unions/expected", "Cargo.lock", "Cargo.toml",
    "rust-toolchain.toml", "kani-dependencies", "scripts/kani", ".cargo/config.toml", ".gitmodules",
    ".github/actions/setup/action.yml", "scripts/setup/install_rustup.sh",
    "scripts/setup/ubuntu/install_deps.sh", "scripts/setup/ubuntu/install_cbmc.sh",
    "scripts/setup/install_kissat.sh", "library/kani/kani_lib.c", "tools/build-kani/src/sysroot.rs",
    "kani-driver/src/call_cargo.rs", "kani-driver/src/call_single_file.rs",
    "kani-driver/src/frontend/schema_utils.rs", "kani-driver/src/cbmc_property_renderer.rs",
    "kani-driver/src/cbmc_output_parser.rs", "kani-driver/src/project.rs", "kani-driver/src/session.rs",
    "kani-driver/src/call_cbmc.rs", "kani-compiler/src/kani_middle/transform/check_uninit/mod.rs",
}
SHARED_FILES = {
    f"{SOURCE}.rs", f"{SOURCE}/verify.rs", "library/Cargo.lock", "library/Cargo.toml",
    "rust-toolchain.toml", "tool_config/kani-version.toml", ".gitmodules",
    *(f"{SOURCE}/verify/{module}.rs" for module in
      ("scratch_geometry", "merge", "network", "helper_contracts_wide")),
}
STD_FILES = {
    "candidate": SHARED_FILES | {f"{SOURCE}/verify/trait_contracts.rs", f"{SOURCE}/verify/trait_model.rs"},
    "pr752": SHARED_FILES,
}

PINS = {
    "tool": {"repository": "feliperodri/kani", "sha": "bcdc1a0f8dc566654da1f18b4e502f0f4e7ad40a",
             "tree": "15816aaf3b6dfa4855452e34825073db8ca6760f", "declared_nightly": "nightly-2026-11-19"},
    "candidate": {"repository": "Tiramisu-Cake/verify-rust-std",
                  "sha": "152f11556ab19c6dcfa21b5a0f1096603530ce67",
                  "tree": "08c6c08235035dbca44715c4b4822f5c34c041f6", "declared_nightly": "nightly-2026-11-19"},
    "pr752": {"repository": "Tiramisu-Cake/verify-rust-std",
              "sha": "872d5a43380752786415bc00d2a12ce0e930cb37",
              "tree": "384023c2f80a04d0618aa7ce971b1419494b062b", "declared_nightly": "nightly-2026-10-22"},
}
STANDALONE = (
    ("positive", "buffer_written_then_read_ok", "SUCCESS", 43),
    ("negative", "buffer_partly_written_ub", "FAILURE", 52),
)
STD_ROWS = (
    ("S2", "scratch_geometry::stable_u64_min_scratch_n2", "plain", 34, 240, 300,
     "geometry_harness", None),
    ("UF2", "merge::route_safety_all_routes_n2", "plain", 34, 240, 300,
     "define_route_safety_harness", None),
    ("N18", "network::dispatch_reachability_network_u8_n18", "plain", 65, 360, 420,
     "dispatch_reachability_case", None),
    ("M8-C", "helper_contracts_wide::merge_safety_u64_len8_scratch48_src32_dst0", "check",
     34, 240, 300, None, "bidirectional_merge"),
    ("M8-R", "helper_contracts_wide::sort8_safety_u64_scratch48_src32_dst0_merge_stubbed", "replace",
     34, 240, 300, None, "bidirectional_merge"),
    ("S2-C", "trait_contracts::stable_sorts_permutation_u64_len2", "check", 32, 240, 300,
     None, "<u64 as StableSmallSortTypeImpl>::small_sort"),
    ("F2-C", "trait_contracts::freeze_default_sorts_permutation_noncopy_u8_backing4", "check",
     32, 240, 300, None, "<NonCopyKey as UnstableSmallSortFreezeTypeImpl>::small_sort"),
)
TRAIT_COVERS = ["sort model enabled before call", "ascending input returns", "descending input returns",
                "duplicate input returns", "trait small_sort returns"]
COVERS = {
    "S2": ["Stable Freeze selects small_sort_general_with_scratch beyond its early return",
           "scratch geometry returns normally and preserves full values"],
    "UF2": ["general u64 safety: normal return reachable", "non-Copy u64 route safety: normal return reachable",
            "stable u64 route safety: normal return reachable"],
    "N18": ["dispatch route normal return is reachable"],
    "M8-C": ["merge length8 entered", "merge length8 returns"],
    "M8-R": ["sort8 scratch48 entered", "sort8 merge consumer returns"],
    "S2-C": TRAIT_COVERS, "F2-C": TRAIT_COVERS,
}
ROOTS = [
    {"id": label, "pin": "tool", "selector": selector, "uninit": True, "mode": "plain",
     "unwind": 8, "harness_seconds": 90, "wall_seconds": 120,
     "expected_verdict": verdict, "read_line": line}
    for label, selector, verdict, line in STANDALONE
] + [
    {"id": f"{pin}-{label}-{'on' if uninit else 'off'}", "pin": pin, "pair": f"{pin}-{label}",
     "selector": PREFIX + suffix, "uninit": uninit, "mode": mode, "contract_target": target,
     "unwind": unwind, "harness_seconds": harness, "wall_seconds": wall, "required_covers": COVERS[label]}
    for pin, rows in (("candidate", STD_ROWS), ("pr752", STD_ROWS[:5]))
    for label, suffix, mode, unwind, harness, wall, _, target in rows
    for uninit in (False, True)
]
STD_ARGV = [
    "{tool_script}", "verify-std", "-Z", "unstable-options", "-Z", "function-contracts",
    "-Z", "mem-predicates", "-Z", "float-lib", "-Z", "c-ffi", "-Z", "loop-contracts",
    "-Z", "quantifiers", "-Z", "stubbing", "--no-assert-contracts", "{uninit}",
    "--harness", "{selector}", "--exact", "--jobs=1", "--output-format=regular",
    "--harness-timeout", "{harness_seconds}s", "-Z", "export-json", "--export-json", "{export}",
    "--verbose", "--target-dir", "{target}", "{std_library}", "--cbmc-args", "--object-bits", "12",
]
STANDALONE_ARGV = [
    "{tool_script}", "main.rs", "-Z", "unstable-options", "-Z", "uninit-checks", "-Z", "export-json",
    "--harness", "{selector}", "--exact", "--jobs=1", "--default-unwind", "8",
    "--harness-timeout", "90s", "--output-format=regular", "--verbose", "--export-json", "{export}",
    "--cbmc-args", "--object-bits", "12",
]
MIB = 1024 * 1024
LIMITS = {
    "job_minutes": 180, "setup_and_build_seconds": 1800, "tool_build_seconds": 900,
    "job_cleanup_upload_seconds": 540, "child_wall_sum_seconds": 7920, "job_margin_seconds": 540,
    "root_launch_headroom_seconds": 30, "root_reap_reserve_seconds": 8, "child_cleanup_seconds": 6,
    "local_rss_kib": 8 * 1024 * 1024, "outer_rss_kib": 12 * 1024 * 1024,
    "memory_reserve_kib": 2 * 1024 * 1024, "stdout_bytes_per_root": 16 * MIB,
    "stderr_bytes_per_root": MIB, "export_bytes_per_root": 8 * MIB,
    "projection_bytes_per_root": 4 * MIB, "artifact_bytes": 128 * MIB, "setup_receipt_bytes": MIB,
}
FIXED = {
    "schema": "ch8-kani5196-request-v1", "result_schema": "ch8-kani5196-index-v1",
    "status": "READY", "go": "NOT_GRANTED", "proof_credit": "NONE",
    "workflow": WORKFLOW, "repository": "Tiramisu-Cake/kani", "event": "push",
    "event_ref": "refs/heads/uninit-ci/ch8-q-pilot-v1", "attempt": "1",
    "concurrency": {"group": "ch8-s2-fork", "cancel_in_progress": False}, "runner": "ubuntu-24.04",
    "control_parent": "6518a69cbe3cd70c03cea07ae64305aeba5104fb",
    "pins": PINS, "roots": ROOTS, "limits": LIMITS,
    "std_argv": STD_ARGV, "standalone_argv": STANDALONE_ARGV, "fixture": FIXTURE,
    "solver": "cadical", "dependency_versions": {"cbmc": "6.11.0", "kissat": "4.0.1"},
    "environment_unset": ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN"],
    "evidence": {"channel": "github-actions-artifact", "name": "ch8-kani5196-{run_id}-{attempt}",
                 "retention_days": 7, "index": RESULT, "root_members": MEMBERS,
                 "pair_manifest": "pairs/{pair}.json", "access": "COORDINATOR_AND_REVIEWERS",
                 "availability_before_go": "ACCESS_CONFIRMATION_PENDING"},
}


def load_request(repo):
    request = json.loads((repo / REQUEST).read_bytes())
    inventories = {"control_payload_sha256": PAYLOAD, "tool_files": TOOL_FILES,
                   **{f"{pin}_files": paths for pin, paths in STD_FILES.items()}}
    if not isinstance(request, dict) or request.keys() != FIXED.keys() | inventories.keys():
        raise ValueError("unexpected request schema")
    for key, value in FIXED.items():
        if json.dumps(request[key], sort_keys=True) != json.dumps(value, sort_keys=True):
            raise ValueError(f"frozen request mismatch: {key}")
    for key, paths in inventories.items():
        hashes = request[key]
        if (not isinstance(hashes, dict) or hashes.keys() != paths
                or any(not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)
                       for value in hashes.values())):
            raise ValueError(f"invalid SHA-256 inventory: {key}")
    return request
