#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Static source invariants; this never invokes a compiler or verifier."""
import argparse
from pathlib import Path
import re


def between(source: str, start: str, end: str) -> str:
    a = source.index(start)
    b = source.index(end, a)
    return source[a:b]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    repo = parser.parse_args().repo
    ptr = (repo / "kani-compiler/src/kani_middle/transform/check_uninit/ptr_uninit/mod.rs").read_text()
    enabled = between(ptr, "fn is_enabled", "fn transform")
    transform = between(ptr, "fn transform", "fn is_harness")
    harness = between(ptr, "fn is_harness", "fn inject_memory_init_setup")
    setup = ptr[ptr.index("fn inject_memory_init_setup"):]
    assert "ExtraChecks::Uninit" in enabled, "pass is not guarded by Uninit ON"
    assert "if is_harness(instance, tcx)" in transform
    assert transform.index("inject_memory_init_setup") < transform.index("UninitInstrumenter::run")
    assert "KaniFunction::try_from(instance)" in harness
    assert "KaniFunction::Intrinsic(KaniIntrinsic::AutomaticHarness)" in harness
    assert 'Symbol::intern("proof_for_contract")' in harness
    assert 'Symbol::intern("proof")' in harness
    assert setup.count("new_body.insert_call(") == 1
    assert "SourceInstruction::Statement { idx: 0, bb: 0 }" in setup
    assert "SourceInstruction::Terminator { bb: 0 }" in setup
    assert "InsertPosition::Before" in setup
    assert "KaniModel::InitializeMemoryInitializationState" in setup

    models = (repo / "library/kani_core/src/mem_init.rs").read_text()
    reset = between(models, "fn initialize_memory_initialization_state()", "/// Get initialization state")
    assert "tracked_object_id = super::any()" in reset
    assert "tracked_offset = super::any()" in reset
    assert "value = false" in reset
    cases = repo / "tests/script-based-pre/autoharness_entry_reset"
    negative = (cases / "uninit_read/main.rs").read_text()
    assert "ptr.add(3).read()" in negative and "union Bytes" in negative
    assert "MaybeUninit" not in negative and "storage" not in negative
    body = lambda path: re.search(r"fn seed_only\(\).*?\n\}", path.read_text(), re.S).group(0)
    assert body(cases / "uninit_off/main.rs") == body(cases / "seed_only/main.rs")
    assert "uninit-checks" not in (cases / "uninit_off/run.sh").read_text()
    print("static source invariants PASS; emitted wrapper/model runtime evidence NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
