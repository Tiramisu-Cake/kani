#!/usr/bin/env python3
"""Offline, bounded CI runner for the frozen Challenge 8 S1 request.

Receipts are observations only. They never grant proof credit. This module is
also deliberately usable with synthetic fixtures; it does not install tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from typing import Any

import rich_evidence
import rustc_diagnostics
import binding_metadata
import s2_policy

HERE = Path(__file__).resolve().parent
REQUEST_PATH = HERE / "CI-REQUEST.json"
STD_SHA = "bd62e54df1b4749154790aa3db3cc7978f547f75"
STD_TREE = "dc2e7a7f258719a05c65bbb9b1e2c7f1e8271ac8"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
MAX_ROW_SECONDS = 600
COMPILE_SECONDS = 900
GROUP_RSS_MAX_KIB = 12 * 1024 * 1024
MEMORY_RESERVE_KIB = 2 * 1024 * 1024
PHASE_SECONDS = 8100
PHASE_CLEANUP_MARGIN = 10
RSS_CAP_KIB = 6 * 1024 * 1024
STDOUT_CAP_BYTES = 16 * 1024 * 1024
STDERR_CAP_BYTES = 1024 * 1024
EXPORT_CAP_BYTES = 8 * 1024 * 1024
ARTIFACT_CAP_BYTES = 256 * 1024 * 1024
UNSTABLE = ("function-contracts", "mem-predicates", "float-lib", "c-ffi",
            "loop-contracts", "quantifiers", "stubbing")


class RunnerError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True, text=True)
    return p.stdout.strip()


def load_request(path: Path = REQUEST_PATH) -> dict[str, Any]:
    try:
        request = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read CI request: {exc}") from exc
    if not isinstance(request,dict):raise RunnerError("request must be an object")
    import s3_profile, s3_pins
    if request.get('profile')=='ch8-s3-2-capped-fullbyte-v1':
        import s32_profile as s3_profile, s32_pins as s3_pins
    if request.get('profile')=='ch8-s3s4-bridge1-fullbyte-v1':
        import s34_profile as s3_profile, s34_pins as s3_pins
    if request.get('profile')=='ch8-s4p-3-network-fullbyte-concrete-calls-v1':
        import s4p3_profile as s3_profile, s4p3_pins as s3_pins
    if request.get('profile')=='ch8-s4p-2r2-network-fullbyte-concrete-calls-v1':
        import s4p2r2_profile as s3_profile, s4p2r2_pins as s3_pins
    if request.get('profile')=='ch8-s4p-2-network-fullbyte-singletons-v1':
        import s4p2_profile as s3_profile, s4p2_pins as s3_pins
    if request.get('profile')=='ch8-s4p-1-fullbyte-length-blocks-v1':
        import s4p_profile as s3_profile, s4p_pins as s3_pins
    s3 = s3_profile.enabled(request)
    expected = {
        "status": "READY", "std_sha": s3_pins.STD_SHA if s3 else STD_SHA, "std_tree": s3_pins.STD_TREE if s3 else STD_TREE,
        "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
    }
    for key, value in expected.items():
        if request.get(key) != value:
            raise RunnerError(f"request binding mismatch: {key}")
    rows = request.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RunnerError("request rows must be a non-empty array")
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RunnerError("row is not an object")
        rid, selector = row.get("id"), row.get("selector")
        if not isinstance(rid, str) or not rid or rid in seen_ids:
            raise RunnerError("missing or duplicate row id")
        if not isinstance(selector, str) or not selector:
            raise RunnerError("missing exact selector")
        seen_ids.add(rid)
        if row.get("mode") not in ("PFC", "Original"):
            raise RunnerError(f"invalid mode for {rid}")
        if row.get("variant") not in ("production", "activation-default", "activation-override"):
            raise RunnerError(f"invalid variant for {rid}")
        if not isinstance(row.get("unwind"), int) or row["unwind"] < 1:
            raise RunnerError(f"invalid unwind for {rid}")
        if row.get("expected") not in ("SUCCESS", "DETECTED"):
            raise RunnerError(f"invalid expected result for {rid}")
        if not isinstance(row.get("required_cover_count"), int) or row["required_cover_count"] < 0:
            raise RunnerError(f"invalid cover count for {rid}")
        timeout = row.get("timeout_seconds")
        if type(timeout) is not int or timeout != MAX_ROW_SECONDS:
            raise RunnerError(f"timeout outside 1..{MAX_ROW_SECONDS} for {rid}")
        if row["expected"] == "DETECTED" and not isinstance(row.get("failure_description"), str):
            raise RunnerError(f"negative row lacks named failure description: {rid}")
        oracle = row.get("oracle")
        if oracle is not None:
            if (not isinstance(oracle, dict) or oracle.get("selector") != selector or
                    oracle.get("class") != "assertion" or not isinstance(oracle.get("property_id"), str) or
                    not oracle["property_id"] or not isinstance(oracle.get("file"), str) or
                    not isinstance(oracle.get("export_file"), str) or type(oracle.get("line")) is not int or
                    oracle["line"] < 1 or not isinstance(oracle.get("source_sha256"), str) or
                    not isinstance(oracle.get("source_line"), str)):
                raise RunnerError(f"invalid negative property oracle: {rid}")
    for key in ("changed_file_sha256", "variants"):
        if not isinstance(request.get(key), dict):
            raise RunnerError(f"missing request {key} object")
    budgets = request.get("budgets")
    if not isinstance(budgets, dict) or any(budgets.get(key) != val for key, val in {
            "phase_seconds": PHASE_SECONDS, "rss_kib": RSS_CAP_KIB,
            "stdout_bytes": STDOUT_CAP_BYTES, "stderr_bytes": STDERR_CAP_BYTES,
            "export_bytes": EXPORT_CAP_BYTES, "artifact_bytes": ARTIFACT_CAP_BYTES,
            "row_seconds": MAX_ROW_SECONDS, "compile_seconds": COMPILE_SECONDS,
            "group_rss_max_kib": GROUP_RSS_MAX_KIB,
            "memory_reserve_kib": MEMORY_RESERVE_KIB}.items()):
        raise RunnerError("request budget mismatch")
    bindings = request.get("source_bindings")
    if not isinstance(bindings, dict) or set(bindings) != seen_ids:
        raise RunnerError("source binding row inventory mismatch")
    for row in rows:
        binding = bindings[row["id"]]
        if (not isinstance(binding, dict) or binding.get("selector") != row["selector"] or
                binding.get("mode") != row["mode"] or binding.get("crate") != "core" or
                not isinstance(binding.get("file"), str) or
                not isinstance(binding.get("locations"), list) or not binding["locations"] or
                any(not isinstance(loc, dict) or type(loc.get("line")) is not int or
                    loc["line"] < 1 or not isinstance(loc.get("source"), str)
                    for loc in binding["locations"]) or
                (row["mode"] == "PFC" and not isinstance(binding.get("target"), str)) or
                (row["mode"] == "Original" and binding.get("target") is not None)):
            raise RunnerError(f"invalid source binding: {row['id']}")
        if row["mode"] == "PFC" and row.get("target") is not None and row.get("target") != binding["target"]:
            raise RunnerError(f"row target/source binding mismatch: {row['id']}")
        oracle = row.get("oracle")
        if oracle is not None and row["variant"] == "production" and oracle["file"] != binding["file"]:
            raise RunnerError(f"negative oracle source location mismatch: {row['id']}")
    execution_groups = request.get("execution_groups")
    if not isinstance(execution_groups, list) or not execution_groups:
        raise RunnerError("execution_groups must be a non-empty ordered array")
    group_rows(request["rows"], execution_groups)
    unions = request.get("replacement_unions")
    if not isinstance(unions, list):
        raise RunnerError("replacement_unions must be an array")
    union_members: set[str] = set()
    for union in unions:
        if (not isinstance(union, dict) or not isinstance(union.get("id"), str) or
                not union["id"] or not isinstance(union.get("member_row_ids"), list) or
                len(union["member_row_ids"]) != 4 or
                not isinstance(union.get("required_cover_messages"), list) or
                not isinstance(union.get("required_success_messages"), list) or
                not union["required_cover_messages"] or not union["required_success_messages"]):
            raise RunnerError("invalid fixed-N replacement union")
        members = union["member_row_ids"]
        if any(not isinstance(x, str) or x not in seen_ids for x in members) or len(set(members)) != 4:
            raise RunnerError("replacement union row inventory mismatch")
        if union_members.intersection(members):
            raise RunnerError("replacement union member duplicated")
        member_rows = [next(r for r in rows if r["id"] == x) for x in members]
        if any(r["mode"] != "PFC" or r["expected"] != "SUCCESS" for r in member_rows):
            raise RunnerError("replacement union must contain four successful PFC cases")
        targets = {bindings[r["id"]]["target"] for r in member_rows}
        if (len(targets) != 1 or {r.get("N") for r in member_rows} != {0, 1, 2, 3} or
                len({r["variant"] for r in member_rows}) != 1 or
                len({r["unwind"] for r in member_rows}) != 1 or
                len({r.get("type") for r in member_rows}) != 1):
            raise RunnerError("replacement union target mismatch")
        union_members.update(members)
    try:
        if s3: s3_profile.validate(request)
        else: s2_policy.validate_request(request)
    except (AssertionError, KeyError, TypeError) as exc: raise RunnerError("S2 request policy mismatch") from exc
    return request


def _source_root(std: Path, tool: Path) -> None:
    std, tool = std.resolve(), tool.resolve()
    if std == tool or std.parent != tool.parent:
        raise RunnerError("std and tool source checkouts must be sibling directories")
    control = HERE.resolve()
    if std == control or tool == control or control in std.parents or control in tool.parents:
        raise RunnerError("source checkout must remain outside CI control workspace")


def verify_source(std: Path, tool: Path, request: dict[str, Any], *, prebuild=False) -> dict[str, Any]:
    _source_root(std, tool)
    bindings = ((std, request["std_sha"], request["std_tree"], "std"), (tool, request["tool_sha"], request["tool_tree"], "tool"))
    for repo, wanted_sha, wanted_tree, label in bindings:
        if git(repo, "rev-parse", "HEAD") != wanted_sha:
            raise RunnerError(f"{label} HEAD drift")
        if git(repo, "rev-parse", "HEAD^{tree}") != wanted_tree:
            raise RunnerError(f"{label} tree drift")
        if git(repo, "cat-file", "-t", wanted_sha) != "commit":
            raise RunnerError(f"{label} pinned commit unavailable")
    for repo, label in ((std, "std"), (tool, "tool")):
        if git(repo, "status", "--porcelain=v1"):
            raise RunnerError(f"{label} production checkout is not clean")
    for rel, digest in request["changed_file_sha256"].items():
        if not isinstance(rel, str) or not isinstance(digest, str):
            raise RunnerError("changed_file_sha256 entries must be path/hash strings")
        path = (std / rel).resolve()
        if std.resolve() not in path.parents or not path.is_file() or sha256(path) != digest:
            raise RunnerError(f"std changed-file SHA drift: {rel}")
    for binding in request.get("source_bindings", {}).values():
        path = (std / binding["file"]).resolve()
        if (std.resolve() not in path.parents or not path.is_file() or
                sha256(path) != binding["sha256"]):
            raise RunnerError("harness source binding SHA drift")
        lines = path.read_text(encoding="utf-8").splitlines()
        for loc in binding["locations"]:
            if loc["line"] > len(lines) or lines[loc["line"]-1] != loc["source"]:
                raise RunnerError("harness source location anchor drift")
    by_id = {row["id"]: row for row in request["rows"]}
    for rid, row in by_id.items():
        oracle = row.get("oracle")
        if oracle is None or row["variant"] != "production":
            continue
        path = (std / oracle["file"]).resolve()
        if (std.resolve() not in path.parents or not path.is_file() or
                sha256(path) != oracle["source_sha256"]):
            raise RunnerError(f"negative oracle source SHA drift: {rid}")
        source_lines = path.read_text(encoding="utf-8").splitlines()
        if oracle["line"] > len(source_lines) or source_lines[oracle["line"]-1] != oracle["source_line"]:
            raise RunnerError(f"negative oracle assertion anchor drift: {rid}")
    if request.get("schema") == "ch8-s2-batch3probes-v1":
        s2_policy.validate_source(std,request)
    if request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):
        import s3_policy
        if request.get("schema")=="ch8-s3-2-v1":import s32_policy as s3_policy
        if request.get("schema")=="ch8-s3s4-bridge1-v1":import s34_policy as s3_policy
        if request.get("schema")=="ch8-s4p-3-v1":import s4p3_policy as s3_policy
        if request.get("schema")=="ch8-s4p-2r2-v1":import s4p2r2_policy as s3_policy
        if request.get("schema")=="ch8-s4p-2-v1":import s4p2_policy as s3_policy
        if request.get("schema")=="ch8-s4p-1-v1":import s4p_policy as s3_policy
        # Native check-source runs every semantic gate before build. Runtime
        # epochs rehash the complete gated dependency set and anchors, avoiding
        # repeated parsing inside the shared180 controller allowance.
        for key in ('cfg_pfc_source_sha256','ordinary_contract_source_sha256','contract_stack_source_sha256','lexical_source_sha256'):
            for rel,digest in request[key].items():
                path=(std/rel).resolve()
                if std.resolve() not in path.parents or not path.is_file() or sha256(path)!=digest:
                    raise RunnerError('S3 dependency snapshot drift: '+rel)
        if prebuild:s3_policy.validate_source(std,request)
    # Variants may describe test overlays; their path/hash are checked when selected.
    return {k:request[k] for k in ("std_sha","std_tree","tool_sha","tool_tree","changed_file_sha256")}


def _variant_info(request: dict[str, Any], name: str) -> tuple[Path, str, dict[str, str]]:
    item = request["variants"].get(name)
    if not isinstance(item, dict):
        raise RunnerError(f"missing variant binding {name}")
    patch = item.get("patch")
    patch_sha = item.get("sha256")
    files = item.get("changed_file_sha256")
    if not isinstance(patch, str) or not isinstance(patch_sha, str) or not isinstance(files, dict):
        raise RunnerError(f"malformed variant binding {name}")
    path = (REQUEST_PATH.parent / patch).resolve()
    if REQUEST_PATH.parent.resolve() not in path.parents or not path.is_file() or sha256(path) != patch_sha:
        raise RunnerError(f"variant patch path/hash mismatch: {name}")
    return path, patch_sha, files


def group_rows(rows: list[dict[str, Any]], execution_groups: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if execution_groups is not None:
        by_id = {row["id"]: row for row in rows}
        if len(by_id) != len(rows):
            raise RunnerError("duplicate row id in execution inventory")
        seen_ids: set[str] = set()
        groups: list[dict[str, Any]] = []
        seen_group_ids: set[str] = set()
        for item in execution_groups:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] or
                    item["id"] in seen_group_ids or item.get("variant") not in
                    ("production", "activation-default", "activation-override") or
                    type(item.get("unwind")) is not int or item["unwind"] < 1 or
                    not isinstance(item.get("row_ids"), list) or not item["row_ids"]):
                raise RunnerError("invalid execution group")
            seen_group_ids.add(item["id"])
            ids = item["row_ids"]
            if any(not isinstance(rid, str) or rid not in by_id for rid in ids) or len(set(ids)) != len(ids):
                raise RunnerError("execution group row inventory mismatch")
            if seen_ids.intersection(ids):
                raise RunnerError("execution groups do not form a disjoint partition")
            members = [by_id[rid] for rid in ids]
            if any(r["variant"] != item["variant"] or r["unwind"] != item["unwind"] for r in members):
                raise RunnerError("execution group compatibility mismatch")
            if len({r["selector"] for r in members}) != len(members):
                raise RunnerError("duplicate selector in invocation group")
            seen_ids.update(ids)
            groups.append({"id": item["id"], "variant": item["variant"],
                           "unwind": item["unwind"], "rows": members})
        if seen_ids != set(by_id):
            raise RunnerError("execution groups do not cover the full row inventory")
        return groups
    groups: dict[tuple[str, int], dict[str, Any]] = {}
    seen: set[tuple[str, int, str]] = set()
    for row in rows:
        key = (row["variant"], row["unwind"])
        identity = (*key, row["selector"])
        if identity in seen:
            raise RunnerError("duplicate selector in invocation group")
        seen.add(identity)
        group = groups.setdefault(key, {"id": f"{key[0]}-u{key[1]}",
                                        "variant": key[0], "unwind": key[1], "rows": []})
        group["rows"].append(row)
    return list(groups.values())


def select_groups(request: dict[str, Any], group_ids: list[str] | None = None) -> list[dict[str, Any]]:
    groups = group_rows(request["rows"], request.get("execution_groups"))
    if group_ids is None:
        return groups
    if not group_ids or any(not isinstance(x, str) or not x for x in group_ids) or len(set(group_ids)) != len(group_ids):
        raise RunnerError("--groups requires a nonempty, unique comma-separated group list")
    known = {g["id"] for g in groups}
    unknown = set(group_ids) - known
    if unknown:
        raise RunnerError(f"unknown execution group(s): {sorted(unknown)}")
    selected = set(group_ids)
    return [g for g in groups if g["id"] in selected]


def aggregate_replacement_union(union, rows, observations):
    # Qualification belongs exclusively to the offline acceptance policy.
    return {"id": union.get("id"), "state": "PENDING_OFFLINE_ACCEPTANCE",
            "member_row_ids": union.get("member_row_ids"),
            "eligible_for_review": False, "proof_credit": "NONE"}


def build_argv(std: Path, tool: Path, selectors: list[str], unwind: int, export: Path) -> list[str]:
    if not selectors or len(set(selectors)) != len(selectors):
        raise RunnerError("nonempty unique exact group selectors required")
    argv = [str((tool.resolve() / "scripts/kani")), "verify-std", "-Z", "unstable-options"]
    for feature in UNSTABLE:
        argv += ["-Z", feature]
    argv += ["--no-assert-contracts", "--jobs=1", "--harness-timeout", "600s"]
    for selector in selectors:
        argv += ["--harness", selector]
    argv += ["--exact", "--default-unwind", str(unwind), "-Z", "export-json",
             "--export-json", str(export.resolve()), "--output-format=regular", str((std.resolve() / "library")),
             "--cbmc-args", "--object-bits", "12"]
    return argv


def ci_env(std: Path | None = None, request=None) -> dict[str, str]:
    env = os.environ.copy()
    fixed = "--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed"
    if request and request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):
        import s3_profile
        fixed=s3_profile.CFG
        if request.get("schema")=="ch8-s4p-3-v1":
            import s4p3_profile
            fixed=s4p3_profile.CFG
        if request.get("schema")=="ch8-s4p-2r2-v1":
            import s4p2r2_profile
            fixed=s4p2r2_profile.CFG
        if request.get("schema")=="ch8-s4p-2-v1":
            import s4p2_profile
            fixed=s4p2_profile.CFG
        if request.get("schema")=="ch8-s4p-1-v1":
            import s4p_profile
            fixed=s4p_profile.CFG
    inherited = env.get("RUSTFLAGS", "").strip()
    if inherited and inherited != fixed:
        raise RunnerError("refusing inherited RUSTFLAGS outside the frozen sorting+controls cfg")
    env["RUSTFLAGS"] = fixed
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    if std is not None:
        # std_project deletes its dummy crate on every invocation, including its
        # default target directory. Keep this job-local cache outside that tree.
        env["CARGO_TARGET_DIR"] = str(std.resolve() / "target/ch8-s1-cargo")
    return env


def _read_pipe_body(pipe, target: Path, cap: int, state: dict[str, Any], lock: threading.Lock, key: str,
               capture_tail: bool = False, rich_parser=None, diagnostics=None) -> None:
    storage_cap = min(cap, 65536) if rich_parser is not None else cap
    head_cap = storage_cap // 2 if capture_tail else storage_cap
    tail_cap = storage_cap - head_cap if capture_tail else 0
    head_kept = 0
    tail = bytearray()
    with target.open("wb") as output:
        while True:
            data = pipe.read(65536)
            if not data:
                break
            with lock:
                room = max(0, cap - state[key + "_kept"])
                if len(data) > room:
                    state[key + "_cap"] = True
                state[key + "_kept"] += min(room, len(data))
                state[key + "_bytes"] += len(data)
                head = state.setdefault(key + "_preview_head", bytearray())
                head.extend(data[:max(0, 2048-len(head))])
                tail_preview = state.setdefault(key + "_preview_tail", bytearray())
                tail_preview.extend(data)
                del tail_preview[:-2048]
            if diagnostics is not None:
                diagnostics.feed(data)
            if rich_parser is not None:
                rich_parser.feed(data)
            head = min(len(data), head_cap - head_kept)
            output.seek(head_kept)
            output.write(data[:head])
            head_kept += head
            if tail_cap:
                tail.extend(data[head:])
                del tail[:-tail_cap]
                # Keep the latest bounded tail durable for a SIGKILL fallback.
                output.seek(head_kept)
                output.write(tail)
                output.truncate()
                output.flush()
        output.seek(head_kept)
        output.write(tail)
    if rich_parser is not None:
        rich_parser.finish()
    if diagnostics is not None:
        diagnostics.finish('AWAITING_EXECUTION_FINALIZATION')
    pipe.close()


def _read_pipe(pipe, target, cap, state, lock, key, capture_tail=False, rich_parser=None, diagnostics=None):
    try:
        _read_pipe_body(pipe, target, cap, state, lock, key, capture_tail, rich_parser, diagnostics)
    except Exception as exc:
        with lock:
            state[key+'_reader_error'] = f'{type(exc).__name__}: {exc}'
        if diagnostics is not None:
            diagnostics.finish('PIPE_READER_ERROR', eof=False)
        pipe.close()


def _group_rss_kib(pgid: int) -> int:
    total = 0
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            if int(tail[2]) != pgid:
                continue
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]); break
        except (OSError, ValueError, IndexError):
            continue
    return total


def _component_rss_kib(pgid: int) -> dict[str, int]:
    values = {"driver": 0, "backend": 0, "compiler": 0, "other": 0}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit(): continue
        try:
            stat = (entry/"stat").read_text()
            if int(stat[stat.rfind(")")+2:].split()[2]) != pgid: continue
            name = (entry/"comm").read_text().strip()
            rss = next(int(x.split()[1]) for x in (entry/"status").read_text().splitlines() if x.startswith("VmRSS:"))
            kind = ("backend" if name in ("cbmc", "goto-instrument", "goto-cc", "goto-analyzer")
                    else "compiler" if name.startswith(("rustc", "kani-compiler"))
                    else "driver" if name.startswith(("kani", "cargo-kani")) else "other")
            values[kind] += rss
        except (OSError, ValueError, IndexError, StopIteration): continue
    return values


def _group_has_live_members(pgid: int) -> bool:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            if int(tail[2]) == pgid and tail[0] != "Z":
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def _kill_group(pgid: int, grace: float = 5.0) -> None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    end = time.monotonic() + grace
    while time.monotonic() < end:
        if not _group_has_live_members(pgid):
            return
        time.sleep(0.05)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _stream_preview(state: dict[str, Any], stream: str) -> dict[str, Any]:
    return {"head": bytes(state.get(stream + "_preview_head", b"")).decode("utf-8", errors="replace"),
            "tail": bytes(state.get(stream + "_preview_tail", b"")).decode("utf-8", errors="replace"),
            "observed_bytes": state.get(stream + "_bytes", 0),
            "scope": "PIPE_BYTES_OBSERVED_AT_SNAPSHOT_NOT_PER_HARNESS"}


class CompileMonitor:
    """The stock initial export marker is written after std_project, before verification."""
    def __init__(self, receipt_path: Path, export: Path, selectors: list[str],
                 seconds: float = COMPILE_SECONDS, *, identities=None):
        self.path, self.export, self.selectors, self.seconds = receipt_path, export, selectors, seconds
        source_tool={"std_sha":STD_SHA,"tool_sha":TOOL_SHA} if identities is None else dict(identities)
        if identities is not None:
            from s3_evidence import identity
            source_tool=identity(source_tool)
        self.receipt: dict[str, Any] = {
            "schema": "ch8-s1-compile-receipt-v1", "state": "IN_PROGRESS",
            "limit_seconds": seconds, **source_tool,
            "request_sha256": sha256(REQUEST_PATH), "selectors": selectors,
            "scope": "STD_PROJECT_COMPILATION_AND_LINK_UNTIL_INITIAL_EXPORT",
            "proof_credit": "NONE", "elapsed_upper_bound_seconds": None}
        _write_json(self.path, self.receipt)

    def poll(self, elapsed: float, state: dict[str, Any]) -> bool:
        if self.receipt["state"] != "IN_PROGRESS":
            return False
        if elapsed >= self.seconds:
            return True
        try:
            if self.export.stat().st_size > EXPORT_CAP_BYTES:
                return False
            data = self.export.read_bytes()
            value = json.loads(data)
        except (OSError, UnicodeError, ValueError):
            return False
        if not _selection_matches(value, self.selectors, marker=True):
            return False
        self.receipt.update(state="COMPLETE", boundary="STOCK_INITIAL_EXPORT_OBSERVED",
                            observed_run_state=value["run_state"],
                            elapsed_upper_bound_seconds=round(elapsed, 3),
                            marker_sha256=hashlib.sha256(data).hexdigest())
        for name in ("stdout", "stderr"):
            self.receipt[name] = _stream_preview(state, name)
        _write_json(self.path, self.receipt)
        return False

    def finish(self, execution: dict[str, Any], state: dict[str, Any]) -> None:
        if self.receipt["state"] == "IN_PROGRESS":
            # A very fast child may have exited between polling iterations.
            elapsed = execution.get("elapsed_seconds", self.seconds)
            self.poll(elapsed, state)
        if self.receipt["state"] == "IN_PROGRESS":
            self.receipt.update(state="FAILED", reason=execution.get("termination_reason") or
                                execution.get("runner_error") or "NO_VALID_INITIAL_EXPORT_BOUNDARY")
            for name in ("stdout", "stderr"):
                self.receipt[name] = _stream_preview(state, name)
        self.receipt["rustc_diagnostics"] = execution.get('rustc_diagnostics', rustc_diagnostics.summary(self.path.parent.parent))
        self.receipt["group_execution"] = execution
        _write_json(self.path, self.receipt)


def group_memory_budget(meminfo: Path = Path("/proc/meminfo"),
                        cgroup: Path = Path("/sys/fs/cgroup")) -> dict[str, Any]:
    values = {}
    for line in meminfo.read_text().splitlines():
        if line.startswith("MemAvailable:"):
            values["mem_available_kib"] = int(line.split()[1])
    available = values.get("mem_available_kib")
    if not isinstance(available, int):
        raise RunnerError("cannot establish available memory for group cap")
    # A cgroup can have less headroom than the host's MemAvailable.
    limit = cgroup / "memory.max"
    current = cgroup / "memory.current"
    if limit.is_file() and current.is_file():
        value = limit.read_text().strip()
        if value != "max":
            headroom = max(0, (int(value)-int(current.read_text().strip())) // 1024)
            values["cgroup_headroom_kib"] = headroom
            available = min(available, headroom)
    cap = min(GROUP_RSS_MAX_KIB, available-MEMORY_RESERVE_KIB)
    if cap <= 0:
        raise RunnerError("less than 2 GiB memory reserve available")
    return {**values, "available_kib": available, "reserve_kib": MEMORY_RESERVE_KIB,
            "group_cap_kib": cap, "per_root_cap_kib": RSS_CAP_KIB,
            "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION"}


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            rss_cap_kib: int = RSS_CAP_KIB, stdout_cap: int = STDOUT_CAP_BYTES,
            stderr_cap: int = STDERR_CAP_BYTES, export_path: Path | None = None,
            export_cap: int = EXPORT_CAP_BYTES, env: dict[str, str] | None = None,
            capture_tail: bool = False, compile_monitor: CompileMonitor | None = None,
            rich_parser=None, record_identity: bool = False) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    info: dict[str, Any] = {"original_exit_code": None, "signal": None, "timed_out": False,
                            "rss_peak_kib": 0, "rss_status": "SAMPLED_PROCESS_GROUP",
                            "output_truncated": False, "output_bytes": 0, "stdout_bytes":0, "stderr_bytes":0}
    state: dict[str, Any] = {"stdout_cap": False, "stderr_cap": False,
                             "stdout_kept": 0, "stderr_kept": 0,
                             "stdout_bytes": 0, "stderr_bytes": 0}
    lock = threading.Lock()
    captures = {stream: rustc_diagnostics.Capture(stream, cap, out / ('rustc-'+stream+'-receipt.json'))
                for stream, cap in (('stdout', stdout_cap), ('stderr', stderr_cap))}
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f"exec failed: {exc}", elapsed_seconds=time.monotonic() - started)
        for stream, capture in captures.items():
            try:
                capture.finish('SPAWN_FAILED', eof=False)
            except Exception as diagnostic_exc:
                info.setdefault('diagnostic_errors', {})[stream] = f'{type(diagnostic_exc).__name__}: {diagnostic_exc}'
        info['rustc_diagnostics'] = rustc_diagnostics.summary(out)
        if compile_monitor is not None:
            try:
                compile_monitor.finish(info, state)
            except Exception as finish_exc:
                info["runner_exception"] = {"type": type(finish_exc).__name__, "message": str(finish_exc)}
        return info
    threads = [threading.Thread(target=_read_pipe, args=(proc.stdout, out / "stdout.log", stdout_cap,
                                                         state, lock, "stdout", capture_tail, rich_parser, captures["stdout"]), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out / "stderr.log", stderr_cap,
                                                         state, lock, "stderr", capture_tail, None, captures["stderr"]), daemon=True)]
    deadline = started + timeout
    killed_for = None
    external_signal: list[int] = []
    previous_handlers = {}
    cleanup_errors = []
    def handle_external(signum, _frame):
        external_signal.append(signum)
        _kill_group(proc.pid)
    try:
        if record_identity:
            from r5_runtime import census
            info['process_identity']=census().get(proc.pid) or {'pid':proc.pid,'state':'EARLY_EXIT_UNOBSERVED_PGID_STARTTIME'}
            info['rss_scope']='SAMPLED_NONATOMIC_PGID_VmRSS; possible overshoot; not strict tree/kernel/cgroup'
        for thread in threads:
            thread.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, handle_external)
        while proc.poll() is None or any(thread.is_alive() for thread in threads):
            components = _component_rss_kib(proc.pid)
            peaks = info.setdefault("component_group_peak_kib", {})
            for kind, value in components.items(): peaks[kind] = max(peaks.get(kind,0),value)
            info["component_rss_scope"] = "SAMPLED_PROCESS_GROUP_BY_COMM_NOT_PER_ROOT; peaks are not simultaneous"
            rss = _group_rss_kib(proc.pid)
            info["rss_peak_kib"] = max(info["rss_peak_kib"], rss)
            if rss > rss_cap_kib:
                killed_for = "rss_cap"; break
            with lock:
                if state["stdout_cap"] or state["stderr_cap"]:
                    killed_for = "stdout_cap" if state["stdout_cap"] else "stderr_cap"
            if export_path is not None:
                try:
                    if export_path.exists() and export_path.stat().st_size > export_cap:
                        killed_for = "export_cap"
                except OSError:
                    pass
            if compile_monitor is not None:
                with lock:
                    compile_expired = compile_monitor.poll(time.monotonic()-started, state)
                if compile_expired:
                    killed_for = "compile_timeout"; info["timed_out"] = True
            if killed_for:
                break
            if time.monotonic() >= deadline:
                killed_for = "timeout"; info["timed_out"] = True; break
            time.sleep(0.05)
    except BaseException as exc:
        info["runner_exception"] = {"type": type(exc).__name__, "message": str(exc)}
        killed_for = "runner_exception"
    finally:
        if killed_for:
            info["termination_reason"] = killed_for
        # This boundary also covers monitor, sampling, signal-setup and thread
        # failures. The caller snapshots binaries only after shutdown/reaping.
        try:
            _kill_group(proc.pid, 0 if info.get("runner_exception") else 5.0)
        except Exception as exc:
            cleanup_errors.append(f"kill: {type(exc).__name__}: {exc}")
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            code = proc.wait(timeout=7)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
        info["original_exit_code"] = code
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=2)
                if thread.is_alive():
                    cleanup_errors.append("pipe reader did not stop")
        for pipe, thread in zip((proc.stdout,proc.stderr),threads):
            if thread.ident is None:pipe.close()
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except Exception as exc:
                cleanup_errors.append(f"restore signal: {type(exc).__name__}: {exc}")
        shutdown_deadline = time.monotonic() + 2
        while _group_has_live_members(proc.pid) and time.monotonic() < shutdown_deadline:
            time.sleep(0.01)
        info["child_shutdown_verified"] = not _group_has_live_members(proc.pid)
        if not info["child_shutdown_verified"]:
            cleanup_errors.append("process group still has live members")
        if cleanup_errors:
            info["cleanup_errors"] = cleanup_errors
            info.setdefault("termination_reason", "child_cleanup_error")
    info["original_exit_code"] = code
    if code < 0:
        info["signal"] = -code
    if external_signal:
        info["interrupted_by_signal"] = external_signal[-1]
        info["termination_reason"] = "external_signal"
    info["output_bytes"] = state["stdout_bytes"] + state["stderr_bytes"]
    info["stdout_bytes"] = state["stdout_bytes"]
    info["stderr_bytes"] = state["stderr_bytes"]
    info["stdout_truncated"] = state["stdout_cap"]
    info["stderr_truncated"] = state["stderr_cap"]
    info["rss_peak_gib"] = info["rss_peak_kib"] / 1048576
    info["rss_sample_period_seconds"] = 0.05
    if state["stdout_cap"] and not info.get("termination_reason"):
        info["termination_reason"] = "stdout_cap"
    elif state["stderr_cap"] and not info.get("termination_reason"):
        info["termination_reason"] = "stderr_cap"
    try:
        if export_path is not None and export_path.exists() and export_path.stat().st_size > export_cap:
            info["termination_reason"] = "export_cap"
    except OSError as exc:
        info.setdefault("runner_exception", {"type": type(exc).__name__, "message": str(exc)})
        info.setdefault("termination_reason", "export_stat_error")
    info["elapsed_seconds"] = round(time.monotonic() - started, 3)
    for stream, capture in captures.items():
        reader_error = state.get(stream+'_reader_error')
        if reader_error:
            info.setdefault('pipe_reader_errors', {})[stream] = reader_error
            info.setdefault('termination_reason', 'pipe_reader_error')
        # No concurrent parser access if a stuck reader survived bounded shutdown.
        if not threads[0 if stream == 'stdout' else 1].is_alive():
            try:
                capture.finish(info.get('termination_reason') or ('SIGNAL_EOF' if code < 0 else None),
                               eof=capture.eof)
            except Exception as diagnostic_exc:
                info.setdefault('diagnostic_errors', {})[stream] = f'{type(diagnostic_exc).__name__}: {diagnostic_exc}'
    info['rustc_diagnostics'] = rustc_diagnostics.summary(out)
    if info.get('diagnostic_errors'):
        info['rustc_diagnostics'].update(complete=False, incomplete_reasons=
            info['rustc_diagnostics']['incomplete_reasons']+['DIAGNOSTIC_FINALIZATION_ERROR'])
    if compile_monitor is not None:
        try:
            compile_monitor.finish(info, state)
        except BaseException as exc:
            info.setdefault("runner_exception", {"type": type(exc).__name__, "message": str(exc)})
            info.setdefault("termination_reason", "compile_receipt_error")
    return info


def _target_tokens(value: Any) -> list[str] | None:
    """Compare the frozen ASCII Rust path syntax without merging identifiers."""
    if not isinstance(value, str):
        return None
    tokens = re.findall(r"::|[A-Za-z_][A-Za-z_0-9]*|[<>]", value)
    if not tokens or "".join(tokens) != "".join(value.split()):
        return None
    return tokens


def _selection_matches(value: Any, selectors: list[str], *, marker: bool = False) -> bool:
    if (not isinstance(value, dict) or value.get("schema_version") != "0.1.0" or
            value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False or
            value.get("run_state") not in (("INCOMPLETE", "COMPLETE") if marker else ("COMPLETE",)) or
            type(value.get("harness_timeout_s")) not in (int, float) or
            value["harness_timeout_s"] != MAX_ROW_SECONDS):
        return False
    selection = value.get("harness_selection")
    return (isinstance(selection, dict) and selection.get("requested_filters") == selectors and
            selection.get("exact") is True and selection.get("unmatched_filters") == [] and
            type(selection.get("matched_count")) is int and selection["matched_count"] == len(selectors))


def parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 source_binding: dict[str, Any] | None = None, std: Path | None = None,
                 group_selectors: list[str] | None = None) -> dict[str, Any]:
    if not path.is_file():
        return {"state": "MISSING", "outcome": "UNKNOWN"}
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return {"state": "OVERSIZE", "size_bytes": size, "outcome": "UNKNOWN"}
        if size == 0:
            return {"state": "EMPTY", "outcome": "UNKNOWN"}
        data = path.read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"state": "INVALID_OR_PARTIAL", "error": str(exc), "outcome": "UNKNOWN"}
    return validate_export_value(value,row,source_binding=source_binding,std=std,group_selectors=group_selectors)


def validate_export_value(value, row, *, source_binding=None, std=None, group_selectors=None):
    """Same stock binder for local capture and sealed structured-only replay."""
    if value is None:
        return {"state": "NULL", "outcome": "UNKNOWN"}
    if not isinstance(value, dict):
        return {"state": "WRONG_TOP_LEVEL_TYPE", "outcome": "UNKNOWN"}
    if value.get("schema_version") != "0.1.0" or value.get("run_state") != "COMPLETE":
        return {"state": "INCOMPLETE_OR_SCHEMA_DRIFT", "outcome": "UNKNOWN"}
    if value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False:
        return {"state": "WRONG_TOOL_BINDING", "outcome": "UNKNOWN"}
    selectors = group_selectors or [row["selector"]]
    if not _selection_matches(value, selectors) or row["selector"] not in selectors:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harnesses = value.get("harnesses")
    if (not isinstance(harnesses, list) or len(harnesses) != len(selectors) or
            any(not isinstance(h, dict) or not isinstance(h.get("name"), str) for h in harnesses)):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    names = [h["name"] for h in harnesses]
    if len(set(names)) != len(names) or set(names) != set(selectors):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harness = next(h for h in harnesses if h["name"] == row["selector"])
    binding = source_binding or {}
    file = harness.get("file")
    if (harness.get("is_automatically_generated") is not False or
            harness.get("crate_name") != binding.get("crate") or
            binding.get("selector") != row["selector"] or binding.get("mode") != row["mode"] or
            not isinstance(file, str) or std is None or
            (std / file).resolve() != (std / binding.get("file", "")).resolve() or
            type(harness.get("line")) is not int or
            harness["line"] not in [loc["line"] for loc in binding.get("locations", [])]):
        return {"state": "WRONG_SOURCE_BINDING", "outcome": "UNKNOWN"}
    attrs = harness.get("attributes")
    kind = attrs.get("kind") if isinstance(attrs, dict) else None
    contract = harness.get("contract")
    reported_contract_function = None
    if row["mode"] == "PFC":
        if (not isinstance(kind, dict) or len(kind) != 1 or "ProofForContract" not in kind or
                not isinstance(kind["ProofForContract"], dict) or not isinstance(contract, dict)):
            return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
        exported_target = kind["ProofForContract"].get("target_fn")
        expected_target = binding.get("target")
        reported_contract_function = contract.get("contracted_function_name")
        # stringify!(TokenStream) changes whitespace, not token boundaries.
        if (not isinstance(exported_target, str) or not isinstance(expected_target, str) or
                _target_tokens(exported_target) is None or
                _target_tokens(exported_target) != _target_tokens(expected_target) or
                not isinstance(reported_contract_function, str) or not reported_contract_function.strip()):
            return {"state": "CONTRACT_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN",
                    "expected_target": expected_target, "exported_target": exported_target,
                    "contracted_function_name": reported_contract_function}
    elif kind != "Proof" or "contract" not in harness or contract is not None:
        return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
    config = value.get("configuration")
    if (not isinstance(config, dict) or not isinstance(config.get("checks"), dict) or
            config["checks"].get("assert_contracts") is not False or
            any(config["checks"].get(k) is not True for k in
                ("memory_safety", "overflow", "unwinding", "undefined_function")) or
            config.get("cbmc_args") != ["--object-bits", "12"]):
        return {"state": "WRONG_CONFIGURATION", "outcome": "UNKNOWN"}
    enabled_features = value.get("enabled_unstable_features")
    required_features = set(UNSTABLE) | {"export-json"}
    if (not isinstance(enabled_features, list) or not required_features.issubset(set(enabled_features)) or
            any(feature in enabled_features for feature in ("uninit-checks", "valid-value-checks"))):
        return {"state": "WRONG_UNSTABLE_FEATURE_SET", "outcome": "UNKNOWN"}
    if harness.get("resolved_unwind") != row["unwind"]:
        return {"state": "WRONG_UNWIND", "outcome": "UNKNOWN"}
    reported_tools = value.get("tools")
    if not isinstance(reported_tools, dict) or any(not isinstance(reported_tools.get(k), str) or not reported_tools[k]
                                                   for k in ("kani", "rustc", "cbmc")):
        return {"state": "MISSING_TOOL_VERSION", "outcome": "UNKNOWN"}
    outcome = harness.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("kind") != "COMPLETED":
        return {"state": "NOT_COMPLETED", "outcome": "UNKNOWN", "reported_outcome": outcome}
    checks, covers = harness.get("checks"), harness.get("covers")
    if not isinstance(checks, dict) or not isinstance(covers, dict):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    failures = checks.get("failure")
    unsupported = harness.get("unsupported_constructs")
    if not isinstance(failures, list) or not isinstance(unsupported, list):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    try:
        rich_evidence.validate_stock_inventory(harness)
    except ValueError as exc:
        return {"state": "INCONSISTENT_PROPERTY_COUNTS", "outcome": "UNKNOWN", "error": str(exc)}
    return {"state": "RECORDED_OBSERVATION", "outcome": "RECORDED",
            **({"source_root":str(std.resolve())} if 'roles' in row else {}),
            "reported_outcome": outcome, "harness": harness,
            "selected_root": harness["name"], "selected_mode": kind,
            "expected_target_fn": binding.get("target"), "source_binding": binding,
            "reported_contracted_function_name": reported_contract_function,
            "qualified_acceptance": "PENDING_OFFLINE_ACCEPTANCE", "proof_credit": "NONE"}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def binary_fingerprints(tool: Path, export: dict[str, Any]) -> dict[str, Any]:
    candidates = {"kani_driver": tool / "target/kani/bin/kani-driver",
                  "kani_compiler": tool / "target/kani/bin/kani-compiler",
                  "cbmc": None}
    cbmc = shutil.which("cbmc")
    if cbmc:
        candidates["cbmc"] = Path(cbmc)
    tools = export.get("tools") if isinstance(export, dict) else None
    fingerprints = {}
    for name, path in candidates.items():
        item = {"path": str(path) if path is not None else None, "sha256": None}
        try:
            if path is not None and path.is_file():
                item["sha256"] = sha256(path)
        except Exception as exc:
            item["error"] = f"{type(exc).__name__}: {exc}"
        fingerprints[name] = item
    required = all(fingerprints.get(key, {}).get("sha256") for key in ("kani_driver", "kani_compiler", "cbmc"))
    return {"binaries": fingerprints, "required_hashes_present": required,
            "reported_versions": tools if isinstance(tools, dict) else None}


def snapshot_binaries(tool: Path, receipt: dict[str, Any], stage: str) -> dict[str, Any]:
    """Fixed binaries are measured even without a parseable stock export.

    Failure to measure one binary must neither hide the others nor replace the
    child's original exit/exception. The receipt keeps these errors separately.
    """
    try:
        snapshot = binary_fingerprints(tool, {})
    except Exception as exc:
        snapshot = {"binaries": {}, "required_hashes_present": False,
                    "error": f"{type(exc).__name__}: {exc}"}
    required = ["kani_driver", "kani_compiler", "cbmc"]
    missing = [name for name in required if not snapshot["binaries"].get(name, {}).get("sha256")]
    snapshot = dict(snapshot)
    snapshot.update(required_binaries=required, missing_binaries=missing,
                    phase="BEFORE_CHILD" if stage == "before" else "AFTER_CHILD_SHUTDOWN",
                    snapshot_completed=True,
                    state="COMPLETE" if not missing and not snapshot.get("error") else "INCOMPLETE")
    receipt["tool_fingerprints_" + stage] = snapshot
    errors = receipt.setdefault("snapshot_errors", [])
    if snapshot.get("error"):
        errors.append({"stage": stage, "error": snapshot["error"]})
    for name, item in snapshot["binaries"].items():
        if item.get("error") or not item.get("sha256"):
            errors.append({"stage": stage, "binary": name,
                           "error": item.get("error", "required binary missing")})
    return snapshot


def fingerprints_match(before, after):
    for snapshot in (before, after):
        if (not isinstance(snapshot, dict) or snapshot.get("required_hashes_present") is not True
                or snapshot.get("error") or not isinstance(snapshot.get("binaries"), dict)):
            return False
        for name in ("kani_driver", "kani_compiler", "cbmc"):
            item = snapshot["binaries"].get(name)
            if (not isinstance(item, dict) or item.get("error") or
                    not isinstance(item.get("path"), str) or not item["path"] or
                    not isinstance(item.get("sha256"), str) or
                    re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
                return False
    return before["binaries"] == after["binaries"]


def capture_binding_metadata(dest, target, request, group, receipt):
    return binding_metadata.capture(dest, target, request, group, receipt)


def _bounded_log(path: Path, total_bytes: int | None) -> dict[str, Any]:
    """Inline bounded head/tail of the bounded capture, including omissions."""
    if not path.is_file():
        return {"path": path.name, "state": "MISSING", "original_bytes": total_bytes,
                "head": "", "tail": ""}
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(min(size, 2048))
        stream.seek(max(len(head), size - 2048))
        tail = stream.read(2048)
    return {"path": path.name, "state": "CAPTURED", "original_bytes": total_bytes,
            "captured_bytes": size, "capture_layout": "HEAD_THEN_TAIL",
            "head": head.decode("utf-8", errors="replace"),
            "tail": tail.decode("utf-8", errors="replace"),
            "preview_omitted_bytes": max(0, size - len(head) - len(tail)),
            "capture_omitted_bytes": max(0, total_bytes - size) if total_bytes is not None else None,
            "sha256": sha256(path)}


def _run_variant(std: Path, name: str, request: dict[str, Any]) -> tuple[Path | None, dict[str, str]]:
    if name == "production":
        return None, request["changed_file_sha256"]
    patch, _, changed = _variant_info(request, name)
    subprocess.run(["git", "-C", str(std), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(std), "apply", str(patch)], check=True)
    try:
        status = subprocess.run(["git", "-C", str(std), "status", "--porcelain=v1", "-z"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
        records = [item for item in status.split(b"\0") if item]
        if any(len(item) < 4 or item[2:3] != b" " for item in records):
            raise RunnerError(f"cannot parse lossless porcelain status ({name})")
        changed_paths = {os.fsdecode(item[3:]) for item in records}
        if changed_paths != set(changed):
            raise RunnerError(f"variant changed unexpected paths ({name}): {sorted(changed_paths ^ set(changed))}")
        for rel, digest in changed.items():
            path = (std / rel).resolve()
            if std.resolve() not in path.parents or not path.is_file() or sha256(path) != digest:
                raise RunnerError(f"variant changed-file SHA mismatch ({name}): {rel}")
        for row in request.get("rows", []):
            if row["variant"] != name or row.get("oracle") is None:
                continue
            oracle = row["oracle"]; path = std / oracle["file"]
            if (changed.get(oracle["file"]) != oracle["source_sha256"] or
                    path.read_text().splitlines()[oracle["line"]-1] != oracle["source_line"]):
                raise RunnerError("mutant oracle source binding drift")
    except Exception:
        subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
        subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
        raise
    return patch, changed


def _row_base(row: dict[str, Any], status: str = "NOT_RUN") -> dict[str, Any]:
    return {"id": row["id"], "selector": row["selector"], "mode": row["mode"],
            "variant": row["variant"], "status": status, "outcome": "UNKNOWN",
            "original_exit": None, "signal": None}


def _artifact_size(out: Path) -> int:
    total = 0
    for path in out.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return total


def source_under_test_record(request,variant,variant_files,patch):
    value={'base_std_sha':STD_SHA,'variant':variant,
           'file_sha256':{**request['changed_file_sha256'],**variant_files},
           'patch_sha256':sha256(patch) if patch is not None else None}
    if request.get('schema') in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):
        from s3_evidence import identity
        value.update(identity(request),base_std_sha=request['std_sha'],
                     historical_patch_base_std_sha=request['base_std_sha'])
    return value


def _run_group(std: Path, tool: Path, out: Path, request: dict[str, Any],
               group: dict[str, Any], phase_deadline: float, isolated_limits=None) -> tuple[list[dict[str, Any]], str | None]:
    if isolated_limits is not None:
        if request.get('schema') in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):
            import s3_profile as profile
            if request.get("schema")=="ch8-s3-2-v1":import s32_profile as profile
            if request.get("schema")=="ch8-s3s4-bridge1-v1":import s34_profile as profile
            if request.get("schema")=="ch8-s4p-3-v1":import s4p3_profile as profile
            if request.get("schema")=="ch8-s4p-2r2-v1":import s4p2r2_profile as profile
            if request.get("schema")=="ch8-s4p-2-v1":import s4p2_profile as profile
            if request.get("schema")=="ch8-s4p-1-v1":import s4p_profile as profile
            prefix='s3-'
        else:
            import r5_profile as profile
            prefix='r5-'
        profile.validate(request)
        assert len(group['rows'])==1 and group['rows'][0]['id'] in profile.ORDER
        assert group['id']==prefix+group['rows'][0]['id']
    compile_limit=180 if isolated_limits is not None else COMPILE_SECONDS
    dest = out / "groups" / group["id"]
    dest.mkdir(parents=True, exist_ok=True)
    selectors = [row["selector"] for row in group["rows"]]
    export = (dest / "export.json").resolve()
    argv = build_argv(std, tool, selectors, group["unwind"], export)
    results = [{**_row_base(row, "IN_PROGRESS"), "group": group["id"],
                "per_root_rss_kib": None, "cost_phases": {k: "UNKNOWN_NOT_EXPORTED_BY_STOCK" for k in ("body_wall_s", "model_wall_s", "checker_wall_s", "summary_wall_s", "driver_root_rss_kib", "backend_root_rss_kib", "aggregate_root_rss_kib")}, "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION",
                "proof_credit": "NONE"} for row in group["rows"]]
    if request.get("schema")=="ch8-s4p-3-v1":
        for result in results:result["target"]=None
    if request.get("schema")=="ch8-s4p-2r2-v1":
        for result in results:result["target"]=None
    if request.get("schema")=="ch8-s4p-2-v1":
        for result in results:result["target"]=None
    receipt = {"schema": "ch8-s1-group-v1", "state": "IN_PROGRESS", "group": group["id"],
               "invocation_id": uuid.uuid4().hex,
               "argv": argv, "selectors": selectors, "variant": group["variant"],
               "unwind": group["unwind"], "proof_credit": "NONE",
               "compile_limit_seconds": compile_limit,
               "group_budget_seconds": 600 if isolated_limits is not None else compile_limit + sum(r["timeout_seconds"] for r in group["rows"]),
               "std_sha": request["std_sha"] if request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1") else STD_SHA,
               "tool_sha": request["tool_sha"] if request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1") else TOOL_SHA,
               "request_sha256": sha256(REQUEST_PATH)}
    patch = None
    metadata_target = None
    fatal = None
    if isolated_limits is not None:
        from r5_runtime import NativeStarts
        rich=NativeStarts(selectors,std.resolve())
    else:
        rich = rich_evidence.RegularEvidence(selectors, std.resolve())
    s3=request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1")
    if s3:
        from s3_evidence import identity
        receipt.update(identity(request))
    monitor = CompileMonitor(dest / "compile/receipt.json", export, selectors, seconds=compile_limit,
                             **({"identities":identity(request)} if s3 else {}))
    try:
        _write_json(dest / "receipt.json", receipt)
        for result in results:
            _write_json(out / result["id"] / "receipt.json", result)
        source_before = verify_source(std, tool, request)
        receipt["source_before"] = source_before
        before = snapshot_binaries(tool, receipt, "before")
        if not before["required_hashes_present"]:
            raise RunnerError("missing required tool binary hash")
        memory = group_memory_budget()
        if isolated_limits is not None:
            memory['group_cap_kib']=min(memory['group_cap_kib'],RSS_CAP_KIB)
            memory['rss_scope']='POLLED_NONATOMIC_PGID_VmRSS; possible overshoot; not strict kernel/tree/cgroup'
        patch, variant_files = _run_variant(std, group["variant"], request)
        receipt.update(source_before=source_before, tool_fingerprints_before=before,
                       memory=memory, source_under_test=source_under_test_record(request,group["variant"],variant_files,patch))
        child_env = ci_env(std,request) if request.get("schema") in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1") else ci_env(std)
        # Fresh namespace prevents old/native-cache metadata from being labelled
        # as this invocation. This is a runner key, not a compiler instance ID.
        metadata_target = Path(child_env["CARGO_TARGET_DIR"]) / receipt["invocation_id"]
        metadata_target.mkdir(parents=True, exist_ok=False)
        child_env["CARGO_TARGET_DIR"] = str(metadata_target)
        receipt["cargo_target_dir"] = child_env["CARGO_TARGET_DIR"]
        receipt["effective_cfg"] = child_env["RUSTFLAGS"]
        remaining = phase_deadline-time.monotonic()-PHASE_CLEANUP_MARGIN
        if remaining <= 0:
            raise RunnerError("phase_seconds_cap_before_group")
        # Group envelope is compile + all row budgets; the separate phase deadline is authoritative.
        timeout = min(receipt["group_budget_seconds"], remaining)
        if isolated_limits is not None:
            if remaining<600:raise RunnerError('r5_preflight_slot_budget_no_full_child')
            timeout=600
            receipt['r5_limits']={'child_wall_seconds':600,'compile_seconds_inside_child':180,
                'rss_effective_kib':memory['group_cap_kib'],'output_remaining':isolated_limits,
                'rss_scope':memory['rss_scope'],'inner_backend_timeout_seconds':600}

        receipt.update(timeout_seconds=timeout, phase_limited=timeout < receipt["group_budget_seconds"])
        export.unlink(missing_ok=True)
        for stream in ("stdout", "stderr"):
            (dest / (stream+".log")).write_bytes(b"")
        _write_json(dest / "receipt.json", receipt)
        try:
            invocation = execute(argv, std.resolve(), dest, timeout,
                                 rss_cap_kib=memory["group_cap_kib"],
                                 stdout_cap=min(STDOUT_CAP_BYTES,isolated_limits['stdout_bytes']) if isolated_limits is not None else STDOUT_CAP_BYTES,
                                 stderr_cap=min(STDERR_CAP_BYTES,isolated_limits['stderr_bytes']) if isolated_limits is not None else STDERR_CAP_BYTES,
                                 export_path=export,
                                 export_cap=min(EXPORT_CAP_BYTES,isolated_limits['export_bytes']) if isolated_limits is not None else EXPORT_CAP_BYTES,
                                 env=child_env, capture_tail=True, compile_monitor=monitor, rich_parser=rich,
                                 **({"record_identity":True} if isolated_limits is not None else {}))
            receipt["execution"] = invocation
            if isolated_limits is not None and invocation.get('elapsed_seconds',0)>=timeout:
                invocation.update(timed_out=True,termination_reason=invocation.get('termination_reason') or 'child_wall_cutoff')
        except BaseException as exc:
            from s3_runtime import diagnostic
            receipt["execution_exception"] = diagnostic(exc,"runner.execute",epoch="CHILD")
            raise
        finally:
            # execute owns child shutdown/reaping. No export parsing or rich
            # validation may precede this protected same-invocation snapshot.
            snapshot_binaries(tool, receipt, "after")
            _write_json(dest / "receipt.json", receipt)
        if invocation.get("runner_exception") or invocation.get("runner_error"):
            raise RunnerError("group_execution_error")
        # Synthetic execution substitutes must also supply a bound compile receipt.
        if monitor.receipt["state"] != "COMPLETE":
            raise RunnerError("compilation_not_complete")
        if (invocation.get("termination_reason") or invocation.get("timed_out") or
                invocation.get("signal") or invocation.get("stdout_truncated") or invocation.get("stderr_truncated")):
            raise RunnerError("group_execution_interrupted_or_capped")
        raw = json.loads(export.read_text()) if export.is_file() and export.stat().st_size <= EXPORT_CAP_BYTES else None
        if not _selection_matches(raw, selectors):
            raise RunnerError("invalid_group_export")
        harnesses = raw.get("harnesses")
        if (not isinstance(harnesses, list) or len(harnesses) != len(selectors) or
                any(not isinstance(h, dict) or not isinstance(h.get("name"), str) for h in harnesses) or
                len({h["name"] for h in harnesses}) != len(selectors) or
                {h["name"] for h in harnesses} != set(selectors)):
            raise RunnerError("invalid_group_harness_inventory")
        all_success = all(h.get("outcome") == {"kind": "COMPLETED", "verdict": "SUCCESS"} for h in harnesses)
        if invocation.get("original_exit_code") != (0 if all_success else 1):
            raise RunnerError("group_exit_export_mismatch")
        rich.validate(raw)
        _write_json(dest / "properties.json", rich.document())
        receipt["rich_evidence_sha256"] = sha256(dest / "properties.json")
        # Version strings are source-reported metadata, never identity hashes.
        receipt["reported_tool_versions"] = raw.get("tools")
        receipt["export_sha256"] = sha256(export)
        for row, result in zip(group["rows"], results):
            parsed = parse_export(export, row, source_binding=request["source_bindings"][row["id"]],
                                  std=std.resolve(), group_selectors=selectors)
            if request.get('schema') in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1") and parsed.get('outcome')!='RECORDED':
                receipt['source_stage_target_binding_error']=parsed
                raise RunnerError('S3 export source/stage/target binding rejected')
            result.update(status="OBSERVED", outcome=parsed["outcome"], export=parsed,
                          group_export_sha256=receipt["export_sha256"],
                          rich_evidence="groups/" + group["id"] + "/properties.json",
                          rich_evidence_sha256=receipt["rich_evidence_sha256"],
                          verification_time_s=parsed.get("harness", {}).get("resources", {}).get("verification_time_s"),
                          group_original_exit=invocation.get("original_exit_code"),
                          original_exit=None, original_exit_scope="PER_ROOT_DRIVER_EXIT_UNAVAILABLE_IN_BATCH",
                          signal=invocation.get("signal"), group_rss_peak_kib=invocation.get("rss_peak_kib"),
                          group_rss_cap_kib=memory["group_cap_kib"],
                          root_timeout_seconds=MAX_ROW_SECONDS,
                          timeout_scope="STOCK_KANI_CBMC_TIMEOUT_NOT_FULL_INSTRUMENTATION_WALL",
                          diagnostics=f"groups/{group['id']}")
    except BaseException as exc:
        fatal = f"{type(exc).__name__}: {exc}"
        receipt.update(state="FAILED", reason=fatal,
                       original_exception=__import__("s3_runtime").diagnostic(exc,"runner._run_group",epoch="WORKER"))
        for result in results:
            result.update(status="UNKNOWN", outcome="UNKNOWN", reason=fatal)
    finally:
        if not fingerprints_match(receipt.get("tool_fingerprints_before"),
                                  receipt.get("tool_fingerprints_after")):
            receipt["binary_identity"] = "UNKNOWN"
            fatal = (fatal + "; " if fatal else "") + "tool_binary_missing_drift_or_snapshot_error"
        else:
            receipt["binary_identity"] = "MATCH"
        if patch is not None:
            try:
                subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
                subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
            except Exception as exc:
                fatal = (fatal + "; " if fatal else "") + f"variant_cleanup_failed: {exc}"
        try:
            source_after = verify_source(std, tool, request)
            receipt["source_after"] = source_after
            if source_after != receipt.get("source_before"):
                raise RunnerError("source_identity_drift")
        except Exception as exc:
            receipt["source_after_error"]=__import__("s3_runtime").diagnostic(exc,"snapshot.source_after",epoch="WORKER_POST")
            fatal = (fatal + "; " if fatal else "") + f"source_drift: {exc}"
        execution = receipt.get("execution", {})
        if monitor.receipt["state"] == "IN_PROGRESS":
            try:
                monitor.finish({**execution, "runner_error": fatal or "NO_COMPLETION"}, {})
            except Exception as exc:
                receipt["compile_receipt_error"] = f"{type(exc).__name__}: {exc}"
                fatal = (fatal + "; " if fatal else "") + "compile_receipt_error: " + receipt["compile_receipt_error"]
        _write_json(dest / "properties.json", rich.document())
        receipt["location_exceptions"] = rich.location_exceptions()
        if isolated_limits is not None:
            receipt['native_start_events']=rich.starts
            receipt['native_start_scope']='OBSERVED_STOCK_STDOUT_HEADER; source-reported not compiler/origin proof'
            receipt['native_start_verified']=[x['selector'] for x in rich.starts]==selectors
            if any(x['selector'] not in selectors for x in rich.starts) or len(rich.starts)>1:
                fatal='native_selector_mismatch_or_duplicate'
        try:
            receipt["binding_metadata"] = capture_binding_metadata(dest, metadata_target, request, group, receipt)
            if receipt["binding_metadata"]["errors"]:
                fatal = (fatal + "; " if fatal else "") + "binding_metadata_capture_incomplete"
        except Exception as exc:
            receipt["binding_metadata_error"] = f"{type(exc).__name__}: {exc}"
            fatal = (fatal + "; " if fatal else "") + "binding_metadata_capture_error: " + receipt["binding_metadata_error"]
        if fatal:
            receipt.update(state="FAILED", reason=fatal)
            for result in results:
                result.update(outcome="UNKNOWN", reason=fatal)
        else:
            receipt["state"] = "COMPLETE"
        for stream in ("stdout", "stderr"):
            receipt[stream] = _bounded_log(dest / (stream+".log"), execution.get(stream+"_bytes"))
        receipt['rustc_diagnostics'] = execution.get('rustc_diagnostics', rustc_diagnostics.summary(dest))
        receipt["compilation"] = "compile/receipt.json"
        for result in results:
            result.update(group_original_exit=execution.get("original_exit_code"), signal=execution.get("signal"),
                          group_rss_peak_kib=execution.get("rss_peak_kib"),
                          stdout=receipt["stdout"], stderr=receipt["stderr"],
                          rustc_diagnostics=receipt['rustc_diagnostics'],
                          diagnostic_scope="SHARED_GROUP_CAPTURE_NOT_PER_ROOT")
            _write_json(out / result["id"] / "receipt.json", result)
        _write_json(dest / "receipt.json", receipt)
    if _artifact_size(out) > ARTIFACT_CAP_BYTES:
        fatal = "artifact_bytes_cap"
        receipt.update(state="FAILED", reason=fatal)
        for result in results:
            result.update(outcome="UNKNOWN", reason=fatal)
            _write_json(out / result["id"] / "receipt.json", result)
        _write_json(dest / "receipt.json", receipt)
    return results, fatal


def run_rows(std: Path, tool: Path, out: Path, request: dict[str, Any],
             group_ids: list[str] | None = None) -> int:
    out.mkdir(parents=True, exist_ok=True)
    import r5_profile
    if request.get('schema') in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):raise RunnerError('S3 multi-root path refused; use S3 singleton campaign')
    if r5_profile.enabled(request):raise RunnerError('r5 multi-root legacy run refused; use isolated campaign')
    phase_started = time.monotonic()
    deadline = phase_started+PHASE_SECONDS
    all_groups = group_rows(request["rows"], request.get("execution_groups"))
    groups = select_groups(request, group_ids)
    selected_group_ids = {g["id"] for g in groups}
    results: dict[str, dict[str, Any]] = {}
    fatal = None
    for group in groups:
        if _artifact_size(out) > ARTIFACT_CAP_BYTES:
            fatal = "artifact_bytes_cap"
        if deadline-time.monotonic() <= PHASE_CLEANUP_MARGIN:
            fatal = fatal or "phase_seconds_cap_before_group"
        if not fatal:
            observed, fatal = _run_group(std, tool, out, request, group, deadline)
            results.update((r["id"], r) for r in observed)
        else:
            for row in group["rows"]:
                result = {**_row_base(row), "reason": fatal, "group": group["id"], "proof_credit": "NONE"}
                results[row["id"]] = result
                _write_json(out / row["id"] / "receipt.json", result)
        _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "IN_PROGRESS",
                    "stop_reason": fatal, "proof_credit": "NONE", "rows": list(results.values())})
    for group in all_groups:
        if group["id"] in selected_group_ids:
            continue
        for row in group["rows"]:
            result = {**_row_base(row, "NOT_SELECTED"), "reason": "group not selected",
                      "group": group["id"], "proof_credit": "NONE"}
            results[row["id"]] = result
    ordered = [results[row["id"]] for row in request["rows"]]
    unknown = any(results[row["id"]].get("outcome") != "RECORDED" for group in groups for row in group["rows"])
    union_summaries = [aggregate_replacement_union(u, request["rows"], results)
                       for u in request.get("replacement_unions", [])]
    _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "COMPLETE_WITH_UNKNOWN" if unknown else "COMPLETE",
                "stop_reason": fatal, "std_sha": STD_SHA, "tool_sha": TOOL_SHA,
                "std_tree": STD_TREE, "tool_tree": TOOL_TREE,
                "request_sha256": sha256(REQUEST_PATH),
                "phase_elapsed_seconds": round(time.monotonic()-phase_started, 3),
                "selected_groups": [g["id"] for g in groups],
                "replacement_unions": union_summaries,
                "proof_credit": "NONE", "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION", "rows": ordered})
    selected_unknown = any(results[row["id"]].get("outcome") != "RECORDED"
                           for group in groups for row in group["rows"])
    return 1 if fatal or selected_unknown else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("check-source", "run"):
        p = sub.add_parser(command)
        p.add_argument("--std", required=True, type=Path)
        p.add_argument("--tool", required=True, type=Path)
        if command != "check-source":
            p.add_argument("--out", required=True, type=Path)
            p.add_argument("--groups", help="comma-separated ordered subset of request execution group IDs")
    args = parser.parse_args(argv)
    try:
        request = load_request()
        if args.command == "check-source":
            print(json.dumps(verify_source(args.std, args.tool, request, prebuild=True), sort_keys=True))
        else:
            import r5_profile
            if request.get('schema') in ("ch8-s3-1-v1", "ch8-s3-2-v1", "ch8-s3s4-bridge1-v1", "ch8-s4p-1-v1", "ch8-s4p-2-v1", "ch8-s4p-2r2-v1", "ch8-s4p-3-v1"):raise RunnerError('S3 multi-root path refused; use S3 singleton campaign')
            if r5_profile.enabled(request):raise RunnerError('r5 requires isolated r5_campaign.py run; legacy multi-root run refused')
            group_ids = args.groups.split(",") if args.groups is not None else None
            code = run_rows(args.std, args.tool, args.out, request, group_ids)
            if code:
                terminal = json.loads((args.out / 'receipt.json').read_text())
                print('runner: ' + str(terminal.get('stop_reason') or terminal['state']), file=sys.stderr)
            return code
    except Exception as exc:
        print(f"runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
