"""CI capture primitives. No compiler or solver is invoked by importing this module."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

A = "0aac16ef62da9e9d5645782d458593e5d78143ba"
B = "3d9a1809388f74c62ea9fb7320e123db0b8b37fa"
PERF_ROWS = [
    "btreeset/insert_any", "btreeset/insert_multi", "btreeset/insert_same",
    "format", "hashset", "misc/array_fold", "misc/display_trait", "misc/struct_defs",
    "smol_str", "vec/box_dyn", "vec/string", "vec/vec",
    "s2n-quic/common/s2n-codec", "s2n-quic/quic/s2n-quic-core",
    "s2n-quic/quic/s2n-quic-platform",
]
LOCK_ROOTS = ["."] + ["tests/perf/" + p for p in PERF_ROWS if not p.startswith("s2n-quic/")] + ["tests/perf/s2n-quic"]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    temp.replace(path)


def event(data):
    """Separate atomic files also preserve concurrent/nested command exits."""
    dest = Path(os.environ["T1_ARM_DIR"]) / "events" / (uuid.uuid4().hex + ".json")
    write_json(dest, {"time_ns": time.time_ns(), **data})


def execute(argv, **kwargs):
    event({"event": "start", "argv": list(map(str, argv)),
           "cwd": str(Path(kwargs.get("cwd", Path.cwd())).resolve())})
    try:
        result = subprocess.run(argv, **kwargs)
    except BaseException as error:
        event({"event": "exception", "argv": list(map(str, argv)), "error": repr(error)})
        raise
    event({"event": "exit", "argv": list(map(str, argv)), "exit": result.returncode})
    return result


def snapshot(path, kind, harness=None, argv=None):
    path = Path(path).resolve(strict=True)
    source = Path(os.environ["T1_SOURCE"])
    row = os.environ["T1_ROW"]
    logical = f"{kind}/{row}/{harness if kind == 'final' else path.relative_to(source).as_posix()}"
    arm = Path(os.environ["T1_ARM_DIR"])
    name = hashlib.sha256(logical.encode()).hexdigest()
    dest = arm / "files" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    # A repeated key is an error, even if the bytes are the same.
    with dest.open("xb") as output, path.open("rb") as inp:
        shutil.copyfileobj(inp, output)
    record = {"kind": kind, "row": row, "path": str(dest.relative_to(arm)),
              "sha256": digest(dest)}
    event({"event": "snapshot", "key": logical, "source_path": str(path), "sha256": record["sha256"]})
    if harness is not None:
        record["harness"] = harness
    if argv is not None:
        record.update(argv=argv, cwd=str(Path.cwd()))
    write_json(arm / "records" / (name + ".json"), {"key": logical, "record": record})
    return record


def metadata_harnesses(target):
    """Read the actual generated metadata; never use a source grep as census."""
    records = []
    for path in sorted(Path(target).rglob("*.kani-metadata.json")):
        data = json.loads(path.read_text())
        for field in ("proof_harnesses", "test_harnesses"):
            values = data[field]
            if not isinstance(values, list):
                raise ValueError(f"invalid metadata {path}: {field}")
            for h in values:
                if not isinstance(h.get("goto_file"), str) or not isinstance(h.get("pretty_name"), str):
                    raise ValueError(f"unbound harness in {path}")
                records.append((path, h, Path(h["goto_file"]).resolve()))
    return records


def bind_harness(model):
    matches = []
    model = Path(model).resolve(strict=True)
    for _, harness, symtab in metadata_harnesses(os.environ["T1_TARGET"]):
        # ArtifactType::SymTabGoto -> ArtifactType::Goto (remove .symtab).
        linked = Path(str(symtab).removesuffix(".symtab.out") + ".out")
        if linked == model:
            matches.append(harness["pretty_name"])
    if len(matches) != 1:
        raise ValueError(f"CBMC input lacks unique metadata binding: {model}: {matches}")
    return matches[0]
