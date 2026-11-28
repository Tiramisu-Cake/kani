"""Project bounded setup diagnostics from the supervisor's capped captures."""
import re
import shlex
from pathlib import Path


DIAGNOSTIC_LINES = 80
DIAGNOSTIC_BYTES = 16 * 1024
FALLBACK_LINES = 8
FALLBACK_BYTES = 2048
CARGO_TAIL_BYTES = 4096
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
ERROR = re.compile(r"^[ \t]*error(?:\[([A-Z][A-Za-z0-9_-]{0,31})\])?:")
CARGO_SUMMARY = re.compile(r"^[ \t]*error: could not compile ", re.MULTILINE)


def clean(data):
    return ANSI.sub(b"", data).decode("utf-8", errors="replace").replace("\r", "")


def clip(text, limit):
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def first_diagnostic(directory, stream, child):
    path = directory / f"{stream}.log"
    present = path.is_file()
    size = path.stat().st_size if present else 0
    record = {"stream": stream, "mode": "unavailable", "start_line": None, "end_line": None,
              "start_byte": None, "scanned_bytes": 0, "captured_bytes": size,
              "capture_complete": child.get(f"{stream}_complete"), "truncated": False,
              "line_truncated": False, "text_bytes": 0, "text": "", "header": None, "code": None}
    if not present:
        return record

    with path.open("rb") as source:
        start, first_line = 0, 1
        line_limit, byte_limit = FALLBACK_LINES, FALLBACK_BYTES
        record["mode"] = "prefix_fallback"
        for number, raw in enumerate(source, 1):
            offset = record["scanned_bytes"]
            record["scanned_bytes"] += len(raw)
            line = clean(raw)
            match = ERROR.match(line)
            if match and not CARGO_SUMMARY.match(line):
                record.update(mode="first_error", header=clip(line.rstrip("\n").strip(), 512), code=match[1])
                start, first_line = offset, number
                line_limit, byte_limit = DIAGNOSTIC_LINES, DIAGNOSTIC_BYTES
                break

        source.seek(start)
        excerpt = []
        for number in range(first_line, first_line + line_limit):
            raw = source.readline()
            if not raw:
                break
            line = clean(raw)
            remaining = byte_limit - record["text_bytes"]
            bounded = clip(line, remaining)
            excerpt.append(bounded)
            record["text_bytes"] += len(bounded.encode("utf-8"))
            record["end_line"] = number
            record["line_truncated"] = bounded != line or (not raw.endswith(b"\n") and
                                                            record["capture_complete"] is False)
            if record["line_truncated"] or record["text_bytes"] == byte_limit:
                break
        if excerpt:
            record.update(start_line=first_line, start_byte=start, text="".join(excerpt))
        record["scanned_bytes"] = max(record["scanned_bytes"], source.tell())
        record["truncated"] = (record["line_truncated"] or source.tell() < size or
                               record["capture_complete"] is False)
    return record


def failure_details(directory, child):
    path = directory / "stderr.log"
    tail = None
    if path.is_file():
        with path.open("rb") as source:
            size = path.stat().st_size
            start = max(0, size - CARGO_TAIL_BYTES)
            source.seek(start)
            text = clip(clean(source.read(CARGO_TAIL_BYTES)), CARGO_TAIL_BYTES)
        tail = {"stream": "stderr", "start_byte": start, "captured_bytes": size,
                "capture_complete": child.get("stderr_complete"), "text": text,
                "summary": next((line.strip() for line in reversed(text.splitlines())
                                 if CARGO_SUMMARY.match(line)), None)}
    return {"diagnostics": {stream: first_diagnostic(directory, stream, child) for stream in ("stdout", "stderr")},
            "cargo_tail": tail}


def core_compile_witness(directory, cfg):
    """Record only the matching tokens from Cargo's verbose compiler command."""
    path = directory / "stderr.log"
    if not path.is_file():
        return None
    cfg_flags = ["--cfg=kani", *(f"--cfg={flag}" for flag in cfg)]
    offset = 0
    with path.open("rb") as source:
        for number, raw in enumerate(source, 1):
            start = offset
            offset += len(raw)
            line = clean(raw).strip()
            if not line.startswith("Running `") or not line.endswith("`"):
                continue
            try:
                argv = shlex.split(line[len("Running `"):-1])
            except ValueError:
                continue
            pairs = list(zip(argv, argv[1:]))
            if (("--crate-name", "core") in pairs and ("-Z", "no-codegen") in pairs
                    and all(flag in argv for flag in cfg_flags)
                    and any(Path(arg).name == "kani-compiler" for arg in argv)):
                return {"stream": "stderr", "line": number, "start_byte": start, "crate": "core",
                        "compiler": "kani-compiler", "cfg_flags": cfg_flags, "rustc_option": "-Z no-codegen"}
    return None
