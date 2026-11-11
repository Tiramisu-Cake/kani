// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bounded, opt-in compiler diagnostics for the KANI3300 investigation.
//!
//! This module only observes values already produced by codegen and MIR passes. It is not
//! consulted unless `KANI3300_TRACE_DIR` is present, and every write failure is contained here.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, create_dir_all};
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

const SCHEMA: &str = "kani3300-trace-v1";
const MAX_RECORDS: usize = 512;
const MAX_RECORD_BYTES: usize = 2048;
// Four compiler processes can each claim one slot. The 24 KiB headroom is reserved for the
// single bounded marker used when a fifth process arrives, keeping the run below 1 MiB.
const MAX_INVOCATION_BYTES: usize = 250 * 1024;
const MAX_STATE_ENTRIES: usize = 64;
const MAX_STATE_KEY_BYTES: usize = 320;
const MAX_FILTERS: usize = 20;
const MAX_FILTER_BYTES: usize = 300;

#[derive(Clone)]
struct Config {
    directory: PathBuf,
    filters: Vec<String>,
    trace_id: Option<String>,
    stage: String,
}

struct Trace {
    file: Option<File>,
    config: Config,
    invocation: String,
    next_seq: usize,
    seen: usize,
    emitted: usize,
    omitted: usize,
    bytes: usize,
    state: &'static str,
    finished: bool,
    coverage: BTreeMap<String, usize>,
    omission_counts: BTreeMap<String, usize>,
    context_root: String,
    context_stage: String,
    context_unit: Option<usize>,
    body_hashes: BTreeMap<String, String>,
    last_writers: BTreeMap<String, Value>,
    unchanged_snapshots: usize,
}

static TRACE: OnceLock<Mutex<Option<Trace>>> = OnceLock::new();
static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
static EXTERNAL_WITNESSES: AtomicUsize = AtomicUsize::new(0);
static EXTERNAL_CACHE_WITNESSES: AtomicUsize = AtomicUsize::new(0);

/// A guard makes the footer best-effort on every compiler return path.
pub(crate) struct InvocationGuard;

impl Drop for InvocationGuard {
    fn drop(&mut self) {
        finish();
    }
}

pub(crate) fn begin() -> InvocationGuard {
    let _ = config();
    InvocationGuard
}

fn trace() -> &'static Mutex<Option<Trace>> {
    TRACE.get_or_init(|| Mutex::new(None))
}

fn config() -> Option<&'static Config> {
    CONFIG.get_or_init(Config::from_env).as_ref()
}

/// Claim a bounded run slot only after a codegen unit contains a selected root.
pub(crate) fn activate() {
    let Some(config) = config() else { return };
    if let Ok(mut guard) = trace().lock()
        && guard.is_none()
    {
        *guard = Trace::open(config.clone());
    }
}

impl Config {
    fn from_env() -> Option<Self> {
        let directory = std::env::var_os("KANI3300_TRACE_DIR")?;
        let filter = std::env::var("KANI3300_TRACE_FILTER").ok()?;
        if filter.len() > 1024 {
            return None;
        }
        let filters: Vec<String> = filter.split(';').map(str::trim).map(str::to_owned).collect();
        if filters.is_empty()
            || filters.len() > MAX_FILTERS
            || filters.iter().map(String::len).sum::<usize>() > 900
            || filters.iter().any(|part| part.is_empty() || part.len() > MAX_FILTER_BYTES)
        {
            return None;
        }
        let trace_id = std::env::var("KANI3300_TRACE_ID").ok();
        if trace_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return None;
        }
        let stage =
            std::env::var("KANI3300_TRACE_STAGE").unwrap_or_else(|_| "kani3300-t1b".to_owned());
        if stage != "kani3300-t1b" {
            return None;
        }
        Some(Self { directory: PathBuf::from(directory), filters, trace_id, stage })
    }
}

impl Trace {
    fn open(config: Config) -> Option<Self> {
        if create_dir_all(&config.directory).is_err() {
            return None;
        }
        let pid = std::process::id();
        let mut slot = None;
        for index in 0..4 {
            let path = config.directory.join(format!("kani3300-trace-{index}.jsonl"));
            if let Ok(file) = OpenOptions::new().write(true).create_new(true).open(path) {
                slot = Some((file, format!("{pid}:{index}")));
                break;
            }
        }
        let Some((file, invocation)) = slot else {
            write_overflow_marker(&config, pid);
            return None;
        };
        let mut trace = Self {
            file: Some(file),
            config,
            invocation,
            next_seq: 0,
            seen: 0,
            emitted: 0,
            omitted: 0,
            bytes: 0,
            state: "COMPLETE",
            finished: false,
            coverage: BTreeMap::new(),
            omission_counts: BTreeMap::new(),
            context_root: String::new(),
            context_stage: "unit_header".to_owned(),
            context_unit: None,
            body_hashes: BTreeMap::new(),
            last_writers: BTreeMap::new(),
            unchanged_snapshots: 0,
        };
        trace.write_record(
            "header",
            json!({
                "filters": trace.config.filters,
                "limits": {"records": MAX_RECORDS, "record_bytes": MAX_RECORD_BYTES,
                    "invocation_bytes": MAX_INVOCATION_BYTES},
                "filter_mode": "semicolon-literal-substring",
            }),
            true,
        );
        Some(trace)
    }

    fn write_record(&mut self, kind: &str, data: Value, is_footer: bool) {
        if self.finished || self.file.is_none() {
            return;
        }
        if !is_footer {
            self.seen += 1;
        }
        let value = json!({
            "schema": SCHEMA,
            "kind": kind,
            "trace_id": self.config.trace_id,
            "stage": self.config.stage,
            "invocation": self.invocation,
            "seq": self.next_seq,
            "context": {"root": self.context_root, "stage": self.context_stage, "unit": self.context_unit},
            "data": data,
        });
        let mut sink = RecordSink { bytes: Vec::with_capacity(MAX_RECORD_BYTES), oversized: false };
        if serde_json::to_writer(&mut sink, &value).is_err() {
            if sink.oversized {
                if !is_footer {
                    self.omitted += 1;
                    *self.omission_counts.entry("oversized_records".to_owned()).or_default() += 1;
                    self.state = "OVERSIZED";
                }
            } else {
                self.state = "IO_ERROR";
                self.file = None;
            }
            return;
        }
        let mut encoded = sink.bytes;
        encoded.push(b'\n');
        let footer_reserve = if is_footer { 0 } else { MAX_RECORD_BYTES };
        if encoded.len() > MAX_RECORD_BYTES
            || self.bytes.saturating_add(encoded.len()).saturating_add(footer_reserve)
                > MAX_INVOCATION_BYTES
        {
            if !is_footer {
                self.omitted += 1;
                *self.omission_counts.entry("oversized_records".to_owned()).or_default() += 1;
                self.state = "OVERSIZED";
            }
            return;
        }
        // Header and footer consume two of the invocation's record allowance.
        if !is_footer && self.emitted + 2 >= MAX_RECORDS {
            self.omitted += 1;
            *self.omission_counts.entry("record_cap".to_owned()).or_default() += 1;
            if self.state == "COMPLETE" {
                self.state = "PARTIAL";
            }
            return;
        }
        if self.file.as_mut().is_some_and(|file| file.write_all(&encoded).is_err()) {
            self.state = "IO_ERROR";
            self.file = None;
            return;
        }
        self.bytes += encoded.len();
        self.next_seq += 1;
        if !is_footer {
            self.emitted += 1;
            *self.coverage.entry(kind.to_owned()).or_default() += 1;
        }
    }

    fn remember_body_hash(&mut self, name: &str, hash: String) {
        if name.len() <= MAX_STATE_KEY_BYTES
            && (self.body_hashes.len() < MAX_STATE_ENTRIES || self.body_hashes.contains_key(name))
        {
            self.body_hashes.insert(name.to_owned(), hash);
        } else {
            self.state_omission("snapshot_state_cap");
        }
    }

    fn state_omission(&mut self, category: &str) {
        *self.omission_counts.entry(category.to_owned()).or_default() += 1;
        if self.state == "COMPLETE" {
            self.state = "PARTIAL";
        }
    }

    fn finish(&mut self) {
        if self.finished || self.file.is_none() {
            self.finished = true;
            return;
        }
        let omitted = self.omitted;
        let state = if !self.omission_counts.is_empty() && self.state == "COMPLETE" {
            "PARTIAL"
        } else {
            self.state
        };
        self.write_record(
            "footer",
            json!({
                "state": state,
                "seen_records": self.seen,
                "emitted_records": self.emitted,
                "omitted_records": omitted,
                "bytes_before_footer": self.bytes,
                "coverage": self.coverage,
                "omission_counts": self.omission_counts,
                "aggregated_unchanged_snapshots": self.unchanged_snapshots,
            }),
            true,
        );
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        self.finished = true;
    }
}

struct RecordSink {
    bytes: Vec<u8>,
    oversized: bool,
}
impl Write for RecordSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > (MAX_RECORD_BYTES - 1).saturating_sub(self.bytes.len()) {
            self.oversized = true;
            return Err(io::Error::other("diagnostic record quota"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_overflow_marker(config: &Config, pid: u32) {
    let path = config.directory.join("kani3300-trace-overflow.jsonl");
    let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(path) else { return };
    let marker = json!({
        "schema": SCHEMA,
        "kind": "overflow",
        "trace_id": config.trace_id,
        "stage": config.stage,
        "invocation": pid.to_string(),
        "seq": 0,
        "data": {"state": "OVERSIZED", "omitted_invocations": "one-or-more", "reason": "run_slot_cap"},
    });
    if let Ok(mut bytes) = serde_json::to_vec(&marker) {
        bytes.push(b'\n');
        if bytes.len() <= MAX_RECORD_BYTES {
            let _ = file.write_all(&bytes);
            let _ = file.flush();
        }
    }
}

pub(crate) fn matches(name: &str) -> bool {
    config().is_some_and(|config| config.filters.iter().any(|filter| name.contains(filter)))
}

pub(crate) fn enabled() -> bool {
    trace().lock().ok().is_some_and(|guard| guard.is_some())
}

pub(crate) fn configured() -> bool {
    config().is_some()
}

pub(crate) fn event(kind: &str, data: Value) {
    if let Ok(mut guard) = trace().lock() {
        if let Some(trace) = guard.as_mut() {
            trace.write_record(kind, data, false);
        }
    }
}

pub(crate) fn context(root: &str, stage: &str) {
    let root = clip(root, 320);
    let stage = clip(stage, 64);
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        trace.context_root = root;
        trace.context_stage = stage;
    }
}

pub(crate) fn unit(unit: usize) {
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        if trace.context_unit != Some(unit) {
            trace.body_hashes.clear();
            trace.last_writers.clear();
        }
        trace.context_unit = Some(unit);
    }
}

pub(crate) fn cache_event(kind: &str, data: Value, selected: bool) {
    if selected || EXTERNAL_CACHE_WITNESSES.fetch_add(1, Ordering::Relaxed) < 16 {
        event(kind, data);
    } else {
        mark_omission("external_cache_witness_cap", 1, false);
    }
}

pub(crate) fn witness_event(kind: &str, data: Value, selected_function: bool) {
    if selected_function || EXTERNAL_WITNESSES.fetch_add(1, Ordering::Relaxed) < 16 {
        event(kind, data);
    } else {
        mark_omission("external_witness_cap", 1, false);
    }
}

pub(crate) fn mark_omission(category: &str, count: usize, oversized: bool) {
    if count == 0 {
        return;
    }
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        *trace.omission_counts.entry(category.to_owned()).or_default() += count;
        if oversized {
            trace.state = "OVERSIZED";
        } else if trace.state == "COMPLETE" {
            trace.state = "PARTIAL";
        }
    }
}

/// Fingerprint the complete dump stream without retaining MIR text. This is diagnostic data,
/// not a cryptographic identity or a second MIR query.
fn fingerprint(name: &str, body: &rustc_public::mir::Body) -> Value {
    struct Sink {
        hasher: DefaultHasher,
        bytes: usize,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.hasher.write(bytes);
            self.bytes = self.bytes.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink { hasher: DefaultHasher::new(), bytes: 0 };
    let dump_ok = body.dump(&mut sink, name).is_ok();
    json!({
        "body_hash": format!("{:016x}", sink.hasher.finish()),
        "body_hash_algorithm": "std-default-hasher-64",
        "dump_bytes": sink.bytes,
        "dump_ok": dump_ok,
    })
}

pub(crate) fn body_snapshot(name: &str, stage: &str, body: &rustc_public::mir::Body) {
    if !matches(name) {
        return;
    }
    let mut data = fingerprint(name, body);
    data["instance"] = json!(clip(name, 320));
    data["stage"] = json!(stage);
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        let hash = data["body_hash"].as_str().unwrap_or_default().to_owned();
        if data["dump_ok"] == true && trace.body_hashes.get(name) == Some(&hash) {
            trace.unchanged_snapshots += 1;
        } else {
            if data["dump_ok"] == true {
                trace.remember_body_hash(name, hash);
            }
            trace.write_record("mir_snapshot", data, false);
        }
    }
}

/// Record a selected writer and keep its context for the actual GOTO consumer.
pub(crate) fn body_writer(name: &str, symbol: &str, writer: &str, body: &rustc_public::mir::Body) {
    if !matches(name) {
        return;
    }
    let mut data = fingerprint(name, body);
    data["instance"] = json!(clip(name, 320));
    data["mangled_symbol"] = json!(clip(symbol, 320));
    data["writer"] = json!(writer);
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        data["writer_context"] = json!({
            "root": trace.context_root, "stage": trace.context_stage, "unit": trace.context_unit,
        });
        if symbol.len() <= MAX_STATE_KEY_BYTES
            && (trace.last_writers.len() < MAX_STATE_ENTRIES
                || trace.last_writers.contains_key(symbol))
        {
            trace.last_writers.insert(
                symbol.to_owned(),
                json!({
                    "writer": data["writer"], "body_hash": data["body_hash"],
                    "dump_ok": data["dump_ok"], "context": data["writer_context"],
                }),
            );
        } else {
            trace.state_omission("writer_state_cap");
        }
        if data["dump_ok"] == true {
            trace.remember_body_hash(
                name,
                data["body_hash"].as_str().unwrap_or_default().to_owned(),
            );
        }
        trace.write_record("body_cache_writer", data, false);
    }
}

/// Observe the very body passed to GOTO block emission; analysis lookups cannot emit this event.
pub(crate) fn body_consumed(name: &str, symbol: &str, body: &rustc_public::mir::Body) {
    if !matches(name) {
        return;
    }
    let mut data = fingerprint(name, body);
    data["instance"] = json!(clip(name, 320));
    data["mangled_symbol"] = json!(clip(symbol, 320));
    data["phase"] = json!("before_goto_blocks");
    if let Ok(mut guard) = trace().lock()
        && let Some(trace) = guard.as_mut()
    {
        data["last_writer"] = trace.last_writers.get(symbol).cloned().unwrap_or(Value::Null);
        trace.write_record("goto_body_consumed", data, false);
    }
}

pub(crate) fn clip(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    mark_omission("clipped_text_bytes", value.len() - end, false);
    value[..end].to_owned()
}

/// Bound Debug formatting before allocating its potentially large masks or projections.
pub(crate) fn debug(value: &impl std::fmt::Debug) -> String {
    struct Sink(String);
    impl std::fmt::Write for Sink {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let remaining = 320usize.saturating_sub(self.0.len());
            let mut end = remaining.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            if end < text.len() { Err(std::fmt::Error) } else { Ok(()) }
        }
    }
    let mut sink = Sink(String::with_capacity(320));
    if std::fmt::write(&mut sink, format_args!("{value:?}")).is_err() {
        mark_omission("truncated_debug_fields", 1, false);
    }
    sink.0
}

pub(crate) fn finish() {
    if let Ok(mut guard) = trace().lock() {
        if let Some(trace) = guard.as_mut() {
            trace.finish();
        }
    }
}
