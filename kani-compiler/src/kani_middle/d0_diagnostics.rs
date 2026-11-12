// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Default-off observations for the KANI3300 D0 experiment. Never queries/changes MIR.
//! MIR snapshots serialize existing indices without expanding Ty::Debug/type queries.
//! Payloads are compiler data, not runtime identities or evidence of execution.

use crate::kani_middle::readable_name;
use rustc_public::mir::mono::Instance;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub const A: &str = "array_value_as_used_by_merge_output";
pub const B: &str = "partial_copy_preserves_written_byte";
const MAX_RECORDS: u64 = 20000;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct Observer {
    root: String,
    phase: String,
    sequence: u64,
    bytes: usize,
    emitted: BTreeMap<String, u64>,
    dropped: BTreeMap<String, u64>,
    filtered: BTreeMap<String, u64>,
    versions: BTreeMap<String, (u64, String, String)>,
}

thread_local! {
    static OBSERVER: RefCell<Observer> = RefCell::new(Observer::default());
}

// rustc_public implements the sysroot serde_core trait. Cargo's trait is a
// different crate identity even when its API/version happens to match.
#[cfg(feature = "cprover")]
pub fn encoded(value: &impl rustc_serde_core::Serialize) -> String {
    rustc_serde_json::to_string(value).expect("D0 serialization")
}

#[cfg(not(feature = "cprover"))]
pub fn encoded<T: ?Sized>(_value: &T) -> String {
    unreachable!("D0 diagnostics require the CProver backend")
}

pub fn enabled() -> bool {
    cfg!(feature = "cprover") && std::env::var_os("KANI_D0_DIR").is_some()
}

pub fn case() -> String {
    std::env::var("KANI_D0_CASE").expect("D0 requires KANI_D0_CASE")
}

pub fn context(root: &str, phase: &str) {
    if enabled() {
        OBSERVER.with(|state| {
            let mut state = state.borrow_mut();
            state.root = root.into();
            state.phase = phase.into();
        });
    }
}

fn relevant(instance: Instance) -> bool {
    let name = instance.name();
    readable_name(instance) == A
        || readable_name(instance) == B
        || name.contains("::array::")
        || name.contains("SpecArrayEq")
        || name.contains("spec_eq")
        || name.contains("MaybeUninit")
        || name.contains("::mem_init::")
        || name.contains("::ptr::")
        || name.contains("::intrinsics::")
}

/// A noncryptographic structural fingerprint; CI also SHA256-hashes each exact sidecar.
/// Numeric compiler IDs are process-local. Compare normalized MIR as well across processes.
fn fingerprint(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    });
    format!("fnv1a64:{hash:016x}")
}

pub fn event(stage: &str, instance: Option<Instance>, payload: impl FnOnce() -> String) {
    let _ = record(stage, instance, payload);
}

pub fn record(
    stage: &str,
    instance: Option<Instance>,
    payload: impl FnOnce() -> String,
) -> Option<u64> {
    if !enabled() {
        return None;
    }
    if instance.is_some_and(|instance| !relevant(instance)) {
        OBSERVER.with(|state| {
            *state.borrow_mut().filtered.entry(stage.into()).or_default() += 1;
        });
        return None;
    }
    let payload = payload();
    OBSERVER.with(|state| {
        let mut state = state.borrow_mut();
        state.sequence += 1;
        let sequence = state.sequence;
        if sequence > MAX_RECORDS || payload.len() > MAX_PAYLOAD {
            *state.dropped.entry(stage.into()).or_default() += 1;
            return None;
        }
        let symbol = instance.map(|instance| instance.mangled_name());
        let body_hash = fingerprint(payload.as_bytes());
        if stage == "cache-write-local" || stage == "cache-write-delayed" {
            let key = symbol.clone().unwrap();
            let version = state.versions.get(&key).map_or(1, |previous| previous.0 + 1);
            let root = state.root.clone();
            state.versions.insert(key, (version, root, body_hash.clone()));
        }
        let writer = symbol.as_ref().and_then(|symbol| state.versions.get(symbol));
        let record = serde_json::json!({
            "schema": "kani3300-d0/v1", "pid": std::process::id(),
            "case": case(), "unit": 0, "cache": 0,
            "root": state.root, "phase": state.phase,
            "sequence": sequence, "stage": stage,
            "instance": instance.map(|instance| instance.name()), "symbol": symbol,
            "payload_fingerprint": body_hash, "cache_writer": writer,
            "payload_encoding": "text-with-serde-mir-and-goto-debug", "payload": payload,
            "runtime_binding": "NOT_RUN"
        });
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        if state.bytes + bytes.len() > MAX_BYTES {
            *state.dropped.entry(stage.into()).or_default() += 1;
            return None;
        }
        let directory = PathBuf::from(std::env::var_os("KANI_D0_DIR").unwrap());
        std::fs::create_dir_all(&directory).expect("D0 sidecar directory");
        let path = directory.join(format!("{}-{sequence:06}-{stage}.json", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("D0 sidecar must not overwrite another observation");
        file.write_all(&bytes).expect("D0 sidecar write");
        state.bytes += bytes.len();
        *state.emitted.entry(stage.into()).or_default() += 1;
        Some(sequence)
    })
}

pub fn finish() {
    if enabled() {
        let counts = OBSERVER.with(|state| {
            let state = state.borrow();
            serde_json::json!({"emitted": state.emitted, "dropped": state.dropped,
                "filtered": state.filtered, "bytes": state.bytes, "attempted": state.sequence,
                "filter": "roots,array,MaybeUninit,mem_init,ptr,intrinsics",
                "missing_or_capped": "UNKNOWN"})
        });
        // Coverage must survive an exhausted event budget.
        let directory = PathBuf::from(std::env::var_os("KANI_D0_DIR").unwrap());
        let path = directory.join(format!("{}-coverage.json", std::process::id()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "kani3300-d0/v1", "case": case(), "pid": std::process::id(),
            "codegen_completed": true, "counts": counts,
            "required_phase_coverage": "CI_MUST_VALIDATE"
        }))
        .unwrap();
        file.write_all(&bytes).unwrap();
    }
}

// These field-only implementations deliberately avoid Debug, type expansion,
// body reconstruction and compiler queries. Do not use Cargo's derive macro:
// its generated private paths are tied to Cargo's serde version as well.
#[cfg(feature = "cprover")]
macro_rules! serialize_struct {
    ($ty:ident { $($field:ident),+ $(,)? }) => {
        impl rustc_serde_core::Serialize for $ty {
            fn serialize<S: rustc_serde_core::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                use rustc_serde_core::ser::SerializeStruct;
                let mut state = serializer.serialize_struct(
                    stringify!($ty), [$(stringify!($field)),+].len(),
                )?;
                $(state.serialize_field(stringify!($field), &self.$field)?;)+
                state.end()
            }
        }
    };
}

#[cfg(feature = "cprover")]
macro_rules! serialize_enum {
    ($ty:ident { $($index:literal => $variant:ident $( { $($field:ident),+ } )?),+ $(,)? }) => {
        impl rustc_serde_core::Serialize for $ty {
            fn serialize<S: rustc_serde_core::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                match self {
                    $(Self::$variant $( { $($field),+ } )? => {
                        $crate::kani_middle::d0_diagnostics::serialize_enum!(
                            @variant serializer, $ty, $index, $variant $( { $($field),+ } )?
                        )
                    }),+
                }
            }
        }
    };
    (@variant $serializer:ident, $ty:ident, $index:literal, $variant:ident) => {
        $serializer.serialize_unit_variant(stringify!($ty), $index, stringify!($variant))
    };
    (@variant $serializer:ident, $ty:ident, $index:literal, $variant:ident { $($field:ident),+ }) => {{
        use rustc_serde_core::ser::SerializeStructVariant;
        let mut state = $serializer.serialize_struct_variant(
            stringify!($ty), $index, stringify!($variant), [$(stringify!($field)),+].len(),
        )?;
        $(state.serialize_field(stringify!($field), $field)?;)+
        state.end()
    }};
}

#[cfg(feature = "cprover")]
pub(crate) use {serialize_enum, serialize_struct};
