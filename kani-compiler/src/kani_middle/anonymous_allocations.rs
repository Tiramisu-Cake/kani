// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Source identities for anonymous data. These are compiler-local keys, never CBMC object IDs.
//! The graph uses whole objects for relevance; byte ranges remain in the original MIR and in
//! the runtime pointer expressions. In particular, an alias edge is not an exact byte offset.

use rustc_middle::ty::{TyCtxt, TypingEnv};
use rustc_public::CrateDef;
use rustc_public::mir::Mutability;
use rustc_public::mir::alloc::{AllocId, GlobalAlloc};
use rustc_public::rustc_internal;
use rustc_public::target::{Endian, MachineInfo};
use rustc_public::ty::{Allocation, ConstantKind, MirConst, RigidTy, Ty, TyKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousOrigin {
    pub key: AllocId,
    pub allocation: Allocation,
    /// Captured before backend byte emission can replace None with physical zero bytes.
    pub mask: Vec<bool>,
    /// Offset of the pointer slot in the *carrier*, not in the referent.
    pub carrier_slot: usize,
    pub referent_offset: Option<u128>,
    pub extent: Option<usize>,
    /// A whole referent typed origin, retained independently of subsequent pointer erasure.
    pub frozen_origin: Option<Ty>,
}

/// Keep every anonymous provenance alternative, including unqualified ones. Qualification never
/// filters the relevance graph. Carrier relocations do not become referent-mask bits.
pub fn anonymous_origins(tcx: TyCtxt<'_>, constant: &MirConst) -> Vec<AnonymousOrigin> {
    let ConstantKind::Allocated(carrier) = constant.kind() else { return vec![] };
    let pointer_size = MachineInfo::target_pointer_width().bytes();
    carrier
        .provenance
        .ptrs
        .iter()
        .filter_map(|&(slot, prov)| {
            let allocation = match GlobalAlloc::from(prov.0) {
                GlobalAlloc::Memory(allocation) => allocation,
                GlobalAlloc::Static(def)
                    if crate::kani_middle::is_anon_static(tcx, def.def_id()) =>
                {
                    def.eval_initializer().ok()?
                }
                _ => return None,
            };
            let offset = slot
                .checked_add(pointer_size)
                .filter(|&end| end <= carrier.bytes.len())
                .and_then(|end| carrier.read_partial_uint(slot..end).ok());
            let pointee = match constant.ty().kind() {
                TyKind::RigidTy(RigidTy::Ref(_, ty, Mutability::Not))
                    if slot == 0
                        && carrier.provenance.ptrs.len() == 1
                        && constant.ty().layout().ok().is_some_and(|layout| {
                            layout.shape().is_sized()
                                && layout.shape().size.bytes() == carrier.bytes.len()
                        }) =>
                {
                    Some(ty)
                }
                _ => None,
            };
            let extent = pointee.and_then(|ty| referent_extent(carrier, ty, pointer_size));
            let frozen_origin = pointee.filter(|&ty| {
                let internal = rustc_internal::internal(tcx, ty);
                crate::kani_middle::transform::immutable_origin_type_supported(tcx, ty)
                    && offset == Some(0)
                    && extent == Some(allocation.bytes.len())
                    && internal.is_freeze(tcx, TypingEnv::fully_monomorphized())
            });
            Some(AnonymousOrigin {
                key: prov.0,
                mask: allocation.bytes.iter().map(Option::is_some).collect(),
                allocation,
                carrier_slot: slot,
                referent_offset: offset,
                extent,
                frozen_origin,
            })
        })
        .collect()
}

fn referent_extent(carrier: &Allocation, ty: Ty, pointer_size: usize) -> Option<usize> {
    match ty.kind() {
        TyKind::RigidTy(RigidTy::Slice(element)) => {
            let end = pointer_size.checked_mul(2)?;
            let count: usize =
                carrier.read_partial_uint(pointer_size..end).ok()?.try_into().ok()?;
            let size = element.layout().ok()?.shape().size.bytes();
            count.checked_mul(size)
        }
        TyKind::RigidTy(RigidTy::Str) => carrier
            .read_partial_uint(pointer_size..pointer_size.checked_mul(2)?)
            .ok()?
            .try_into()
            .ok(),
        _ => {
            let layout = ty.layout().ok()?;
            layout.shape().is_sized().then(|| layout.shape().size.bytes())
        }
    }
}

/// The backend and rustc_public must interpret pointer carrier bytes on the same target.
pub fn target_matches(pointer_width: u64, big_endian: bool) -> bool {
    pointer_width as usize == MachineInfo::target_pointer_width().bits()
        && big_endian == (MachineInfo::target_endianness() == Endian::Big)
}
