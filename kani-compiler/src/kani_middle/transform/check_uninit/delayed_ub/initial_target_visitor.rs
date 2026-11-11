// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! This module contains the visitor responsible for collecting initial analysis targets for delayed
//! UB instrumentation.

use crate::{
    intrinsics::Intrinsic,
    kani_middle::transform::check_uninit::ty_layout::tys_layout_equal_to_size,
};
use rustc_public::{
    mir::{
        Body, CastKind, LocalDecl, MirVisitor, NonDivergingIntrinsic, Operand, Place, Rvalue,
        Statement, StatementKind, Terminator, TerminatorKind,
        alloc::GlobalAlloc,
        mono::{Instance, InstanceKind, StaticDef},
        visit::Location,
    },
    ty::{ConstantKind, RigidTy, TyKind},
};

/// Pointer, write through which might trigger delayed UB.
pub enum AnalysisTarget {
    Place(Place),
    Static(StaticDef),
}

/// Visitor that finds initial analysis targets for delayed UB instrumentation. For our purposes,
/// analysis targets are *pointers* to places reading and writing from which should be tracked.
pub struct InitialTargetVisitor {
    body: Body,
    instance: Instance,
    targets: Vec<AnalysisTarget>,
}

impl InitialTargetVisitor {
    pub fn new(body: Body, instance: Instance) -> Self {
        Self { body, instance, targets: vec![] }
    }

    pub fn into_targets(self) -> Vec<AnalysisTarget> {
        self.targets
    }

    pub fn push_operand(&mut self, operand: &Operand, location: Location, reason: &str) {
        let instance_name = if crate::kani_middle::trace::enabled() {
            Some(crate::kani_middle::trace::clip(self.instance.name().as_str(), 320))
        } else {
            None
        };
        let selected = instance_name.as_deref().is_some_and(crate::kani_middle::trace::matches);
        match operand {
            Operand::Copy(place) | Operand::Move(place) => {
                if instance_name.is_some() {
                    crate::kani_middle::trace::witness_event(
                        "target_origin",
                        serde_json::json!({
                            "instance": instance_name.as_deref().unwrap_or_default(),
                            "location": crate::kani_middle::trace::debug(&location),
                            "reason": reason,
                            "target": crate::kani_middle::trace::debug(place),
                        }),
                        selected,
                    );
                }
                self.targets.push(AnalysisTarget::Place(place.clone()));
            }
            Operand::Constant(constant) => {
                // Extract the static from the constant.
                if let ConstantKind::Allocated(allocation) = constant.const_.kind() {
                    for (_, prov) in &allocation.provenance.ptrs {
                        if let GlobalAlloc::Static(static_def) = GlobalAlloc::from(prov.0) {
                            if instance_name.is_some() {
                                crate::kani_middle::trace::witness_event(
                                    "target_origin",
                                    serde_json::json!({
                                        "instance": instance_name.as_deref().unwrap_or_default(),
                                        "location": crate::kani_middle::trace::debug(&location),
                                        "reason": reason,
                                        "target": crate::kani_middle::trace::debug(&static_def),
                                    }),
                                    selected,
                                );
                            }
                            self.targets.push(AnalysisTarget::Static(static_def));
                        };
                    }
                }
            }
            // Runtime-check operands (rust-lang/rust#148766) carry no place or static.
            Operand::RuntimeChecks(_) => {}
        }
    }
}

/// We implement MirVisitor to facilitate target finding, we look for:
/// - pointer casts where pointees have different padding;
/// - calls to `copy`-like intrinsics.
impl MirVisitor for InitialTargetVisitor {
    fn visit_rvalue(&mut self, rvalue: &Rvalue, location: Location) {
        if let Rvalue::Cast(kind, operand, ty) = rvalue {
            let operand_ty = operand.ty(self.body.locals()).unwrap();
            match kind {
                CastKind::Transmute | CastKind::PtrToPtr => {
                    let operand_ty_kind = operand_ty.kind();
                    let from_ty = match operand_ty_kind.rigid().unwrap() {
                        RigidTy::RawPtr(ty, _) | RigidTy::Ref(_, ty, _) => Some(ty),
                        _ => None,
                    };
                    let ty_kind = ty.kind();
                    let to_ty = match ty_kind.rigid().unwrap() {
                        RigidTy::RawPtr(ty, _) | RigidTy::Ref(_, ty, _) => Some(ty),
                        _ => None,
                    };
                    if let (Some(from_ty), Some(to_ty)) = (from_ty, to_ty)
                        && !tys_layout_equal_to_size(from_ty, to_ty)
                    {
                        self.push_operand(
                            operand,
                            location,
                            match kind {
                                CastKind::Transmute => "transmute_pointer_layout_mismatch",
                                CastKind::PtrToPtr => "ptr_to_ptr_layout_mismatch",
                                _ => "pointer_cast_layout_mismatch",
                            },
                        );
                    }
                }
                _ => {}
            };
        }
        self.super_rvalue(rvalue, location);
    }

    fn visit_statement(&mut self, stmt: &Statement, location: Location) {
        if let StatementKind::Intrinsic(NonDivergingIntrinsic::CopyNonOverlapping(copy)) =
            &stmt.kind
        {
            self.push_operand(&copy.dst, location, "copy_non_overlapping_destination");
        }
        self.super_statement(stmt, location);
    }

    fn visit_terminator(&mut self, term: &Terminator, location: Location) {
        // Only calls to the copy intrinsics write to a target here. A call through a function
        // pointer or a vtable cannot be one (intrinsics cannot be coerced to function pointers),
        // and whatever its callee writes is collected when visiting the callee's own body.
        if let TerminatorKind::Call { func, args, .. } = &term.kind
            && let Some(instance) = try_resolve_instance(self.body.locals(), func)
            && instance.kind == InstanceKind::Intrinsic
        {
            match Intrinsic::from_instance(&instance) {
                Intrinsic::Copy => {
                    // Here, `dst` is the second argument.
                    self.push_operand(&args[1], location, "copy_intrinsic_destination");
                }
                Intrinsic::VolatileCopyMemory | Intrinsic::VolatileCopyNonOverlappingMemory => {
                    // Here, `dst` is the first argument.
                    self.push_operand(&args[0], location, "volatile_copy_intrinsic_destination");
                }
                _ => {}
            }
        }
        self.super_terminator(term, location);
    }
}

/// The instance a call operand refers to, if it is a function item rather than a function pointer.
fn try_resolve_instance(locals: &[LocalDecl], func: &Operand) -> Option<Instance> {
    match func.ty(locals).unwrap().kind() {
        TyKind::RigidTy(RigidTy::FnDef(def, args)) => Some(Instance::resolve(def, &args).unwrap()),
        _ => None,
    }
}
