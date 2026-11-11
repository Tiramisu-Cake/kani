// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Visitor that collects all instructions relevant to uninitialized memory access.

use crate::{
    intrinsics::Intrinsic,
    kani_middle::nonnull_pointee,
    kani_middle::transform::{
        body::{InsertPosition, MutableBody, SourceInstruction},
        check_uninit::{
            PointeeInfo, PointeeLayout, TargetFinder,
            relevant_instruction::{InitRelevantInstruction, MemoryInitOp, constant_init_mask},
            ty_layout::{
                LayoutComputationError, maybe_uninit_storage, tys_layout_compatible_to_size,
                wrapper_inner,
            },
        },
    },
};
use rustc_attr_ir::lang_items::LangItem;
use rustc_middle::ty::TyCtxt;
use rustc_public::CrateDefType;
use rustc_public::{
    mir::{
        AggregateKind, CastKind, LocalDecl, MirVisitor, NonDivergingIntrinsic, Operand, Place,
        PointerCoercion, ProjectionElem, Rvalue, Statement, StatementKind, Terminator,
        TerminatorKind,
        alloc::GlobalAlloc,
        mono::{Instance, InstanceKind},
        visit::{Location, PlaceContext},
    },
    ty::{AdtKind, ConstantKind, RigidTy, Ty, TyKind, UintTy},
};

pub struct CheckUninitVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    locals: Vec<LocalDecl>,
    /// All target instructions in the body.
    targets: Vec<InitRelevantInstruction>,
    /// Current analysis target, eventually needs to be added to a list of all targets.
    current_target: InitRelevantInstruction,
}

impl TargetFinder for CheckUninitVisitor<'_> {
    fn find_all(mut self, body: &MutableBody) -> Vec<InitRelevantInstruction> {
        self.locals = body.locals().to_vec();
        for (bb_idx, bb) in body.blocks().iter().enumerate() {
            // Set the first target to start iterating from.
            self.current_target = if !bb.statements.is_empty() {
                InitRelevantInstruction {
                    source: SourceInstruction::Statement { idx: 0, bb: bb_idx },
                    before_instruction: vec![],
                    after_instruction: vec![],
                }
            } else {
                InitRelevantInstruction {
                    source: SourceInstruction::Terminator { bb: bb_idx },
                    before_instruction: vec![],
                    after_instruction: vec![],
                }
            };
            if bb_idx == 0 {
                let union_args: Vec<_> = body
                    .locals()
                    .iter()
                    .enumerate()
                    .skip(1)
                    .take(body.arg_count())
                    .filter(|(_, local)| self.transfers_shadow(local.ty))
                    .collect();
                if !union_args.is_empty() {
                    for (idx, _) in union_args {
                        self.push_target(MemoryInitOp::LoadArgument {
                            operand: Operand::Copy(Place { local: idx, projection: vec![] }),
                            argument_no: idx,
                            position: InsertPosition::Before,
                        })
                    }
                }
            }
            self.visit_basic_block(bb);
        }
        self.targets
    }
}

impl<'tcx> CheckUninitVisitor<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self {
            tcx,
            locals: vec![],
            targets: vec![],
            current_target: InitRelevantInstruction {
                source: SourceInstruction::Statement { idx: 0, bb: 0 },
                before_instruction: vec![],
                after_instruction: vec![],
            },
        }
    }

    fn push_target(&mut self, source_op: MemoryInitOp) {
        self.current_target.push_operation(source_op);
    }

    fn transfers_shadow(&self, ty: Ty) -> bool {
        ty.kind().is_union() || maybe_uninit_storage(self.tcx, ty).is_some()
    }

    /// Locate the first union on the projection path, including a union at the end.
    fn enclosing_union(&self, place: &Place) -> Option<Ty> {
        let mut prefix = Place::from(place.local);
        for projection in &place.projection {
            let ty = prefix.ty(&self.locals).unwrap();
            if ty.kind().is_union() {
                return Some(ty);
            }
            prefix.projection.push(projection.clone());
        }
        let ty = prefix.ty(&self.locals).unwrap();
        ty.kind().is_union().then_some(ty)
    }

    fn assign_storage_operand(&mut self, place: &Place, operand: &Operand) {
        if let Some(initialized) = constant_init_mask(operand) {
            self.push_target(MemoryInitOp::SetStorage {
                operand: Operand::Copy(place.clone()),
                initialized,
                position: InsertPosition::After,
            });
        } else if matches!(operand, Operand::Copy(_) | Operand::Move(_)) {
            // Capture the source and destination addresses before the assignment can overwrite
            // any part of either place.
            self.push_target(MemoryInitOp::AssignUnion {
                lvalue: place.clone(),
                rvalue: operand.clone(),
                position: InsertPosition::Before,
            });
        } else {
            self.unsupported_storage_assignment();
        }
    }

    fn unsupported_storage_assignment(&mut self) {
        self.push_target(MemoryInitOp::Unsupported {
            reason: "Kani does not support this assignment to MaybeUninit storage.".to_string(),
        });
    }

    fn assign_storage(&mut self, place: &Place, ty: Ty, rvalue: &Rvalue) {
        match rvalue {
            Rvalue::Cast(CastKind::Transmute, operand, target)
                if let Some(initialized) = self.typed_storage_mask(operand, *target) =>
            {
                // visit_rvalue preserves the typed source checks. A typed move
                // can discard padding, so only T's data bytes are initialized in the slot.
                // This is the sole destination update: do not run the generic union setter.
                self.push_target(MemoryInitOp::SetStorage {
                    operand: Operand::Copy(place.clone()),
                    initialized,
                    position: InsertPosition::After,
                });
            }
            Rvalue::Use(operand, _) => self.assign_storage_operand(place, operand),
            Rvalue::Aggregate(AggregateKind::Adt(def, _, _, _, Some(field)), _)
                if def.kind() == AdtKind::Union =>
            {
                self.push_target(MemoryInitOp::CreateUnion {
                    operand: Operand::Copy(place.clone()),
                    field: *field,
                });
            }
            Rvalue::Aggregate(AggregateKind::Array(_), operands)
                if place.projection.is_empty()
                    && operands.iter().all(|operand| match operand {
                        Operand::Copy(src) | Operand::Move(src) => {
                            src.local != place.local && src.projection.is_empty()
                        }
                        _ => constant_init_mask(operand).is_some(),
                    }) =>
            {
                let len = operands.len().try_into().unwrap();
                for (index, operand) in operands.iter().enumerate() {
                    let mut element = place.clone();
                    element.projection.push(ProjectionElem::ConstantIndex {
                        offset: index.try_into().unwrap(),
                        min_length: len,
                        from_end: false,
                    });
                    self.assign_storage_operand(&element, operand);
                }
            }
            Rvalue::Repeat(operand, _) => {
                if let Some(mask) = constant_init_mask(operand) {
                    let TyKind::RigidTy(RigidTy::Array(_, len)) = ty.kind() else { unreachable!() };
                    self.push_target(MemoryInitOp::SetStorage {
                        operand: Operand::Copy(place.clone()),
                        initialized: mask
                            .repeat(len.eval_target_usize().unwrap().try_into().unwrap()),
                        position: InsertPosition::After,
                    });
                } else if place.projection.is_empty()
                    && let Operand::Copy(source) | Operand::Move(source) = operand
                    && source.projection.is_empty()
                    && source.local != place.local
                {
                    // MIR may hold a const constructor result in a local before repeating it.
                    // Copy its byte state to each slot using the array's static element stride.
                    let TyKind::RigidTy(RigidTy::Array(_, len)) = ty.kind() else { unreachable!() };
                    let len = len.eval_target_usize().unwrap();
                    for index in 0..len {
                        let mut element = place.clone();
                        element.projection.push(ProjectionElem::ConstantIndex {
                            offset: index,
                            min_length: len,
                            from_end: false,
                        });
                        self.assign_storage_operand(&element, operand);
                    }
                } else {
                    self.unsupported_storage_assignment();
                }
            }
            _ => self.unsupported_storage_assignment(),
        }
    }

    /// Match only T -> MaybeUninit<T> or [T; N] -> [MaybeUninit<T>; N].
    /// Both the cast visitor and assignment handler use this exact predicate and mask.
    fn typed_storage_mask(&self, operand: &Operand, target: Ty) -> Option<Vec<bool>> {
        let source = operand.ty(&self.locals).ok()?;
        let matches = wrapper_inner(self.tcx, target, LangItem::MaybeUninit) == Some(source)
            || match (source.kind(), target.kind()) {
                (
                    TyKind::RigidTy(RigidTy::Array(from, from_len)),
                    TyKind::RigidTy(RigidTy::Array(to, to_len)),
                ) => {
                    from_len == to_len
                        && wrapper_inner(self.tcx, to, LangItem::MaybeUninit) == Some(from)
                }
                _ => false,
            };
        if !matches || source.layout().ok()?.shape().size != target.layout().ok()?.shape().size {
            return None;
        }
        let info = PointeeInfo::from_ty(source).ok()?;
        let PointeeLayout::Sized { layout } = info.layout() else { return None };
        Some(layout.clone())
    }

    /// Match only the transparent conversion from MaybeUninit<T> to T or ManuallyDrop<T>.
    fn maybe_uninit_transmute(&mut self, operand: &Operand, target: Ty) -> bool {
        let operand_ty = operand.ty(&self.locals).unwrap();
        let Some(inner) = wrapper_inner(self.tcx, operand_ty, LangItem::MaybeUninit) else {
            return false;
        };
        if target != inner && wrapper_inner(self.tcx, target, LangItem::ManuallyDrop) != Some(inner)
        {
            return false;
        }
        let Ok(info) = PointeeInfo::from_ty(inner) else { return false };
        let PointeeLayout::Sized { layout } = info.layout() else { return false };
        if matches!(operand, Operand::Copy(_) | Operand::Move(_)) {
            self.push_target(MemoryInitOp::CheckRefAs {
                operand: operand.clone(),
                pointee_ty: inner,
            });
        } else if let Some(initialized) = constant_init_mask(operand)
            && initialized.len() == layout.len()
        {
            if layout
                .iter()
                .zip(initialized)
                .any(|(required, initialized)| *required && !initialized)
            {
                self.push_target(MemoryInitOp::TriviallyUnsafe {
                    reason: format!(
                        "Undefined Behavior: Reading from an uninitialized pointer of type `{inner}`"
                    ),
                });
            }
        } else {
            self.push_target(MemoryInitOp::Unsupported {
                reason:
                    "Kani cannot determine the initialization state of this MaybeUninit constant."
                        .to_string(),
            });
        }
        true
    }

    fn address_of_raw_deref(&self, place: &Place) -> bool {
        let mut prefix = Place::from(place.local);
        for projection in &place.projection {
            if *projection == ProjectionElem::Deref
                && prefix.ty(&self.locals).unwrap().kind().is_raw_ptr()
            {
                return true;
            }
            prefix.projection.push(projection.clone());
        }
        false
    }

    fn visit_ordinary_assignment(
        &mut self,
        place: &Place,
        rvalue: &Rvalue,
        ty: Ty,
        in_union: bool,
    ) {
        // Check whether we are assigning into a dereference (*ptr = _).
        if let Some(place_without_deref) = try_remove_topmost_deref(place) {
            // First, check that we are not dereferencing extra pointers along the way
            // (e.g., **ptr = _). If yes, check whether these pointers are initialized.
            let mut place_to_add_projections =
                Place { local: place_without_deref.local, projection: vec![] };
            for projection_elem in place_without_deref.projection.iter() {
                // If the projection is Deref and the current type is raw pointer, check
                // if it points to initialized memory.
                if *projection_elem == ProjectionElem::Deref
                    && let TyKind::RigidTy(RigidTy::RawPtr(..)) =
                        place_to_add_projections.ty(&self.locals).unwrap().kind()
                {
                    self.push_target(MemoryInitOp::Check {
                        operand: Operand::Copy(place_to_add_projections.clone()),
                    });
                };
                place_to_add_projections.projection.push(projection_elem.clone());
            }
            if place_without_deref.ty(&self.locals).unwrap().kind().is_raw_ptr() {
                self.push_target(MemoryInitOp::Set {
                    operand: Operand::Copy(place_without_deref),
                    value: true,
                    position: InsertPosition::After,
                });
            }
        }
        // Check whether Rvalue creates a new initialized pointer previously not captured inside shadow memory.
        if ty.kind().is_raw_ptr()
            && let Rvalue::AddressOf(_, addressed) = rvalue
            && !self.address_of_raw_deref(addressed)
            && !self.enclosing_union(addressed).is_some_and(|union| {
                wrapper_inner(self.tcx, union, LangItem::MaybeUninit).is_some()
            })
            && maybe_uninit_storage(self.tcx, addressed.ty(&self.locals).unwrap()).is_none()
        {
            self.push_target(MemoryInitOp::Set {
                operand: Operand::Copy(place.clone()),
                value: true,
                position: InsertPosition::After,
            });
        }

        // Need to copy some information about union initialization, since lvalue is
        // either a union or a field inside a union.
        if in_union {
            match rvalue {
                Rvalue::Use(operand, _) => {
                    // This is a union-to-union assignment, so we need to copy the
                    // initialization state.
                    if place.ty(&self.locals).unwrap().kind().is_union() {
                        self.push_target(MemoryInitOp::AssignUnion {
                            lvalue: place.clone(),
                            rvalue: operand.clone(),
                            position: InsertPosition::After,
                        });
                    } else {
                        // This is assignment to a field of a union.
                        self.push_target(MemoryInitOp::SetRef {
                            operand: Operand::Copy(place.clone()),
                            value: true,
                            position: InsertPosition::After,
                        });
                    }
                }
                Rvalue::Aggregate(AggregateKind::Adt(adt_def, _, _, _, union_field), _) => {
                    // Create a union from scratch as an aggregate. We handle it here because we
                    // need to know which field is getting assigned.
                    if adt_def.kind() == AdtKind::Union {
                        self.push_target(MemoryInitOp::CreateUnion {
                            operand: Operand::Copy(place.clone()),
                            field: union_field.unwrap(), // Safe to unwrap because we know this is a union.
                        });
                    }
                }
                // TODO: add support for Rvalue::Cast, etc.
                _ => self.push_target(MemoryInitOp::Unsupported {
                    reason:
                        "Performing a union assignment with a non-supported construct as an Rvalue"
                            .to_string(),
                }),
            }
        }
    }
}

impl MirVisitor for CheckUninitVisitor<'_> {
    fn visit_statement(&mut self, stmt: &Statement, location: Location) {
        // Leave it as an exhaustive match to be notified when a new kind is added.
        match &stmt.kind {
            StatementKind::Intrinsic(NonDivergingIntrinsic::CopyNonOverlapping(copy)) => {
                self.super_statement(stmt, location);
                // The copy is untyped, so we should copy memory initialization state from `src`
                // to `dst`.
                self.push_target(MemoryInitOp::Copy {
                    from: copy.src.clone(),
                    to: copy.dst.clone(),
                    count: copy.count.clone(),
                });
            }
            StatementKind::Assign(place, rvalue) => {
                // First check rvalue.
                self.visit_rvalue(rvalue, location);

                let ty = place.ty(&self.locals).unwrap();
                let union = self.enclosing_union(place);
                let in_maybe_uninit = union
                    .is_some_and(|ty| wrapper_inner(self.tcx, ty, LangItem::MaybeUninit).is_some());

                // Reject nested unions before the generic shadow update can treat them as values.
                if maybe_uninit_storage(self.tcx, ty).is_some() {
                    self.assign_storage(place, ty, rvalue);
                } else if let Err(reason @ LayoutComputationError::UnionAsField(_)) =
                    PointeeInfo::from_ty(ty)
                {
                    self.push_target(MemoryInitOp::Unsupported {
                        reason: format!(
                            "Checking memory initialization of type {ty} is not supported. {reason}"
                        ),
                    });
                } else if in_maybe_uninit {
                    self.push_target(MemoryInitOp::SetRef {
                        operand: Operand::Copy(place.clone()),
                        value: true,
                        position: InsertPosition::After,
                    });
                } else {
                    self.visit_ordinary_assignment(place, rvalue, ty, union.is_some());
                }
            }
            StatementKind::FakeRead(_, _)
            | StatementKind::SetDiscriminant { .. }
            | StatementKind::StorageLive(_)
            | StatementKind::StorageDead(_)
            | StatementKind::PlaceMention(_)
            | StatementKind::AscribeUserType { .. }
            | StatementKind::Coverage(_)
            | StatementKind::ConstEvalCounter
            | StatementKind::Intrinsic(NonDivergingIntrinsic::Assume(_))
            | StatementKind::Nop => self.super_statement(stmt, location),
        }
        // Switch to the next statement.
        if let SourceInstruction::Statement { idx, bb } = self.current_target.source {
            self.targets.push(self.current_target.clone());
            self.current_target = InitRelevantInstruction {
                source: SourceInstruction::Statement { idx: idx + 1, bb },
                after_instruction: vec![],
                before_instruction: vec![],
            };
        } else {
            unreachable!()
        }
    }

    fn visit_terminator(&mut self, term: &Terminator, location: Location) {
        if let SourceInstruction::Statement { bb, .. } = self.current_target.source {
            // We don't have to push the previous target, since it already happened in the statement
            // handling code.
            self.current_target = InitRelevantInstruction {
                source: SourceInstruction::Terminator { bb },
                after_instruction: vec![],
                before_instruction: vec![],
            };
        } else {
            // The only instruction in this basic block is the terminator, which was already set.
        }
        // Leave it as an exhaustive match to be notified when a new kind is added.
        match &term.kind {
            TerminatorKind::Call { func, args, destination, .. } => {
                self.super_terminator(term, location);
                let instance = match try_resolve_instance(&self.locals, func) {
                    Ok(instance) => instance,
                    Err(reason) => {
                        self.super_terminator(term, location);
                        self.push_target(MemoryInitOp::Unsupported { reason });
                        return;
                    }
                };
                // Forget consumes its argument without reading or returning any bytes; it
                // already has an explicit no-effect model below. Other bodyless transfers
                // need an actual shadow model, not an unpaired argument-buffer store.
                let modeled_consumption = instance.kind == InstanceKind::Intrinsic
                    && matches!(Intrinsic::from_instance(&instance), Intrinsic::Forget);
                if !instance.has_body()
                    && !modeled_consumption
                    && args.iter().any(|arg| self.transfers_shadow(arg.ty(&self.locals).unwrap()))
                {
                    self.push_target(MemoryInitOp::Unsupported {
                        reason: "Kani does not support shadow-carrying arguments to calls without a MIR body."
                            .to_string(),
                    });
                    // In particular, do not leave an unconsumed store for the next call.
                    self.targets.push(self.current_target.clone());
                    return;
                }
                let destination_ty = destination.ty(&self.locals).unwrap();
                if maybe_uninit_storage(self.tcx, destination_ty).is_some() {
                    if instance.kind == InstanceKind::Item && instance.has_body() {
                        self.push_target(MemoryInitOp::LoadArgument {
                            operand: Operand::Copy(destination.clone()),
                            argument_no: 0,
                            position: InsertPosition::After,
                        });
                    } else {
                        self.push_target(MemoryInitOp::Unsupported {
                            reason: "Kani does not support MaybeUninit return values from calls without a MIR body."
                                .to_string(),
                        });
                    }
                }
                match instance.kind {
                    InstanceKind::Intrinsic => {
                        match Intrinsic::from_instance(&instance) {
                            intrinsic_name if can_skip_intrinsic(intrinsic_name.clone()) => {
                                /* Intrinsics that can be safely skipped */
                            }
                            Intrinsic::AtomicAnd
                            | Intrinsic::AtomicCxchg
                            | Intrinsic::AtomicCxchgWeak
                            | Intrinsic::AtomicLoad
                            | Intrinsic::AtomicMax
                            | Intrinsic::AtomicMin
                            | Intrinsic::AtomicNand
                            | Intrinsic::AtomicOr
                            | Intrinsic::AtomicStore
                            | Intrinsic::AtomicUmax
                            | Intrinsic::AtomicUmin
                            | Intrinsic::AtomicXadd
                            | Intrinsic::AtomicXchg
                            | Intrinsic::AtomicXor
                            | Intrinsic::AtomicXsub => {
                                self.push_target(MemoryInitOp::Check { operand: args[0].clone() });
                            }
                            Intrinsic::RawEq => {
                                for operand in args {
                                    let TyKind::RigidTy(RigidTy::Ref(_, pointee_ty, _)) =
                                        operand.ty(&self.locals).unwrap().kind()
                                    else {
                                        unreachable!("raw_eq operands must be references")
                                    };
                                    // raw_eq reads the whole extent, including padding and union
                                    // storage. A byte array selects every byte without imposing
                                    // the pointee's typed data mask or reading its value.
                                    let bytes_ty = pointee_ty.layout().ok().and_then(|layout| {
                                        Ty::try_new_array(
                                            Ty::unsigned_ty(UintTy::U8),
                                            layout.shape().size.bytes().try_into().unwrap(),
                                        )
                                        .ok()
                                    });
                                    if let Some(pointee_ty) = bytes_ty {
                                        self.push_target(MemoryInitOp::CheckAs {
                                            operand: operand.clone(),
                                            pointee_ty,
                                        });
                                    } else {
                                        self.push_target(MemoryInitOp::Unsupported {
                                            reason: format!(
                                                "Kani cannot determine the pointee layout for raw_eq of `{pointee_ty}`."
                                            ),
                                        });
                                    }
                                }
                            }
                            Intrinsic::CompareBytes => {
                                self.push_target(MemoryInitOp::CheckSliceChunk {
                                    operand: args[0].clone(),
                                    count: args[2].clone(),
                                });
                                self.push_target(MemoryInitOp::CheckSliceChunk {
                                    operand: args[1].clone(),
                                    count: args[2].clone(),
                                });
                            }
                            Intrinsic::Copy => {
                                // The copy is untyped, so we should copy memory
                                // initialization state from `src` to `dst`.
                                self.push_target(MemoryInitOp::Copy {
                                    from: args[0].clone(),
                                    to: args[1].clone(),
                                    count: args[2].clone(),
                                });
                            }
                            Intrinsic::VolatileCopyMemory
                            | Intrinsic::VolatileCopyNonOverlappingMemory => {
                                // The copy is untyped, so we should copy initialization state
                                // from `src` to `dst`. Note that the `dst` comes before `src`
                                // in this case.
                                self.push_target(MemoryInitOp::Copy {
                                    from: args[1].clone(),
                                    to: args[0].clone(),
                                    count: args[2].clone(),
                                });
                            }
                            Intrinsic::TypedSwap
                                if let TyKind::RigidTy(RigidTy::RawPtr(ty, _)) =
                                    args[0].ty(&self.locals).unwrap().kind()
                                    && maybe_uninit_storage(self.tcx, ty).is_some() =>
                            {
                                self.push_target(MemoryInitOp::Unsupported {
                                    reason:
                                        "Kani does not support typed_swap of MaybeUninit storage."
                                            .to_string(),
                                });
                            }
                            Intrinsic::TypedSwap => {
                                self.push_target(MemoryInitOp::Check { operand: args[0].clone() });
                                self.push_target(MemoryInitOp::Check { operand: args[1].clone() });
                            }
                            Intrinsic::VolatileLoad | Intrinsic::UnalignedVolatileLoad => {
                                self.push_target(MemoryInitOp::Check { operand: args[0].clone() });
                            }
                            Intrinsic::VolatileStore | Intrinsic::UnalignedVolatileStore => {
                                self.push_target(MemoryInitOp::Set {
                                    operand: args[0].clone(),
                                    value: true,
                                    position: InsertPosition::After,
                                });
                            }
                            // `volatile_set_memory(dst, val, count)` has the same shape and the
                            // same memory-initialization effect as `write_bytes(dst, val, count)`;
                            // volatility does not change which bytes become initialized.
                            Intrinsic::WriteBytes | Intrinsic::VolatileSetMemory => self
                                .push_target(MemoryInitOp::SetSliceChunk {
                                    operand: args[0].clone(),
                                    count: args[2].clone(),
                                    value: true,
                                    position: InsertPosition::After,
                                }),
                            intrinsic => {
                                self.push_target(MemoryInitOp::Unsupported {
                                    reason: format!("Kani does not support reasoning about memory initialization of intrinsic `{intrinsic:?}`."),
                                });
                            }
                        }
                    }
                    InstanceKind::Item => {
                        if instance.is_foreign_item() {
                            match instance.name().as_str() {
                                "alloc::alloc::__rust_alloc" | "alloc::alloc::__rust_realloc" => {
                                    /* Memory is uninitialized, nothing to do here. */
                                }
                                "alloc::alloc::__rust_alloc_zeroed" => {
                                    /* Memory is initialized here, need to update shadow memory. */
                                    self.push_target(MemoryInitOp::SetSliceChunk {
                                        operand: Operand::Copy(destination.clone()),
                                        count: args[0].clone(),
                                        value: true,
                                        position: InsertPosition::After,
                                    });
                                }
                                "alloc::alloc::__rust_dealloc" => {
                                    /* Memory is uninitialized here, need to update shadow memory. */
                                    self.push_target(MemoryInitOp::SetSliceChunk {
                                        operand: raw_ptr_arg(&args[0], self.locals.as_slice()),
                                        count: args[1].clone(),
                                        value: false,
                                        position: InsertPosition::After,
                                    });
                                }
                                _ => {}
                            }
                        } else {
                            let union_args: Vec<_> = args
                                .iter()
                                .enumerate()
                                .filter(|(_, arg)| {
                                    self.transfers_shadow(arg.ty(&self.locals).unwrap())
                                })
                                .collect();
                            if !union_args.is_empty() {
                                for (idx, operand) in union_args {
                                    self.push_target(MemoryInitOp::StoreArgument {
                                        operand: operand.clone(),
                                        argument_no: idx + 1, // since arguments are 1-indexed
                                    })
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            TerminatorKind::Drop { place, .. } => {
                self.super_terminator(term, location);
                let place_ty = place.ty(&self.locals).unwrap();

                // When drop is codegen'ed for types that could define their own dropping
                // behavior, a reference is taken to the place which is later implicitly coerced
                // to a pointer. Hence, we need to bless this pointer as initialized.
                match place
                    .ty(&self.locals)
                    .unwrap()
                    .kind()
                    .rigid()
                    .expect("should be working with monomorphized code")
                {
                    RigidTy::Adt(..) | RigidTy::Dynamic(_, _) => {
                        self.push_target(MemoryInitOp::SetRef {
                            operand: Operand::Copy(place.clone()),
                            value: true,
                            position: InsertPosition::Before,
                        });
                    }
                    _ => {}
                }

                if place_ty.kind().is_raw_ptr() {
                    self.push_target(MemoryInitOp::Set {
                        operand: Operand::Copy(place.clone()),
                        value: false,
                        position: InsertPosition::After,
                    });
                }
            }
            TerminatorKind::Return => {
                let return_place = Place::from(0);
                if maybe_uninit_storage(self.tcx, return_place.ty(&self.locals).unwrap()).is_some()
                {
                    self.push_target(MemoryInitOp::StoreArgument {
                        operand: Operand::Copy(return_place),
                        argument_no: 0,
                    });
                }
                self.super_terminator(term, location);
            }
            TerminatorKind::Goto { .. }
            | TerminatorKind::SwitchInt { .. }
            | TerminatorKind::Resume
            | TerminatorKind::Abort
            | TerminatorKind::Unreachable
            | TerminatorKind::Assert { .. }
            | TerminatorKind::InlineAsm { .. } => self.super_terminator(term, location),
        }
        // Push the current target from the terminator onto the list.
        self.targets.push(self.current_target.clone());
    }

    fn visit_place(&mut self, place: &Place, ptx: PlaceContext, location: Location) {
        for (idx, elem) in place.projection.iter().enumerate() {
            let intermediate_place =
                Place { local: place.local, projection: place.projection[..idx].to_vec() };
            match elem {
                ProjectionElem::Deref => {
                    let ptr_ty = intermediate_place.ty(&self.locals).unwrap();
                    if ptr_ty.kind().is_raw_ptr() {
                        self.push_target(MemoryInitOp::Check {
                            operand: Operand::Copy(intermediate_place.clone()),
                        });
                    }
                }
                ProjectionElem::Field(_, _) => {
                    let union_ty = intermediate_place.ty(&self.locals).unwrap();
                    if union_ty.kind().is_union() && !ptx.is_mutating() {
                        if wrapper_inner(self.tcx, union_ty, LangItem::MaybeUninit).is_none()
                            && place.projection.contains(&ProjectionElem::Deref)
                        {
                            // We do not currently support having a deref projection in the same
                            // place as union field access.
                            self.push_target(MemoryInitOp::Unsupported {
                                reason: "Kani does not yet support performing a dereference on a union field".to_string(),
                            });
                        }
                        // Accessing a place inside the union, need to check if it is initialized.
                        self.push_target(MemoryInitOp::CheckRef {
                            operand: Operand::Copy(place.clone()),
                        });
                    }
                }
                ProjectionElem::Index(_)
                | ProjectionElem::ConstantIndex { .. }
                | ProjectionElem::Subslice { .. } => {
                    /* For a slice to be indexed, it should be valid first. */
                }
                ProjectionElem::Downcast(_) => {}
                ProjectionElem::OpaqueCast(_) => {}
            }
        }
        self.super_place(place, ptx, location)
    }

    fn visit_operand(&mut self, operand: &Operand, location: Location) {
        if let Operand::Constant(constant) = operand
            && let ConstantKind::Allocated(allocation) = constant.const_.kind()
        {
            for (_, prov) in &allocation.provenance.ptrs {
                if let GlobalAlloc::Static(_) = GlobalAlloc::from(prov.0)
                    && constant.ty().kind().is_raw_ptr()
                {
                    // If a static is a raw pointer, need to mark it as initialized.
                    self.push_target(MemoryInitOp::Set {
                        operand: Operand::Constant(constant.clone()),
                        value: true,
                        position: InsertPosition::Before,
                    });
                };
            }
        }
        self.super_operand(operand, location);
    }

    fn visit_rvalue(&mut self, rvalue: &Rvalue, location: Location) {
        if let Rvalue::AddressOf(_, place) = rvalue
            && let Some(deref) = place.projection.iter().rposition(|p| *p == ProjectionElem::Deref)
        {
            // Forming an address does not read the final pointee. A pointer loaded while
            // computing that address still needs the ordinary read checks.
            let pointer =
                Place { local: place.local, projection: place.projection[..deref].to_vec() };
            self.visit_operand(&Operand::Copy(pointer), location);
            return;
        }
        if let Rvalue::AddressOf(_, place) = rvalue
            && self.enclosing_union(place).is_some_and(|union| {
                wrapper_inner(self.tcx, union, LangItem::MaybeUninit).is_some()
            })
        {
            // A raw address into the value field of a local slot also leaves shadow unchanged.
            return;
        }
        if let Rvalue::Ref(_, _, place) = rvalue
            && let Some(union) = self.enclosing_union(place)
            && wrapper_inner(self.tcx, union, LangItem::MaybeUninit).is_some()
        {
            self.push_target(MemoryInitOp::CheckRef { operand: Operand::Copy(place.clone()) });
            return;
        }
        if let Rvalue::Cast(cast_kind, operand, ty) = rvalue {
            match cast_kind {
                CastKind::PointerCoercion(PointerCoercion::Unsize) => {
                    if let TyKind::RigidTy(RigidTy::RawPtr(pointee_ty, _)) = ty.kind()
                        && pointee_ty.kind().is_trait()
                    {
                        self.push_target(MemoryInitOp::Unsupported {
                                reason: "Kani does not support reasoning about memory initialization of unsized pointers.".to_string(),
                            });
                    }
                }
                CastKind::Transmute => {
                    let operand_ty = operand.ty(&self.locals).unwrap();
                    if self.typed_storage_mask(operand, *ty).is_some() {
                        // The ordinary operand traversal below retains raw-dereference and
                        // union-field checks. Delayed UB still checks affected typed locals.
                        // Only the layout rejection is bypassed; assign_storage installs T's
                        // data mask once, including false padding bytes.
                    } else if let (
                        TyKind::RigidTy(RigidTy::Array(from, from_len)),
                        TyKind::RigidTy(RigidTy::Array(to, to_len)),
                    ) = (operand_ty.kind(), ty.kind())
                        && from_len == to_len
                        && wrapper_inner(self.tcx, from, LangItem::MaybeUninit) == Some(to)
                    {
                        self.push_target(MemoryInitOp::Unsupported {
                            reason: "Kani does not support checking memory initialization of transmute from [MaybeUninit<T>; N] to [T; N]."
                                .to_string(),
                        });
                    } else if self.maybe_uninit_transmute(operand, *ty) {
                        // Initialization was checked against the destination's data bytes.
                    } else if !tys_layout_compatible_to_size(&operand_ty, ty) {
                        // If transmuting between two types of incompatible layouts, padding
                        // bytes are exposed, which is UB.
                        self.push_target(MemoryInitOp::TriviallyUnsafe {
                            reason: "Transmuting between types of incompatible layouts."
                                .to_string(),
                        });
                    } else if let (
                        TyKind::RigidTy(RigidTy::Ref(_, from_ty, _)),
                        TyKind::RigidTy(RigidTy::Ref(_, to_ty, _)),
                    ) = (operand_ty.kind(), ty.kind())
                    {
                        if !tys_layout_compatible_to_size(&from_ty, &to_ty) {
                            // Since references are supposed to always be initialized for its type,
                            // transmuting between two references of incompatible layout is UB.
                            self.push_target(MemoryInitOp::TriviallyUnsafe {
                                reason: "Transmuting between references pointing to types of incompatible layouts."
                                    .to_string(),
                            });
                        }
                    } else if let (
                        TyKind::RigidTy(RigidTy::RawPtr(..)),
                        TyKind::RigidTy(RigidTy::Ref(_, to_ty, _)),
                    ) = (operand_ty.kind(), ty.kind())
                    {
                        // When transmuting from a raw pointer to a reference, need to check that
                        // the value the reference points to is initialized. That is a `to_ty`,
                        // whatever the pointer pointed to before.
                        self.push_target(MemoryInitOp::CheckAs {
                            operand: operand.clone(),
                            pointee_ty: to_ty,
                        });
                    }
                }
                _ => {}
            }
        };
        self.super_rvalue(rvalue, location);
    }
}

/// Determines if the intrinsic has no memory initialization related function and hence can be
/// safely skipped.
fn can_skip_intrinsic(intrinsic: Intrinsic) -> bool {
    match intrinsic {
        Intrinsic::AddWithOverflow
        | Intrinsic::AlignOfVal
        | Intrinsic::ArithOffset
        | Intrinsic::AssertInhabited
        | Intrinsic::AssertMemUninitializedValid
        | Intrinsic::AssertZeroValid
        | Intrinsic::Assume
        | Intrinsic::Bitreverse
        | Intrinsic::BlackBox
        | Intrinsic::Breakpoint
        | Intrinsic::Bswap
        | Intrinsic::CeilF32
        | Intrinsic::CeilF64
        | Intrinsic::CopySignF32
        | Intrinsic::CopySignF64
        | Intrinsic::CosF32
        | Intrinsic::CosF64
        | Intrinsic::Ctlz
        | Intrinsic::CtlzNonZero
        | Intrinsic::Ctpop
        | Intrinsic::Cttz
        | Intrinsic::CttzNonZero
        | Intrinsic::DiscriminantValue
        | Intrinsic::ExactDiv
        | Intrinsic::Exp2F32
        | Intrinsic::Exp2F64
        | Intrinsic::ExpF32
        | Intrinsic::ExpF64
        | Intrinsic::FabsF128
        | Intrinsic::FabsF16
        | Intrinsic::FabsF32
        | Intrinsic::FabsF64
        | Intrinsic::FaddFast
        | Intrinsic::FdivFast
        | Intrinsic::FloorF32
        | Intrinsic::FloorF64
        | Intrinsic::FmafF32
        | Intrinsic::FmafF64
        | Intrinsic::FmulFast
        | Intrinsic::Forget
        | Intrinsic::FsubFast
        | Intrinsic::IsValStaticallyKnown
        | Intrinsic::Likely
        | Intrinsic::Log10F32
        | Intrinsic::Log10F64
        | Intrinsic::Log2F32
        | Intrinsic::Log2F64
        | Intrinsic::LogF32
        | Intrinsic::LogF64
        | Intrinsic::MaxNumF32
        | Intrinsic::MaxNumF64
        | Intrinsic::MinNumF32
        | Intrinsic::MinNumF64
        | Intrinsic::MulWithOverflow
        | Intrinsic::PowF32
        | Intrinsic::PowF64
        | Intrinsic::PowIF32
        | Intrinsic::PowIF64
        | Intrinsic::RotateLeft
        | Intrinsic::RotateRight
        | Intrinsic::RoundF32
        | Intrinsic::RoundF64
        | Intrinsic::SaturatingAdd
        | Intrinsic::SaturatingSub
        | Intrinsic::SinF32
        | Intrinsic::SinF64
        | Intrinsic::SqrtF32
        | Intrinsic::SqrtF64
        | Intrinsic::SubWithOverflow
        | Intrinsic::TruncF32
        | Intrinsic::TruncF64
        | Intrinsic::UncheckedDiv
        | Intrinsic::UncheckedRem
        | Intrinsic::Unlikely
        | Intrinsic::VtableSize
        | Intrinsic::VtableAlign
        | Intrinsic::WrappingAdd
        | Intrinsic::WrappingMul
        | Intrinsic::WrappingSub => {
            /* Intrinsics that do not interact with memory initialization. */
            true
        }
        Intrinsic::PtrGuaranteedCmp
        | Intrinsic::PtrOffsetFrom
        | Intrinsic::PtrOffsetFromUnsigned
        | Intrinsic::SizeOfVal => {
            /* AFAICS from the documentation, none of those require the pointer arguments to be actually initialized. */
            true
        }
        Intrinsic::SimdAdd
        | Intrinsic::SimdAnd
        | Intrinsic::SimdDiv
        | Intrinsic::SimdRem
        | Intrinsic::SimdReduceAll
        | Intrinsic::SimdReduceMax
        | Intrinsic::SimdReduceMin
        | Intrinsic::SimdEq
        | Intrinsic::SimdExtract
        | Intrinsic::SimdGe
        | Intrinsic::SimdGt
        | Intrinsic::SimdInsert
        | Intrinsic::SimdLe
        | Intrinsic::SimdLt
        | Intrinsic::SimdMul
        | Intrinsic::SimdNe
        | Intrinsic::SimdOr
        | Intrinsic::SimdShl
        | Intrinsic::SimdShr
        | Intrinsic::SimdShuffle(_)
        | Intrinsic::SimdSplat
        | Intrinsic::SimdSub
        | Intrinsic::SimdXor => {
            /* SIMD operations */
            true
        }
        Intrinsic::AtomicFence | Intrinsic::AtomicSingleThreadFence => {
            /* Atomic fences */
            true
        }
        _ => {
            /* Everything else */
            false
        }
    }
}

/// Try removing a topmost deref projection from a place if it exists, returning a place without it.
fn try_remove_topmost_deref(place: &Place) -> Option<Place> {
    let mut new_place = place.clone();
    if let Some(ProjectionElem::Deref) = new_place.projection.pop() {
        Some(new_place)
    } else {
        None
    }
}

/// Try retrieving instance for the given function operand.
fn try_resolve_instance(locals: &[LocalDecl], func: &Operand) -> Result<Instance, String> {
    let ty = func.ty(locals).unwrap();
    match ty.kind() {
        TyKind::RigidTy(RigidTy::FnDef(def, args)) => Ok(Instance::resolve(def, &args).unwrap()),
        _ => Err(format!(
            "Kani was not able to resolve the instance of the function operand `{ty:?}`. Currently, memory initialization checks in presence of function pointers and vtable calls are not supported. For more information about planned support, see https://github.com/model-checking/kani/issues/3300."
        )),
    }
}

/// The pointer argument of an allocation shim, as a raw pointer.
///
/// These shims take `NonNull<u8>` as of nightly-2026-03-21, where they previously took `*mut u8`.
/// `NonNull<T>` holds the address in a single field, which as of nightly-2026-05-01 is a
/// `pattern_type!(*const T is !null)` rather than a bare `*const T`. Project through those
/// single-field wrappers until the raw pointer is reached, so that the shadow-memory models see the
/// same address with the pointer type they expect. Operands that are already raw pointers, and any
/// shape we cannot project all the way down to a pointer, are passed through unchanged.
fn raw_ptr_arg(arg: &Operand, locals: &[LocalDecl]) -> Operand {
    let Ok(arg_ty) = arg.ty(locals) else { return arg.clone() };
    if nonnull_pointee(arg_ty).is_none() {
        return arg.clone();
    }
    let place = match arg {
        Operand::Copy(place) | Operand::Move(place) => place,
        Operand::Constant(_) | Operand::RuntimeChecks(_) => return arg.clone(),
    };
    let mut projection = place.projection.clone();
    let mut curr_ty = arg_ty;
    while !curr_ty.kind().is_raw_ptr() {
        let Some(field_ty) = single_field_ty(curr_ty) else { return arg.clone() };
        projection.push(ProjectionElem::Field(0, field_ty));
        curr_ty = field_ty;
    }
    Operand::Copy(Place { local: place.local, projection })
}

/// The type held by `ty`'s only field, if `ty` is a single-field wrapper.
///
/// This sees through both structs with exactly one field (such as `NonNull`) and pattern types,
/// which hold the type they constrain in a single tuple-like field.
fn single_field_ty(ty: Ty) -> Option<Ty> {
    match ty.kind() {
        TyKind::RigidTy(RigidTy::Adt(def, args)) => {
            let variant = def.variants_iter().next()?;
            let fields = variant.fields();
            if fields.len() != 1 {
                return None;
            }
            Some(fields[0].ty_with_args(&args))
        }
        TyKind::RigidTy(RigidTy::Pat(base_ty, _)) => Some(base_ty),
        _ => None,
    }
}
