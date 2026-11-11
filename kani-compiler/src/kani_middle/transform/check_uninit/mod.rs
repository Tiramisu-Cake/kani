// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Module containing multiple transformation passes that instrument the code to detect possible UB
//! due to the accesses to uninitialized memory.

use crate::kani_middle::nonnull_pointee;
use crate::kani_middle::transform::body::{
    CheckType, InsertPosition, MutableBody, SourceInstruction, synthetic_source_info,
};
use relevant_instruction::{InitRelevantInstruction, MemoryInitOp, constant_init_mask};
use rustc_middle::ty::TyCtxt;
use rustc_public::{
    mir::{
        AggregateKind, BasicBlock, BinOp, Body, ConstOperand, Mutability, Operand, Place, Rvalue,
        Statement, StatementKind, Terminator, TerminatorKind, UnwindAction, mono::Instance,
    },
    ty::{FnDef, GenericArgKind, GenericArgs, MirConst, RigidTy, Ty, TyConst, TyKind, UintTy},
};
use std::collections::HashMap;
use ty_layout::{maybe_uninit_storage, product_layout};

use crate::kani_middle::kani_functions::{KaniFunction, KaniModel};
pub use delayed_ub::DelayedUbPass;
pub use ptr_uninit::UninitPass;
use rustc_public::mir::WithRetag;
pub use ty_layout::{PointeeInfo, PointeeLayout};

mod delayed_ub;
mod ptr_uninit;
mod relevant_instruction;
mod ty_layout;

/// Trait that the instrumentation target providers must implement to work with the instrumenter.
pub trait TargetFinder {
    fn find_all(self, body: &MutableBody) -> Vec<InitRelevantInstruction>;
}

const KANI_IS_PTR_INITIALIZED: KaniFunction = KaniFunction::Model(KaniModel::IsPtrInitialized);
const KANI_SET_PTR_INITIALIZED: KaniFunction = KaniFunction::Model(KaniModel::SetPtrInitialized);
const KANI_IS_SLICE_CHUNK_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::IsSliceChunkPtrInitialized);
const KANI_SET_SLICE_CHUNK_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::SetSliceChunkPtrInitialized);
const KANI_IS_SLICE_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::IsSlicePtrInitialized);
const KANI_SET_SLICE_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::SetSlicePtrInitialized);
const KANI_IS_STR_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::IsStrPtrInitialized);
const KANI_SET_STR_PTR_INITIALIZED: KaniFunction =
    KaniFunction::Model(KaniModel::SetStrPtrInitialized);
const KANI_COPY_INIT_STATE: KaniFunction = KaniFunction::Model(KaniModel::CopyInitState);
const KANI_COPY_INIT_STATE_SINGLE: KaniFunction =
    KaniFunction::Model(KaniModel::CopyInitStateSingle);
const KANI_LOAD_ARGUMENT: KaniFunction = KaniFunction::Model(KaniModel::LoadArgument);
const KANI_STORE_ARGUMENT: KaniFunction = KaniFunction::Model(KaniModel::StoreArgument);
// The contract-clause-depth functions access the `CONTRACT_CLAUSE_DEPTH`
// static. Instrumenting that access would inject memory-initialization shadow
// writes that CBMC's contract write-set check then flags as illegal side
// effects when a clause is evaluated during contract verification (e.g. a
// `requires(can_dereference(..))` under `-Z uninit-checks`). The counter is
// verifier-internal and always reset at harness entry, so skipping these is
// sound, mirroring the mem-init functions above.
const KANI_ENTER_CONTRACT_CLAUSE: KaniFunction =
    KaniFunction::Model(KaniModel::EnterContractClause);
const KANI_EXIT_CONTRACT_CLAUSE: KaniFunction = KaniFunction::Model(KaniModel::ExitContractClause);
const KANI_IN_CONTRACT_CLAUSE: KaniFunction = KaniFunction::Model(KaniModel::InContractClause);
const KANI_RESET_CONTRACT_CLAUSE_DEPTH: KaniFunction =
    KaniFunction::Model(KaniModel::ResetContractClauseDepth);

// Function bodies of those functions will not be instrumented as not to cause infinite recursion.
const SKIPPED_ITEMS: &[KaniFunction] = &[
    KANI_IS_PTR_INITIALIZED,
    KANI_SET_PTR_INITIALIZED,
    KANI_IS_SLICE_CHUNK_PTR_INITIALIZED,
    KANI_SET_SLICE_CHUNK_PTR_INITIALIZED,
    KANI_IS_SLICE_PTR_INITIALIZED,
    KANI_SET_SLICE_PTR_INITIALIZED,
    KANI_IS_STR_PTR_INITIALIZED,
    KANI_SET_STR_PTR_INITIALIZED,
    KANI_COPY_INIT_STATE,
    KANI_COPY_INIT_STATE_SINGLE,
    KANI_LOAD_ARGUMENT,
    KANI_STORE_ARGUMENT,
    KANI_ENTER_CONTRACT_CLAUSE,
    KANI_EXIT_CONTRACT_CLAUSE,
    KANI_IN_CONTRACT_CLAUSE,
    KANI_RESET_CONTRACT_CLAUSE_DEPTH,
];

/// Instruments the code with checks for uninitialized memory, agnostic to the source of targets.
pub struct UninitInstrumenter<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    safety_check_type: CheckType,
    unsupported_check_type: CheckType,
    /// Used to cache FnDef lookups of injected memory initialization functions.
    mem_init_fn_cache: &'a mut HashMap<KaniFunction, FnDef>,
}

impl<'a, 'tcx> UninitInstrumenter<'a, 'tcx> {
    /// Create the instrumenter and run it with the given parameters.
    pub(crate) fn run(
        tcx: TyCtxt<'tcx>,
        body: Body,
        instance: Instance,
        safety_check_type: CheckType,
        unsupported_check_type: CheckType,
        mem_init_fn_cache: &'a mut HashMap<KaniFunction, FnDef>,
        target_finder: impl TargetFinder,
    ) -> (bool, Body) {
        let mut instrumenter =
            Self { tcx, safety_check_type, unsupported_check_type, mem_init_fn_cache };
        let body = MutableBody::from(body);
        let (changed, new_body) = instrumenter.instrument(body, instance, target_finder);
        (changed, new_body.into())
    }

    /// Instrument a body with memory initialization checks, the visitor that generates
    /// instrumentation targets must be provided via a TF type parameter.
    fn instrument(
        &mut self,
        mut body: MutableBody,
        instance: Instance,
        target_finder: impl TargetFinder,
    ) -> (bool, MutableBody) {
        // Need to break infinite recursion when memory initialization checks are inserted, so the
        // internal functions responsible for memory initialization are skipped.
        if KaniFunction::try_from(instance).map(|f| SKIPPED_ITEMS.contains(&f)).unwrap_or(false) {
            if crate::kani_middle::trace::enabled() {
                let name = crate::kani_middle::trace::clip(instance.name().as_str(), 320);
                if crate::kani_middle::trace::matches(&name) {
                    crate::kani_middle::trace::event(
                        "memory_init_ops",
                        serde_json::json!({"instance": name, "decision": "skipped", "reason": "internal_mem_init_function_recursion_guard"}),
                    );
                }
            }
            return (false, body);
        }

        let orig_len = body.blocks().len();
        let instructions = target_finder.find_all(&body);
        let instance_name = crate::kani_middle::trace::enabled()
            .then(|| crate::kani_middle::trace::clip(instance.name().as_str(), 320));
        if instance_name.as_deref().is_some_and(crate::kani_middle::trace::matches) {
            let instance_name = instance_name.as_deref().unwrap_or_default();
            let mut zero_ops = 0usize;
            for instruction in &instructions {
                if instruction.before_instruction.is_empty()
                    && instruction.after_instruction.is_empty()
                {
                    zero_ops += 1;
                    continue;
                }
                let before: Vec<&str> = instruction
                    .before_instruction
                    .iter()
                    .take(12)
                    .map(|op| op.as_ref())
                    .collect::<Vec<_>>();
                let after: Vec<&str> = instruction
                    .after_instruction
                    .iter()
                    .take(12)
                    .map(|op| op.as_ref())
                    .collect::<Vec<_>>();
                crate::kani_middle::trace::event(
                    "memory_init_ops",
                    serde_json::json!({
                        "instance": instance_name,
                        "source": format!("{:?}", instruction.source),
                        "before": before,
                        "after": after,
                        "before_count": instruction.before_instruction.len(),
                        "after_count": instruction.after_instruction.len(),
                        "decision": "ops_selected",
                    }),
                );
                for (position, operations) in [
                    ("before", &instruction.before_instruction),
                    ("after", &instruction.after_instruction),
                ] {
                    crate::kani_middle::trace::mark_omission(
                        "selected_ops_payload",
                        operations.len().saturating_sub(12),
                        false,
                    );
                    for (ordinal, operation) in operations.iter().take(12).enumerate() {
                        crate::kani_middle::trace::event(
                            "memory_init_op",
                            serde_json::json!({
                                "instance": instance_name,
                                "source": format!("{:?}", instruction.source),
                                "position": position,
                                "ordinal": ordinal,
                                "operation": <MemoryInitOp as AsRef<str>>::as_ref(operation),
                                "details": crate::kani_middle::trace::debug(operation),
                                "selection_only": true,
                            }),
                        );
                    }
                }
            }
            crate::kani_middle::trace::event(
                "memory_init_ops_summary",
                serde_json::json!({"instance": instance_name, "instructions": instructions.len(), "zero_ops": zero_ops, "nonzero_ops": instructions.len() - zero_ops}),
            );
            if instructions.is_empty() {
                crate::kani_middle::trace::event(
                    "memory_init_ops",
                    serde_json::json!({"instance": instance_name, "decision": "zero_instructions", "reason": "body_has_no_visitable_instructions"}),
                );
            }
        }
        for instruction in instructions.into_iter().rev() {
            let source = instruction.source;
            self.build_check_for_instruction(&mut body, instruction, source);
        }
        (orig_len != body.blocks().len(), body)
    }

    /// Inject memory initialization checks for each operation in an instruction.
    fn build_check_for_instruction(
        &mut self,
        body: &mut MutableBody,
        instruction: InitRelevantInstruction,
        mut source: SourceInstruction,
    ) {
        for operation in instruction.before_instruction {
            self.build_check_for_operation(body, &mut source, operation);
        }
        for operation in instruction.after_instruction {
            self.build_check_for_operation(body, &mut source, operation);
        }
    }

    /// Inject memory initialization check for an operation.
    fn build_check_for_operation(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        mut operation: MemoryInitOp,
    ) {
        if let MemoryInitOp::StoreArgument { operand, .. } = &mut operation
            && matches!(operand, Operand::Constant(_))
            && (maybe_uninit_storage(self.tcx, operand.ty(body.locals()).unwrap()).is_some()
                || product_layout(self.tcx, operand.ty(body.locals()).unwrap())
                    .ok()
                    .flatten()
                    .is_some())
        {
            let Some(initialized) = constant_init_mask(operand) else {
                self.inject_unsupported_check(
                    body,
                    source,
                    InsertPosition::Before,
                    "Kani cannot determine the initialization state of this MaybeUninit argument.",
                );
                return;
            };
            let local = body.insert_assignment(
                Rvalue::Use(operand.clone(), WithRetag::No),
                source,
                InsertPosition::Before,
            );
            *operand = Operand::Copy(Place::from(local));
            self.build_check_for_operation(
                body,
                source,
                MemoryInitOp::SetStorage {
                    operand: operand.clone(),
                    initialized,
                    position: InsertPosition::Before,
                },
            );
        }

        if let MemoryInitOp::Unsupported { reason } = &operation {
            self.inject_unsupported_check(body, source, operation.position(), reason);
            return;
        } else if let MemoryInitOp::TriviallyUnsafe { reason } = &operation {
            self.inject_safety_check(body, source, operation.position(), reason);
            return;
        };

        if let MemoryInitOp::SetPadding { padding, .. } = &operation {
            let padding = padding.clone();
            self.build_product_padding(body, source, operation, &padding);
            return;
        }

        let pointee_info = {
            // Sanity check: since CBMC memory object primitives only accept pointers, need to
            // ensure the correct type.
            let ptr_operand_ty = operation.operand_ty(body);
            let pointee_ty =
                if let TyKind::RigidTy(RigidTy::RawPtr(pointee_ty, _)) = ptr_operand_ty.kind() {
                    pointee_ty
                } else if let Some(pointee_ty) = nonnull_pointee(ptr_operand_ty) {
                    // The allocation shims hand us a `NonNull<u8>`, which holds the same address as the
                    // `*mut u8` they used to take.
                    pointee_ty
                } else {
                    unreachable!(
                        "Should only build checks for raw pointers, `{ptr_operand_ty}` encountered."
                    )
                };
            // Calculate pointee layout for byte-by-byte memory initialization checks.
            let product = match product_layout(self.tcx, pointee_ty) {
                Ok(product) => product,
                Err(reason) => {
                    self.inject_unsupported_check(
                        body,
                        source,
                        operation.position(),
                        &reason.to_string(),
                    );
                    return;
                }
            };
            let layout = if let Some(product) = product {
                match &operation {
                    // A delayed setter and implicit Drop address must not bless storage, or
                    // overwrite the result of a typed transfer. Ordinary writes are handled at
                    // their field ranges; typed reads retain the R checks below.
                    MemoryInitOp::SetRef { operand, position, .. } => {
                        let padding_op = MemoryInitOp::SetPadding {
                            operand: operand.clone(),
                            padding: product.padding_mask.clone(),
                            position: *position,
                        };
                        self.build_product_padding(body, source, padding_op, &product.padding_mask);
                        return;
                    }
                    MemoryInitOp::SetSliceChunk { .. } => {
                        PointeeInfo::for_product_storage(self.tcx, pointee_ty)
                    }
                    MemoryInitOp::Set { .. } => {
                        // An unmodeled typed/volatile write cannot fabricate S state. Bytewise
                        // intrinsics through u8 pointers continue to use the ordinary path.
                        self.inject_unsupported_check(
                            body,
                            source,
                            operation.position(),
                            "Kani does not support this write to compound storage.",
                        );
                        return;
                    }
                    _ => PointeeInfo::for_product_read(self.tcx, pointee_ty),
                }
            } else if maybe_uninit_storage(self.tcx, pointee_ty).is_some() {
                match &operation {
                    // Reading a slot or slice of slots does not require initialized data.
                    MemoryInitOp::Check { .. }
                    | MemoryInitOp::CheckRef { .. }
                    | MemoryInitOp::CheckAs { .. }
                    | MemoryInitOp::CheckSliceChunk { .. } => {
                        match PointeeInfo::for_storage(self.tcx, pointee_ty) {
                            Ok(_) => return,
                            Err(reason) => Err(reason),
                        }
                    }
                    // The pointer visitor handles writes to this storage, including transfers.
                    // A generic set from delayed UB instrumentation would erase that state.
                    MemoryInitOp::SetRef { .. } => return,
                    MemoryInitOp::SetStorage { .. }
                    | MemoryInitOp::Copy { .. }
                    | MemoryInitOp::AssignUnion { .. }
                    | MemoryInitOp::StoreArgument { .. }
                    | MemoryInitOp::LoadArgument { .. }
                    | MemoryInitOp::SetSliceChunk { .. } => {
                        PointeeInfo::for_storage(self.tcx, pointee_ty)
                    }
                    _ => PointeeInfo::from_ty(pointee_ty),
                }
            } else {
                PointeeInfo::from_ty(pointee_ty)
            };
            match layout {
                Ok(type_info) => type_info,
                Err(reason) => {
                    let reason = format!(
                        "Kani currently doesn't support checking memory initialization for pointers to `{pointee_ty}. {reason}",
                    );
                    self.inject_unsupported_check(body, source, operation.position(), &reason);
                    return;
                }
            }
        };

        match &operation {
            MemoryInitOp::CheckSliceChunk { .. }
            | MemoryInitOp::Check { .. }
            | MemoryInitOp::CheckAs { .. }
            | MemoryInitOp::CheckRef { .. }
            | MemoryInitOp::CheckRefAs { .. } => {
                self.build_get_and_check(body, source, operation, pointee_info)
            }
            MemoryInitOp::SetSliceChunk { .. }
            | MemoryInitOp::Set { .. }
            | MemoryInitOp::SetRef { .. }
            | MemoryInitOp::CreateUnion { .. }
            | MemoryInitOp::SetStorage { .. } => {
                self.build_set(body, source, operation, pointee_info)
            }
            MemoryInitOp::Copy { .. } => self.build_copy(body, source, operation, pointee_info),
            MemoryInitOp::AssignUnion { .. } => {
                self.build_assign_union(body, source, operation, pointee_info)
            }
            MemoryInitOp::StoreArgument { .. } | MemoryInitOp::LoadArgument { .. } => {
                self.build_argument_operation(body, source, operation, pointee_info)
            }
            MemoryInitOp::Unsupported { .. }
            | MemoryInitOp::TriviallyUnsafe { .. }
            | MemoryInitOp::SetPadding { .. } => {
                unreachable!()
            }
        };
    }

    /// Clear each maximal padding interval using a u8 range. No setter spans R or S.
    fn build_product_padding(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        padding: &[bool],
    ) {
        let position = operation.position();
        let mut statements = vec![];
        let address = operation.mk_operand(body, &mut statements, source);
        for stmt in statements {
            body.insert_stmt(stmt, source, position);
        }
        let u8_ty = Ty::unsigned_ty(UintTy::U8);
        let byte_ptr = body.insert_ptr_cast(address, u8_ty, Mutability::Not, source, position);
        let mut start = 0;
        while start < padding.len() {
            if !padding[start] {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < padding.len() && padding[end] {
                end += 1;
            }
            let span = source.span(body.blocks());
            let offset = body.new_uint_operand(start as u128, UintTy::Usize, span);
            let ptr = body.insert_binary_op(
                BinOp::Offset,
                Operand::Copy(Place::from(byte_ptr)),
                offset,
                source,
                position,
            );
            let count = body.new_uint_operand((end - start) as u128, UintTy::Usize, span);
            self.build_check_for_operation(
                body,
                source,
                MemoryInitOp::SetSliceChunk {
                    operand: Operand::Copy(Place::from(ptr)),
                    count,
                    value: false,
                    position,
                },
            );
            start = end;
        }
    }

    /// Inject a load from memory initialization state and an assertion that all non-padding bytes
    /// are initialized.
    fn build_get_and_check(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        pointee_info: PointeeInfo,
    ) {
        let ret_place = Place {
            local: body.new_local(Ty::bool_ty(), source.span(body.blocks()), Mutability::Not),
            projection: vec![],
        };
        // Instead of injecting the instrumentation immediately, collect it into a list of
        // statements and a terminator to construct a basic block and inject it at the end.
        let mut statements = vec![];
        let ptr_operand = operation.mk_operand(body, &mut statements, source);
        let terminator = match pointee_info.layout() {
            PointeeLayout::Sized { layout } => {
                let layout_operand = mk_layout_operand(body, &mut statements, source, layout);
                // Depending on whether accessing the known number of elements in the slice, need to
                // pass is as an argument.
                let (diagnostic, args) = match &operation {
                    MemoryInitOp::Check { .. }
                    | MemoryInitOp::CheckAs { .. }
                    | MemoryInitOp::CheckRef { .. }
                    | MemoryInitOp::CheckRefAs { .. } => {
                        let diagnostic = KANI_IS_PTR_INITIALIZED;
                        let args = vec![ptr_operand.clone(), layout_operand];
                        (diagnostic, args)
                    }
                    MemoryInitOp::CheckSliceChunk { .. } => {
                        let diagnostic = KANI_IS_SLICE_CHUNK_PTR_INITIALIZED;
                        let args =
                            vec![ptr_operand.clone(), layout_operand, operation.expect_count()];
                        (diagnostic, args)
                    }
                    _ => unreachable!(),
                };
                let is_ptr_initialized_instance = resolve_mem_init_fn(
                    get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
                    layout.len(),
                    *pointee_info.ty(),
                );
                Terminator {
                    kind: TerminatorKind::Call {
                        func: Operand::Copy(Place::from(body.new_local(
                            is_ptr_initialized_instance.ty(),
                            source.span(body.blocks()),
                            Mutability::Not,
                        ))),
                        args,
                        destination: ret_place.clone(),
                        target: Some(0), // The current value does not matter, since it will be overwritten in add_bb.
                        unwind: UnwindAction::Terminate,
                    },
                    source_info: synthetic_source_info(source.span(body.blocks())),
                }
            }
            PointeeLayout::Slice { element_layout } => {
                // Since `str`` is a separate type, need to differentiate between [T] and str.
                let (slicee_ty, diagnostic) = match pointee_info.ty().kind() {
                    TyKind::RigidTy(RigidTy::Slice(slicee_ty)) => {
                        (slicee_ty, KANI_IS_SLICE_PTR_INITIALIZED)
                    }
                    TyKind::RigidTy(RigidTy::Str) => {
                        (Ty::unsigned_ty(UintTy::U8), KANI_IS_STR_PTR_INITIALIZED)
                    }
                    _ => unreachable!(),
                };
                let is_ptr_initialized_instance = resolve_mem_init_fn(
                    get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
                    element_layout.len(),
                    slicee_ty,
                );
                let layout_operand =
                    mk_layout_operand(body, &mut statements, source, element_layout);
                Terminator {
                    kind: TerminatorKind::Call {
                        func: Operand::Copy(Place::from(body.new_local(
                            is_ptr_initialized_instance.ty(),
                            source.span(body.blocks()),
                            Mutability::Not,
                        ))),
                        args: vec![ptr_operand.clone(), layout_operand],
                        destination: ret_place.clone(),
                        target: Some(0), // The current value does not matter, since it will be overwritten in add_bb.
                        unwind: UnwindAction::Terminate,
                    },
                    source_info: synthetic_source_info(source.span(body.blocks())),
                }
            }
            PointeeLayout::TraitObject => {
                let reason = "Kani does not support reasoning about memory initialization of pointers to trait objects.";
                self.inject_unsupported_check(body, source, operation.position(), reason);
                return;
            }
            PointeeLayout::Union { .. } => {
                // Here we are reading from a pointer to a union.
                // TODO: we perhaps need to check that the union at least contains an intersection
                // of all layouts initialized.
                let reason = "Interaction between raw pointers and unions is not yet supported.";
                self.inject_unsupported_check(body, source, operation.position(), reason);
                return;
            }
        };

        // Construct the basic block and insert it into the body.
        body.insert_bb(BasicBlock { statements, terminator }, source, operation.position());

        // Since the check involves a terminator, we cannot add it to the previously constructed
        // basic block. Instead, we insert the check after the basic block.
        let operand_ty = match &operation {
            MemoryInitOp::Check { operand }
            | MemoryInitOp::CheckSliceChunk { operand, .. }
            | MemoryInitOp::CheckRef { operand } => operand.ty(body.locals()).unwrap(),
            MemoryInitOp::CheckRefAs { pointee_ty, .. } => *pointee_ty,
            MemoryInitOp::CheckAs { .. } => operation.operand_ty(body),
            _ => unreachable!(),
        };
        body.insert_check(
            &self.safety_check_type,
            source,
            operation.position(),
            Some(ret_place.local),
            &format!(
                "Undefined Behavior: Reading from an uninitialized pointer of type `{operand_ty}`"
            ),
        )
    }

    /// Inject a store into memory initialization state to initialize or deinitialize all
    /// non-padding bytes.
    fn build_set(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        pointee_info: PointeeInfo,
    ) {
        let ret_place = Place {
            local: body.new_local(Ty::new_tuple(&[]), source.span(body.blocks()), Mutability::Not),
            projection: vec![],
        };

        // Instead of injecting the instrumentation immediately, collect it into a list of
        // statements and a terminator to construct a basic block and inject it at the end.
        let mut statements = vec![];
        let ptr_operand = operation.mk_operand(body, &mut statements, source);
        let value = operation.expect_value();
        let terminator = match pointee_info.layout() {
            PointeeLayout::Sized { layout } => {
                let layout = if let MemoryInitOp::SetStorage { initialized, .. } = &operation {
                    assert_eq!(layout.len(), initialized.len());
                    initialized
                } else {
                    layout
                };
                let layout_operand = mk_layout_operand(body, &mut statements, source, layout);
                // Depending on whether writing to the known number of elements in the slice, need to
                // pass is as an argument.
                let (diagnostic, args) = match &operation {
                    MemoryInitOp::Set { .. }
                    | MemoryInitOp::SetRef { .. }
                    | MemoryInitOp::SetStorage { .. } => {
                        let diagnostic = KANI_SET_PTR_INITIALIZED;
                        let args = vec![
                            ptr_operand,
                            layout_operand,
                            Operand::Constant(ConstOperand {
                                span: source.span(body.blocks()),
                                user_ty: None,
                                const_: MirConst::from_bool(value),
                            }),
                        ];
                        (diagnostic, args)
                    }
                    MemoryInitOp::SetSliceChunk { .. } => {
                        let diagnostic = KANI_SET_SLICE_CHUNK_PTR_INITIALIZED;
                        let args = vec![
                            ptr_operand,
                            layout_operand,
                            operation.expect_count(),
                            Operand::Constant(ConstOperand {
                                span: source.span(body.blocks()),
                                user_ty: None,
                                const_: MirConst::from_bool(value),
                            }),
                        ];
                        (diagnostic, args)
                    }
                    _ => unreachable!(),
                };
                let set_ptr_initialized_instance = resolve_mem_init_fn(
                    get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
                    layout.len(),
                    *pointee_info.ty(),
                );
                Terminator {
                    kind: TerminatorKind::Call {
                        func: Operand::Copy(Place::from(body.new_local(
                            set_ptr_initialized_instance.ty(),
                            source.span(body.blocks()),
                            Mutability::Not,
                        ))),
                        args,
                        destination: ret_place.clone(),
                        target: Some(0), // this will be overriden in add_bb
                        unwind: UnwindAction::Terminate,
                    },
                    source_info: synthetic_source_info(source.span(body.blocks())),
                }
            }
            PointeeLayout::Slice { element_layout } => {
                // Since `str`` is a separate type, need to differentiate between [T] and str.
                let (slicee_ty, diagnostic) = match pointee_info.ty().kind() {
                    TyKind::RigidTy(RigidTy::Slice(slicee_ty)) => {
                        (slicee_ty, KANI_SET_SLICE_PTR_INITIALIZED)
                    }
                    TyKind::RigidTy(RigidTy::Str) => {
                        (Ty::unsigned_ty(UintTy::U8), KANI_SET_STR_PTR_INITIALIZED)
                    }
                    _ => unreachable!(),
                };
                let set_ptr_initialized_instance = resolve_mem_init_fn(
                    get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
                    element_layout.len(),
                    slicee_ty,
                );
                let layout_operand =
                    mk_layout_operand(body, &mut statements, source, element_layout);
                Terminator {
                    kind: TerminatorKind::Call {
                        func: Operand::Copy(Place::from(body.new_local(
                            set_ptr_initialized_instance.ty(),
                            source.span(body.blocks()),
                            Mutability::Not,
                        ))),
                        args: vec![
                            ptr_operand,
                            layout_operand,
                            Operand::Constant(ConstOperand {
                                span: source.span(body.blocks()),
                                user_ty: None,
                                const_: MirConst::from_bool(value),
                            }),
                        ],
                        destination: ret_place.clone(),
                        target: Some(0), // The current value does not matter, since it will be overwritten in add_bb.
                        unwind: UnwindAction::Terminate,
                    },
                    source_info: synthetic_source_info(source.span(body.blocks())),
                }
            }
            PointeeLayout::TraitObject => {
                // The layout, and so the padding, depends on the concrete type behind the vtable.
                // As for reads (see `build_get_and_check`), report it rather than skip the update:
                // a skipped update could leave uninitialized memory marked as initialized.
                let reason = "Kani does not support reasoning about memory initialization of pointers to trait objects.";
                self.inject_unsupported_check(body, source, operation.position(), reason);
                return;
            }
            PointeeLayout::Union { field_layouts } => {
                // Writing union data, which could be either creating a union from scratch or
                // performing some pointer operations with it. If we are creating a union from
                // scratch, an operation will contain a union field.

                // TODO: If we don't have a union field, we are either creating a pointer to a union
                // or assigning to one. In the former case, it is safe to return from this function,
                // since the union must be already tracked (on creation and update). In the latter
                // case, we should have been using union assignment instead. Nevertheless, this is
                // currently mitigated by injecting `assert!(false)`.
                let union_field = match operation.union_field() {
                    Some(field) => field,
                    None => {
                        let reason =
                            "Interaction between raw pointers and unions is not yet supported.";
                        self.inject_unsupported_check(body, source, operation.position(), reason);
                        return;
                    }
                };
                let field_layout = &field_layouts[union_field];
                let mut storage_layout;
                let layout = if maybe_uninit_storage(self.tcx, *pointee_info.ty()).is_some() {
                    // An empty aggregate replaces the entire slot, even when its field is ().
                    let size = pointee_info.ty().layout().unwrap().shape().size.bytes();
                    storage_layout = field_layout.clone();
                    storage_layout.resize(size, false);
                    &storage_layout
                } else {
                    field_layout
                };
                let layout_operand = mk_layout_operand(body, &mut statements, source, layout);
                let diagnostic = KANI_SET_PTR_INITIALIZED;
                let args = vec![
                    ptr_operand,
                    layout_operand,
                    Operand::Constant(ConstOperand {
                        span: source.span(body.blocks()),
                        user_ty: None,
                        const_: MirConst::from_bool(value),
                    }),
                ];
                let set_ptr_initialized_instance = resolve_mem_init_fn(
                    get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
                    layout.len(),
                    *pointee_info.ty(),
                );
                Terminator {
                    kind: TerminatorKind::Call {
                        func: Operand::Copy(Place::from(body.new_local(
                            set_ptr_initialized_instance.ty(),
                            source.span(body.blocks()),
                            Mutability::Not,
                        ))),
                        args,
                        destination: ret_place.clone(),
                        target: Some(0), // this will be overriden in add_bb
                        unwind: UnwindAction::Terminate,
                    },
                    source_info: synthetic_source_info(source.span(body.blocks())),
                }
            }
        };
        // Construct the basic block and insert it into the body.
        body.insert_bb(BasicBlock { statements, terminator }, source, operation.position());
    }

    /// Copy memory initialization state from one pointer to the other.
    fn build_copy(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        pointee_info: PointeeInfo,
    ) {
        let ret_place = Place {
            local: body.new_local(Ty::new_tuple(&[]), source.span(body.blocks()), Mutability::Not),
            projection: vec![],
        };
        let layout_size = pointee_info.layout().maybe_size().unwrap();
        let copy_init_state_instance = resolve_mem_init_fn(
            get_mem_init_fn_def(KANI_COPY_INIT_STATE, self.mem_init_fn_cache),
            layout_size,
            *pointee_info.ty(),
        );
        let position = operation.position();
        let (from, to) = operation.expect_copy_operands();
        let count = operation.expect_count();
        body.insert_call(
            &copy_init_state_instance,
            source,
            position,
            vec![from, to, count],
            ret_place.clone(),
        );
    }

    /// Instrument the code to pass information about arguments containing unions. Whenever a
    /// function is called and some of the arguments contain unions, we store the information. And
    /// when we enter the callee, we load the information.
    fn build_argument_operation(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        pointee_info: PointeeInfo,
    ) {
        let ret_place = Place {
            local: body.new_local(Ty::new_tuple(&[]), source.span(body.blocks()), Mutability::Not),
            projection: vec![],
        };
        let mut statements = vec![];
        let layout_size = pointee_info.layout().maybe_size().unwrap();
        let diagnostic = match operation {
            MemoryInitOp::LoadArgument { .. } => KANI_LOAD_ARGUMENT,
            MemoryInitOp::StoreArgument { .. } => KANI_STORE_ARGUMENT,
            _ => unreachable!(),
        };
        let argument_operation_instance = resolve_mem_init_fn(
            get_mem_init_fn_def(diagnostic, self.mem_init_fn_cache),
            layout_size,
            *pointee_info.ty(),
        );
        let operand = operation.mk_operand(body, &mut statements, source);
        let argument_no = operation.expect_argument_no();
        let terminator = Terminator {
            kind: TerminatorKind::Call {
                func: Operand::Copy(Place::from(body.new_local(
                    argument_operation_instance.ty(),
                    source.span(body.blocks()),
                    Mutability::Not,
                ))),
                args: vec![
                    operand,
                    Operand::Constant(ConstOperand {
                        span: source.span(body.blocks()),
                        user_ty: None,
                        const_: MirConst::try_from_uint(argument_no as u128, UintTy::Usize)
                            .unwrap(),
                    }),
                ],
                destination: ret_place.clone(),
                target: Some(0), // this will be overriden in add_bb
                unwind: UnwindAction::Terminate,
            },
            source_info: synthetic_source_info(source.span(body.blocks())),
        };

        // Loading a typed product also drops its target padding; only R/S retain state.
        let padding_op = if let MemoryInitOp::LoadArgument { operand, position, .. } = &operation
            && let Ok(Some(product)) = product_layout(self.tcx, *pointee_info.ty())
        {
            Some((
                MemoryInitOp::SetPadding {
                    operand: operand.clone(),
                    padding: product.padding_mask.clone(),
                    position: *position,
                },
                product.padding_mask,
            ))
        } else {
            None
        };
        // Construct the basic block and insert it into the body.
        body.insert_bb(BasicBlock { statements, terminator }, source, operation.position());
        if let Some((padding_op, mask)) = padding_op {
            self.build_product_padding(body, source, padding_op, &mask);
        }
    }

    /// Copy memory initialization state from one union variable to another.
    fn build_assign_union(
        &mut self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        operation: MemoryInitOp,
        pointee_info: PointeeInfo,
    ) {
        let ret_place = Place {
            local: body.new_local(Ty::new_tuple(&[]), source.span(body.blocks()), Mutability::Not),
            projection: vec![],
        };
        let mut statements = vec![];
        let layout_size = pointee_info.layout().maybe_size().unwrap();
        let copy_init_state_instance = resolve_mem_init_fn(
            get_mem_init_fn_def(KANI_COPY_INIT_STATE_SINGLE, self.mem_init_fn_cache),
            layout_size,
            *pointee_info.ty(),
        );
        let (from, to) = operation.expect_assign_union_operands(body, &mut statements, source);
        let terminator = Terminator {
            kind: TerminatorKind::Call {
                func: Operand::Copy(Place::from(body.new_local(
                    copy_init_state_instance.ty(),
                    source.span(body.blocks()),
                    Mutability::Not,
                ))),
                args: vec![from, to],
                destination: ret_place.clone(),
                target: Some(0), // this will be overriden in add_bb
                unwind: UnwindAction::Terminate,
            },
            source_info: synthetic_source_info(source.span(body.blocks())),
        };

        // Construct the basic block and insert it into the body.
        body.insert_bb(BasicBlock { statements, terminator }, source, operation.position());
    }

    fn inject_safety_check(
        &self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        position: InsertPosition,
        reason: &str,
    ) {
        let span = source.span(body.blocks());
        let rvalue = Rvalue::Use(
            Operand::Constant(ConstOperand {
                const_: MirConst::from_bool(false),
                span,
                user_ty: None,
            }),
            WithRetag::No,
        );
        let result = body.insert_assignment(rvalue, source, position);
        body.insert_check(&self.safety_check_type, source, position, Some(result), reason);
    }

    fn inject_unsupported_check(
        &self,
        body: &mut MutableBody,
        source: &mut SourceInstruction,
        position: InsertPosition,
        reason: &str,
    ) {
        body.insert_check(&self.unsupported_check_type, source, position, None, reason);
    }
}

/// Create an operand from a bit array that represents a byte mask for a type layout where padding
/// bytes are marked as `false` and data bytes are marked as `true`.
///
/// For example, the layout for:
/// ```
/// [repr(C)]
/// struct {
///     a: u16,
///     b: u8
/// }
/// ```
/// will have the following byte mask `[true, true, true, false]`.
pub fn mk_layout_operand(
    body: &mut MutableBody,
    statements: &mut Vec<Statement>,
    source: &mut SourceInstruction,
    layout_byte_mask: &[bool],
) -> Operand {
    let span = source.span(body.blocks());
    let rvalue = Rvalue::Aggregate(
        AggregateKind::Array(Ty::bool_ty()),
        layout_byte_mask
            .iter()
            .map(|byte| {
                Operand::Constant(ConstOperand {
                    span: source.span(body.blocks()),
                    user_ty: None,
                    const_: MirConst::from_bool(*byte),
                })
            })
            .collect(),
    );
    let ret_ty = rvalue.ty(body.locals()).unwrap();
    let result = body.new_local(ret_ty, span, Mutability::Not);
    let stmt = Statement {
        kind: StatementKind::Assign(Place::from(result), rvalue),
        source_info: synthetic_source_info(span),
    };
    statements.push(stmt);

    Operand::Move(Place { local: result, projection: vec![] })
}

/// Retrieve a function definition by diagnostic string, caching the result.
pub fn get_mem_init_fn_def(
    diagnostic: KaniFunction,
    cache: &mut HashMap<KaniFunction, FnDef>,
) -> FnDef {
    cache[&diagnostic]
}

/// Resolves a given memory initialization function with passed type parameters.
pub fn resolve_mem_init_fn(fn_def: FnDef, layout_size: usize, associated_type: Ty) -> Instance {
    Instance::resolve(
        fn_def,
        &GenericArgs(vec![
            GenericArgKind::Const(TyConst::try_from_target_usize(layout_size as u64).unwrap()),
            GenericArgKind::Type(associated_type),
        ]),
    )
    .unwrap()
}
