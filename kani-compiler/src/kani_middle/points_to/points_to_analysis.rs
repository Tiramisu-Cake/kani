// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Implementation of the points-to analysis using Rust's native dataflow framework. This provides
//! necessary aliasing information for instrumenting delayed UB later on.
//!
//! The analysis uses Rust's dataflow framework by implementing appropriate traits to leverage the
//! existing fixpoint solver infrastructure. The main trait responsible for the dataflow analysis
//! behavior is `rustc_mir_dataflow::Analysis`: it provides two methods that are responsible for
//! handling statements and terminators, which we implement.
//!
//! The analysis proceeds by looking at each instruction in the dataflow order and collecting all
//! possible aliasing relations that the instruction introduces. If a terminator is a function call,
//! the analysis recurs into the function and then joins the information retrieved from it into the
//! original graph.
//!
//! For each instruction, the analysis first resolves dereference projections for each place to
//! determine which places it could point to. This is done by finding a set of successors in the
//! graph for each dereference projection.
//!
//! Then, the analysis adds the appropriate edges into the points-to graph. It proceeds until there
//! is no new information to be discovered.
//!
//! Currently, the analysis is not field-sensitive: e.g., if a field of a place aliases to some
//! other place, we treat it as if the place itself aliases to another place.

use crate::{
    intrinsics::Intrinsic,
    kani_middle::{
        SourceLocation,
        points_to::{MemLoc, PointsToGraph},
        reachability::CallGraph,
        readable_name,
        transform::RustcInternalMir,
    },
};
use rustc_middle::{
    mir::{
        BasicBlock, BinOp, Body, CallReturnPlaces, Location, NonDivergingIntrinsic, Operand, Place,
        ProjectionElem, Rvalue, Statement, StatementKind, Terminator, TerminatorKind,
    },
    ty::{Instance, InstanceKind, List, TyCtxt},
};
use rustc_mir_dataflow::{Analysis, Forward, JoinSemiLattice};
use rustc_public::mir::{
    Body as StableBody,
    mono::{Instance as StableInstance, InstanceKind as StableInstanceKind},
};
use rustc_public::rustc_internal;
use rustc_public::ty::{RigidTy as StableRigidTy, Ty as StableTy, TyKind as StableTyKind};
use rustc_span::Spanned;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};

/// A failed root has no usable points-to graph. Never export an unfinished summary.
#[derive(Clone, Debug)]
pub struct PointsToAnalysisError {
    pub reason: String,
}

/// Diagnostic provenance of the existing immutable override selection. This does
/// not select an additional body or introduce an analysis fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyProvenance {
    Source,
    RegistrationOverride(StableInstance),
    DiscardedClosureOverride,
}

#[derive(Clone)]
pub struct AnalysisBodyOverride {
    pub body: StableBody,
    pub provenance: BodyProvenance,
}

/// Exact Instance and selected snapshot, fixed for one root's immutable map.
#[derive(Clone, Copy, PartialEq, Eq)]
struct AnalysisKey<'tcx> {
    instance: Instance<'tcx>,
    provenance: BodyProvenance,
}

impl Display for AnalysisKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep exact Instance/provenance equality for cycle detection, but never
        // expose Debug IDs or compiler symbols in a user-facing diagnostic.
        let owner = readable_name(rustc_internal::stable(self.instance));
        match self.provenance {
            BodyProvenance::Source => write!(f, "{owner} [provenance=source]"),
            BodyProvenance::RegistrationOverride(origin) => write!(
                f,
                "{owner} [provenance=registration-override; origin={}]",
                readable_name(origin)
            ),
            BodyProvenance::DiscardedClosureOverride => {
                write!(f, "{owner} [provenance=discarded-closure-override]")
            }
        }
    }
}

#[derive(Clone)]
struct CallerLocation {
    file: String,
    line: usize,
}

impl Display for CallerLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Shared only by the synchronous, nested analyses of ONE entry root. This is an
/// active stack, not a visited set or an input-independent summary cache.
struct ActiveCalls<K> {
    stack: Vec<K>,
    callers: Vec<Option<CallerLocation>>,
    error: Option<PointsToAnalysisError>,
}

impl<K: Display + Eq> ActiveCalls<K> {
    fn new() -> Self {
        Self { stack: Vec::new(), callers: Vec::new(), error: None }
    }

    #[cfg(test)]
    fn enter(&mut self, key: K) -> Result<(), PointsToAnalysisError> {
        self.enter_at(key, None)
    }

    fn enter_at(
        &mut self,
        key: K,
        caller: Option<CallerLocation>,
    ) -> Result<(), PointsToAnalysisError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if let Some(cycle_start) = self.stack.iter().position(|active| active == &key) {
            // Keep the root and the end of the original active path, including the
            // repeated call. Bound the diagnostic, never the analysis depth or key.
            const MAX_FRAMES: usize = 12;
            const MAX_FRAME_CHARS: usize = 4096;
            let label = |frame: &K, caller: Option<&CallerLocation>| {
                let text = match caller {
                    Some(caller) => format!("{frame} [call at {caller}]"),
                    None => format!("{frame}"),
                };
                let prefix: String = text.chars().take(MAX_FRAME_CHARS).collect();
                if prefix.len() < text.len() {
                    format!("{prefix}... [frame truncated; {} chars total]", text.chars().count())
                } else {
                    prefix
                }
            };
            let mut path = vec![label(&self.stack[0], self.callers[0].as_ref())];
            let tail_start = self.stack.len().saturating_sub(MAX_FRAMES - 2).max(1);
            if tail_start > 1 {
                path.push(format!("... {} frames omitted ...", tail_start - 1));
            }
            path.extend((tail_start..self.stack.len()).map(|idx| {
                format!("frame {idx}: {}", label(&self.stack[idx], self.callers[idx].as_ref()))
            }));
            path.push(format!("repeated: {}", label(&key, caller.as_ref())));
            let error = PointsToAnalysisError {
                reason: format!(
                    "Kani delayed uninitialized-memory analysis detected an interprocedural cycle \
                     (repeats active frame {cycle_start}); root/active path: {}",
                    path.join(" -> ")
                ),
            };
            self.error = Some(error.clone());
            return Err(error);
        }
        self.stack.push(key);
        self.callers.push(caller);
        Ok(())
    }

    fn exit(&mut self) -> Result<(), PointsToAnalysisError> {
        self.stack.pop().expect("balanced points-to analysis entry/exit");
        self.callers.pop().expect("balanced points-to caller metadata");
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

/// Main points-to analysis object.
struct PointsToAnalysis<'a, 'tcx> {
    instance: Instance<'tcx>,
    active_calls: &'a RefCell<ActiveCalls<AnalysisKey<'tcx>>>,
    body: &'a Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    /// This will be used in the future to resolve function pointer and vtable calls. Currently, we
    /// can resolve call graph edges just by looking at the terminators and erroring if we can't
    /// resolve the callee.
    call_graph: &'a CallGraph,
    /// Contract registration trampolines and discarded closures must agree with codegen.
    body_overrides: &'a HashMap<StableInstance, AnalysisBodyOverride>,
    /// This graph should contain a subset of the points-to graph reachable from function arguments.
    /// For the entry function it will be empty (as it supposedly does not have any parameters).
    initial_graph: PointsToGraph<'tcx>,
}

/// Public points-to analysis entry point. Performs the analysis on a body, outputting the graph
/// containing aliasing information of the body itself and any body reachable from it.
pub fn run_points_to_analysis<'tcx>(
    body: &StableBody,
    tcx: TyCtxt<'tcx>,
    instance: StableInstance,
    call_graph: &CallGraph,
    body_overrides: &HashMap<StableInstance, AnalysisBodyOverride>,
) -> Result<PointsToGraph<'tcx>, PointsToAnalysisError> {
    // Dataflow analysis does not yet work with StableMIR, so need to perform backward
    // conversion.
    let internal_instance = rustc_internal::internal(tcx, instance);
    let internal_body = body.internal_mir(tcx);
    PointsToAnalysis::run(
        &internal_body,
        tcx,
        internal_instance,
        call_graph,
        body_overrides,
        &RefCell::new(ActiveCalls::new()),
        PointsToGraph::empty(),
        None,
    )
}

impl<'a, 'tcx> PointsToAnalysis<'a, 'tcx> {
    /// Perform the analysis on a body, outputting the graph containing aliasing information of the
    /// body itself and any body reachable from it.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        body: &'a Body<'tcx>,
        tcx: TyCtxt<'tcx>,
        instance: Instance<'tcx>,
        call_graph: &'a CallGraph,
        body_overrides: &'a HashMap<StableInstance, AnalysisBodyOverride>,
        active_calls: &'a RefCell<ActiveCalls<AnalysisKey<'tcx>>>,
        initial_graph: PointsToGraph<'tcx>,
        caller: Option<CallerLocation>,
    ) -> Result<PointsToGraph<'tcx>, PointsToAnalysisError> {
        let key = AnalysisKey {
            instance,
            provenance: body_overrides
                .get(&rustc_internal::stable(instance))
                .map_or(BodyProvenance::Source, |selected| selected.provenance),
        };
        active_calls.borrow_mut().enter_at(key, caller)?;
        let analysis =
            Self { body, tcx, instance, call_graph, body_overrides, active_calls, initial_graph };
        // This creates a fixpoint solver using the initial graph, the body, and extra information
        // and solves the dataflow problem, producing the cursor, which contains dataflow state for
        // each instruction in the body.
        let mut cursor =
            analysis.iterate_to_fixpoint(tcx, body, Some(Self::NAME)).into_results_cursor(body);
        // We collect dataflow state at each `Return` terminator to determine the full aliasing
        // graph for the function. This is sound since those are the only places where the function
        // finishes, so the dataflow state at those places will be a union of dataflow states
        // preceding to it, which means every possible execution is taken into account.
        let mut results = PointsToGraph::empty();
        for (idx, bb) in body.basic_blocks.iter().enumerate() {
            if let TerminatorKind::Return = bb.terminator().kind {
                // Switch the cursor to the end of the block ending with `Return`.
                cursor.seek_to_block_end(idx.into());
                // Retrieve the dataflow state and join into the results graph.
                results.join(&cursor.get().clone());
            }
        }
        // Trait callbacks cannot return Result. A cycle latches the first error;
        // callbacks then stop adding effects, and every active frame unwinds here.
        // No partial graph can cross this Result boundary, even during cursor replay.
        active_calls.borrow_mut().exit().map(|()| results)
    }
}

impl<'tcx> Analysis<'tcx> for PointsToAnalysis<'_, 'tcx> {
    /// Dataflow state at each instruction.
    type Domain = PointsToGraph<'tcx>;

    type Direction = Forward;

    const NAME: &'static str = "PointsToAnalysis";

    /// Dataflow state instantiated at the beginning of each basic block, before the state from
    /// previous basic blocks gets joined into it.
    fn bottom_value(&self, _body: &Body<'tcx>) -> Self::Domain {
        PointsToGraph::empty()
    }

    /// Dataflow state instantiated at the entry into the body; this should be the initial dataflow
    /// graph.
    fn initialize_start_block(&self, _body: &Body<'tcx>, state: &mut Self::Domain) {
        state.join(&self.initial_graph.clone());
    }

    /// Update current dataflow state based on the information we can infer from the given
    /// statement.
    fn apply_primary_statement_effect(
        &self,
        state: &mut Self::Domain,
        statement: &Statement<'tcx>,
        _location: Location,
    ) {
        if self.active_calls.borrow().error.is_some() {
            return;
        }
        // The only two statements that can introduce new aliasing information are assignments and
        // copies using `copy_nonoverlapping`.
        match &statement.kind {
            StatementKind::Assign(assign_box) => {
                let (place, rvalue) = *assign_box.clone();
                // Resolve all dereference projections for the lvalue.
                let lvalue_set = state.resolve_place(place, self.instance);
                // Determine all places rvalue could point to.
                let rvalue_set = self.successors_for_rvalue(state, rvalue);
                // Create an edge between all places which could be lvalue and all places rvalue
                // could be pointing to.
                state.extend(&lvalue_set, &rvalue_set);
            }
            StatementKind::Intrinsic(non_diverging_intrinsic) => {
                match *non_diverging_intrinsic.clone() {
                    NonDivergingIntrinsic::CopyNonOverlapping(copy_nonoverlapping) => {
                        // Copy between the values pointed by `*const a` and `*mut b` is
                        // semantically equivalent to *b = *a with respect to aliasing.
                        self.apply_copy_effect(
                            state,
                            copy_nonoverlapping.src.clone(),
                            copy_nonoverlapping.dst.clone(),
                        );
                    }
                    NonDivergingIntrinsic::Assume(..) => { /* This is a no-op. */ }
                }
            }
            StatementKind::FakeRead(..)
            | StatementKind::SetDiscriminant { .. }
            | StatementKind::StorageLive(..)
            | StatementKind::StorageDead(..)
            | StatementKind::PlaceMention(..)
            | StatementKind::AscribeUserType(..)
            | StatementKind::Coverage(..)
            | StatementKind::ConstEvalCounter
            | StatementKind::BackwardIncompatibleDropHint { .. }
            | StatementKind::Nop => { /* This is a no-op with regard to aliasing. */ }
        }
    }

    fn apply_primary_terminator_effect(
        &self,
        state: &mut Self::Domain,
        terminator: &Terminator<'tcx>,
        location: Location,
    ) {
        if self.active_calls.borrow().error.is_some() {
            return;
        }
        if let TerminatorKind::Call { func, args, destination, .. } = &terminator.kind {
            // Calls the analysis cannot follow add no edges here: the instrumentation guards each
            // of them with an unsupported check, which stops execution before the call.
            let Ok(instance) =
                resolve_call(self.tcx, rustc_internal::stable(func.ty(self.body, self.tcx)))
            else {
                return;
            };
            let instance = rustc_internal::internal(self.tcx, instance);
            match instance.def {
                // Intrinsics could introduce aliasing edges we care about, so need to handle them.
                InstanceKind::Intrinsic(_)
                    if crate::kani_middle::select_unpredictable_fallback(
                        self.tcx,
                        rustc_internal::stable(instance),
                    )
                    .is_some() =>
                {
                    // Follow the same fallback as codegen. Its assignments and returns join
                    // both value arms' referents, without introducing a condition edge or
                    // the address of either caller argument slot.
                    self.apply_regular_call_effect(state, instance, args, destination, location);
                }
                InstanceKind::Intrinsic(_) => {
                    match Intrinsic::from_instance(&rustc_internal::stable(instance)) {
                        intrinsic if is_identity_aliasing_intrinsic(intrinsic.clone()) => {
                            // Treat the intrinsic as an aggregate, taking a union of all of the
                            // arguments' aliases.
                            let destination_set = state.resolve_place(*destination, self.instance);
                            let operands_set = args
                                .into_iter()
                                .flat_map(|operand| {
                                    self.successors_for_operand(state, operand.node.clone())
                                })
                                .collect();
                            state.extend(&destination_set, &operands_set);
                        }
                        // All `atomic_cxchg` intrinsics take `dst, old, src` as arguments.
                        // This is equivalent to `destination = *dst; *dst = src`.
                        Intrinsic::AtomicCxchg | Intrinsic::AtomicCxchgWeak => {
                            let src_set = self.successors_for_operand(state, args[2].node.clone());
                            let dst_set = self.successors_for_deref(state, args[0].node.clone());
                            let destination_set = state.resolve_place(*destination, self.instance);
                            state.extend(&destination_set, &state.successors(&dst_set));
                            state.extend(&dst_set, &src_set);
                        }
                        // All `atomic_load` intrinsics take `src` as an argument.
                        // This is equivalent to `destination = *src`.
                        Intrinsic::AtomicLoad => {
                            let src_set = self.successors_for_deref(state, args[0].node.clone());
                            let destination_set = state.resolve_place(*destination, self.instance);
                            state.extend(&destination_set, &state.successors(&src_set));
                        }
                        // All `atomic_store` intrinsics take `dst, val` as arguments.
                        // This is equivalent to `*dst = val`.
                        Intrinsic::AtomicStore => {
                            let dst_set = self.successors_for_deref(state, args[0].node.clone());
                            let val_set = self.successors_for_operand(state, args[1].node.clone());
                            state.extend(&dst_set, &val_set);
                        }
                        // All other `atomic` intrinsics take `dst, src` as arguments.
                        // This is equivalent to `destination = *dst; *dst = src`.
                        Intrinsic::AtomicAnd
                        | Intrinsic::AtomicMax
                        | Intrinsic::AtomicMin
                        | Intrinsic::AtomicNand
                        | Intrinsic::AtomicOr
                        | Intrinsic::AtomicUmax
                        | Intrinsic::AtomicUmin
                        | Intrinsic::AtomicXadd
                        | Intrinsic::AtomicXchg
                        | Intrinsic::AtomicXor
                        | Intrinsic::AtomicXsub => {
                            let src_set = self.successors_for_operand(state, args[1].node.clone());
                            let dst_set = self.successors_for_deref(state, args[0].node.clone());
                            let destination_set = state.resolve_place(*destination, self.instance);
                            state.extend(&destination_set, &state.successors(&dst_set));
                            state.extend(&dst_set, &src_set);
                        }
                        // Similar to `copy_nonoverlapping`, argument order is `src`, `dst`, `count`.
                        Intrinsic::Copy => {
                            self.apply_copy_effect(
                                state,
                                args[0].node.clone(),
                                args[1].node.clone(),
                            );
                        }
                        Intrinsic::TypedSwap => {
                            // Extend from x_set to y_set and vice-versa so that both x and y alias
                            // to a union of places each of them alias to.
                            let x_set = self.successors_for_deref(state, args[0].node.clone());
                            let y_set = self.successors_for_deref(state, args[1].node.clone());
                            state.extend(&x_set, &state.successors(&y_set));
                            state.extend(&y_set, &state.successors(&x_set));
                        }
                        // Similar to `copy_nonoverlapping`, argument order is `dst`, `src`, `count`.
                        Intrinsic::VolatileCopyMemory
                        | Intrinsic::VolatileCopyNonOverlappingMemory => {
                            self.apply_copy_effect(
                                state,
                                args[1].node.clone(),
                                args[0].node.clone(),
                            );
                        }
                        // Semantically equivalent to dest = *a
                        Intrinsic::VolatileLoad | Intrinsic::UnalignedVolatileLoad => {
                            // Destination of the return value.
                            let lvalue_set = state.resolve_place(*destination, self.instance);
                            let rvalue_set = self.successors_for_deref(state, args[0].node.clone());
                            state.extend(&lvalue_set, &state.successors(&rvalue_set));
                        }
                        // Semantically equivalent *a = b.
                        Intrinsic::VolatileStore | Intrinsic::UnalignedVolatileStore => {
                            let lvalue_set = self.successors_for_deref(state, args[0].node.clone());
                            let rvalue_set =
                                self.successors_for_operand(state, args[1].node.clone());
                            state.extend(&lvalue_set, &rvalue_set);
                        }
                        Intrinsic::Unimplemented { .. } => {
                            // This will be taken care of at the codegen level.
                        }
                        intrinsic => {
                            unimplemented!(
                                "Kani does not support reasoning about aliasing in presence of intrinsic `{intrinsic:?}`. For more information about the state of uninitialized memory checks implementation, see: https://github.com/model-checking/kani/issues/3300."
                            );
                        }
                    }
                }
                _ => {
                    if self.tcx.is_foreign_item(instance.def_id()) {
                        match self
                            .tcx
                            .def_path_str_with_args(instance.def_id(), instance.args)
                            .as_str()
                        {
                            // This is an internal function responsible for heap allocation,
                            // which creates a new node we need to add to the points-to graph.
                            "alloc::alloc::__rust_alloc" | "alloc::alloc::__rust_alloc_zeroed" => {
                                let lvalue_set = state.resolve_place(*destination, self.instance);
                                let rvalue_set = HashSet::from([MemLoc::new_heap_allocation(
                                    self.instance,
                                    location,
                                )]);
                                state.extend(&lvalue_set, &rvalue_set);
                            }
                            _ => {}
                        }
                    } else {
                        // Otherwise, handle this as a regular function call.
                        self.apply_regular_call_effect(
                            state,
                            instance,
                            args,
                            destination,
                            location,
                        );
                    }
                }
            }
        };
    }

    /// We don't care about this and just need to implement this to implement the trait.
    fn apply_call_return_effect(
        &self,
        _state: &mut Self::Domain,
        _block: BasicBlock,
        _return_places: CallReturnPlaces<'_, 'tcx>,
    ) {
    }
}

/// Resolve calls whose effects the uninitialized-memory passes can follow.
/// The local visitor owns the diagnostic on every rejected path, even without delayed-UB seeds.
/// MIR-backed shims may be analyzed, but this does not grant them A3 shadow transfers.
pub fn resolve_call(tcx: TyCtxt, func_ty: StableTy) -> Result<StableInstance, String> {
    let StableTyKind::RigidTy(StableRigidTy::FnDef(def, args)) = func_ty.kind() else {
        return Err(unsupported_call_reason("calls through function pointers"));
    };
    let instance = StableInstance::resolve(def, &args).map_err(|err| {
        format!("Kani could not resolve function item `{func_ty:?}` for memory initialization checks: {err:?}.")
    })?;
    let reason = match instance.kind {
        StableInstanceKind::Intrinsic => return Ok(instance),
        StableInstanceKind::Item if instance.is_foreign_item() => return Ok(instance),
        StableInstanceKind::Item | StableInstanceKind::Shim => {
            // Query actual MIR availability, including empty compiler-generated shims.
            // has_body alone describes the definition rather than the generated instance.
            if crate::kani_middle::checked_body(tcx, instance).is_some() {
                return Ok(instance);
            }
            format!("calls to bodyless {:?} instances", instance.kind)
        }
        StableInstanceKind::Virtual { .. } => "trait object method calls".to_string(),
        StableInstanceKind::LlvmIntrinsic => "calls to LlvmIntrinsic instances".to_string(),
    };
    Err(unsupported_call_reason(&reason))
}

fn unsupported_call_reason(kind: &str) -> String {
    format!(
        "Kani does not support memory initialization checks across {kind}. For more information about planned support, see https://github.com/model-checking/kani/issues/3300."
    )
}

impl<'tcx> PointsToAnalysis<'_, 'tcx> {
    /// Update the analysis state according to the operation, which is semantically equivalent to `*to = *from`.
    fn apply_copy_effect(
        &self,
        state: &mut PointsToGraph<'tcx>,
        from: Operand<'tcx>,
        to: Operand<'tcx>,
    ) {
        let lvalue_set = self.successors_for_deref(state, to);
        let rvalue_set = self.successors_for_deref(state, from);
        state.extend(&lvalue_set, &state.successors(&rvalue_set));
    }

    /// Find all places where the operand could point to at the current stage of the program.
    fn successors_for_operand(
        &self,
        state: &mut PointsToGraph<'tcx>,
        operand: Operand<'tcx>,
    ) -> HashSet<MemLoc<'tcx>> {
        match operand {
            Operand::Copy(place) | Operand::Move(place) => {
                // Find all places which are pointed to by the place.
                state.successors(&state.resolve_place(place, self.instance))
            }
            Operand::Constant(const_operand) => {
                let constant = rustc_internal::stable(const_operand.const_);
                state.constant_successors(self.tcx, &constant)
            }
            // Runtime-check operands (rust-lang/rust#148766) reference no place or static.
            Operand::RuntimeChecks(..) => HashSet::new(),
        }
    }

    /// Find all places where the deref of the operand could point to at the current stage of the program.
    fn successors_for_deref(
        &self,
        state: &mut PointsToGraph<'tcx>,
        operand: Operand<'tcx>,
    ) -> HashSet<MemLoc<'tcx>> {
        match operand {
            Operand::Copy(place) | Operand::Move(place) => state.resolve_place(
                place.project_deeper(&[ProjectionElem::Deref], self.tcx),
                self.instance,
            ),
            Operand::Constant(const_operand) => {
                let constant = rustc_internal::stable(const_operand.const_);
                state.constant_successors(self.tcx, &constant)
            }
            // Runtime-check operands (rust-lang/rust#148766) reference no place or static.
            Operand::RuntimeChecks(..) => HashSet::new(),
        }
    }

    /// Update the analysis state according to the regular function call.
    fn apply_regular_call_effect(
        &self,
        state: &mut PointsToGraph<'tcx>,
        instance: Instance<'tcx>,
        args: &[Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        location: Location,
    ) {
        // Here we simply call another function, so need to retrieve internal body for it.
        let new_body = {
            let stable_instance = rustc_internal::stable(instance);
            // The shared resolver also checks source MIR, so absence is guaranteed to have
            // a local Unsupported check. Preserve the graph accumulated before that call.
            let Some(stable_body) = self
                .body_overrides
                .get(&stable_instance)
                .map(|selected| selected.body.clone())
                .or_else(|| crate::kani_middle::checked_body(self.tcx, stable_instance))
            else {
                return;
            };
            stable_body.internal_mir(self.tcx)
        };

        // In order to be efficient, create a new graph for the function call analysis, which only
        // contains arguments and statics and anything transitively reachable from them.
        let mut initial_graph = PointsToGraph::empty();
        for arg in args.iter() {
            match arg.node {
                Operand::Copy(place) | Operand::Move(place) => {
                    initial_graph
                        .join(&state.transitive_closure(state.resolve_place(place, self.instance)));
                }
                Operand::Constant(_) => {}
                Operand::RuntimeChecks(_) => {}
            }
        }

        // A missing link is the connections between the arguments in the caller and parameters in
        // the callee, add it to the graph.
        if self.tcx.is_closure_like(instance.def.def_id()) {
            // This means we encountered a closure call.
            // Sanity check. The first argument is the closure itself and the second argument is the tupled arguments from the caller.
            assert!(args.len() == 2);
            // First, connect all upvars.
            let lvalue_set = HashSet::from([MemLoc::new_stack_allocation(
                instance,
                Place { local: 1usize.into(), projection: List::empty() },
            )]);
            let rvalue_set = self.successors_for_operand(state, args[0].node.clone());
            initial_graph.extend(&lvalue_set, &rvalue_set);
            // Then, connect the argument tuple to each of the spread arguments.
            let spread_arg_operand = args[1].node.clone();
            for i in 0..new_body.arg_count {
                let lvalue_set = HashSet::from([MemLoc::new_stack_allocation(
                    instance,
                    Place {
                        local: (i + 1).into(), // Since arguments in the callee are starting with 1, account for that.
                        projection: List::empty(),
                    },
                )]);
                // This conservatively assumes all arguments alias to all parameters.
                let rvalue_set = self.successors_for_operand(state, spread_arg_operand.clone());
                initial_graph.extend(&lvalue_set, &rvalue_set);
            }
        } else {
            // Otherwise, simply connect all arguments to parameters.
            for (i, arg) in args.iter().enumerate() {
                let lvalue_set = HashSet::from([MemLoc::new_stack_allocation(
                    instance,
                    Place {
                        local: (i + 1).into(), // Since arguments in the callee are starting with 1, account for that.
                        projection: List::empty(),
                    },
                )]);
                let rvalue_set = self.successors_for_operand(state, arg.node.clone());
                initial_graph.extend(&lvalue_set, &rvalue_set);
            }
        }

        // Resolve the call site as source text, never as Debug MIR/span IDs.
        let call_site = SourceLocation::new(rustc_internal::stable(
            self.body.basic_blocks[location.block].terminator().source_info.span,
        ));
        // Run the analysis.
        let Ok(new_result) = PointsToAnalysis::run(
            &new_body,
            self.tcx,
            instance,
            self.call_graph,
            self.body_overrides,
            self.active_calls,
            initial_graph,
            Some(CallerLocation { file: call_site.filename, line: call_site.start_line }),
        ) else {
            // The shared context carries the error through the dataflow callbacks.
            // In particular, do not join this failed callee's partial graph.
            return;
        };
        // Merge the results into the current state.
        state.join(&new_result);

        // Connect the return value to the return destination.
        let lvalue_set = state.resolve_place(*destination, self.instance);
        let rvalue_set = HashSet::from([MemLoc::new_stack_allocation(
            instance,
            Place { local: 0usize.into(), projection: List::empty() },
        )]);
        state.extend(&lvalue_set, &state.successors(&rvalue_set));
    }

    /// Find all places where the rvalue could point to at the current stage of the program.
    fn successors_for_rvalue(
        &self,
        state: &mut PointsToGraph<'tcx>,
        rvalue: Rvalue<'tcx>,
    ) -> HashSet<MemLoc<'tcx>> {
        match rvalue {
            // Using the operand unchanged requires determining where it could point, which
            // `successors_for_operand` does.
            Rvalue::Use(operand, _)
            | Rvalue::Cast(_, operand, _)
            | Rvalue::Repeat(operand, ..)
            | Rvalue::WrapUnsafeBinder(operand, _) => self.successors_for_operand(state, operand),
            // A `Reborrow` bitwise-copies the place, so it can point wherever that place does.
            Rvalue::Reborrow(_, _, ref_place)
            | Rvalue::Ref(_, _, ref_place)
            | Rvalue::RawPtr(_, ref_place) => {
                // Here, a reference to a place is created, which leaves the place
                // unchanged.
                state.resolve_place(ref_place, self.instance)
            }
            Rvalue::BinaryOp(bin_op, operands) => {
                match bin_op {
                    BinOp::Offset => {
                        // Offsetting a pointer should still be within the boundaries of the
                        // same object, so we can simply use the operand unchanged.
                        let (ptr, _) = *operands.clone();
                        self.successors_for_operand(state, ptr)
                    }
                    BinOp::Add
                    | BinOp::AddUnchecked
                    | BinOp::AddWithOverflow
                    | BinOp::Sub
                    | BinOp::SubUnchecked
                    | BinOp::SubWithOverflow
                    | BinOp::Mul
                    | BinOp::MulUnchecked
                    | BinOp::MulWithOverflow
                    | BinOp::Div
                    | BinOp::Rem
                    | BinOp::BitXor
                    | BinOp::BitAnd
                    | BinOp::BitOr
                    | BinOp::Shl
                    | BinOp::ShlUnchecked
                    | BinOp::Shr
                    | BinOp::ShrUnchecked => {
                        // While unlikely, those could be pointer addresses, so we need to
                        // track them. We assume that even shifted addresses will be within
                        // the same original object.
                        let (l_operand, r_operand) = *operands.clone();
                        let l_operand_set = self.successors_for_operand(state, l_operand);
                        let r_operand_set = self.successors_for_operand(state, r_operand);
                        l_operand_set.union(&r_operand_set).cloned().collect()
                    }
                    BinOp::Eq
                    | BinOp::Lt
                    | BinOp::Le
                    | BinOp::Ne
                    | BinOp::Ge
                    | BinOp::Gt
                    | BinOp::Cmp => {
                        // None of those could yield an address as the result.
                        HashSet::new()
                    }
                }
            }
            Rvalue::UnaryOp(_, operand) => {
                // The same story from BinOp applies here, too. Need to track those things.
                self.successors_for_operand(state, operand)
            }
            Rvalue::Discriminant(..) => {
                // All of those should yield a constant.
                HashSet::new()
            }
            Rvalue::Aggregate(_, operands) => {
                // Conservatively find a union of all places mentioned here and resolve
                // their pointees.
                operands
                    .into_iter()
                    .flat_map(|operand| self.successors_for_operand(state, operand))
                    .collect()
            }
            Rvalue::CopyForDeref(place) => {
                // Resolve pointees of a place.
                state.successors(&state.resolve_place(place, self.instance))
            }
            Rvalue::ThreadLocalRef(def_id) => {
                // We store a def_id of a static.
                HashSet::from([MemLoc::new_static_allocation(def_id)])
            }
        }
    }
}

/// Determines if the intrinsic does not influence aliasing beyond being treated as an identity
/// function (i.e. propagate aliasing without changes).
fn is_identity_aliasing_intrinsic(intrinsic: Intrinsic) -> bool {
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
        | Intrinsic::CompareBytes
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
        | Intrinsic::PtrGuaranteedCmp
        | Intrinsic::PtrOffsetFrom
        | Intrinsic::PtrOffsetFromUnsigned
        | Intrinsic::RawEq
        | Intrinsic::RetagBoxToRaw
        | Intrinsic::RotateLeft
        | Intrinsic::RotateRight
        | Intrinsic::RoundF32
        | Intrinsic::RoundF64
        | Intrinsic::RoundTiesEvenF32
        | Intrinsic::RoundTiesEvenF64
        | Intrinsic::SaturatingAdd
        | Intrinsic::SaturatingSub
        | Intrinsic::SinF32
        | Intrinsic::SinF64
        | Intrinsic::SizeOfVal
        | Intrinsic::SqrtF32
        | Intrinsic::SqrtF64
        | Intrinsic::SubWithOverflow
        | Intrinsic::Transmute
        | Intrinsic::TruncF32
        | Intrinsic::TruncF64
        | Intrinsic::UncheckedDiv
        | Intrinsic::UncheckedRem
        | Intrinsic::Unlikely
        // Same argument shape/semantics as `WriteBytes` below (volatility is not
        // an aliasing concern), so it is likewise identity-aliasing.
        | Intrinsic::VolatileSetMemory
        | Intrinsic::VtableSize
        | Intrinsic::VtableAlign
        | Intrinsic::WrappingAdd
        | Intrinsic::WrappingMul
        | Intrinsic::WrappingSub
        | Intrinsic::WriteBytes => {
            /* Intrinsics that do not interact with aliasing beyond propagating it. */
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

#[cfg(test)]
mod active_call_tests {
    use super::{ActiveCalls, CallerLocation};
    use std::fmt::{self, Display};

    #[derive(PartialEq, Eq)]
    struct TestKey(&'static str, bool);

    impl Display for TestKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{} [override={}]", self.0, self.1)
        }
    }

    #[test]
    fn self_cycle_is_an_error_without_pushing_another_frame() {
        let mut calls = ActiveCalls::new();
        calls.enter(TestKey("A::<u8>", false)).unwrap();
        let error = calls.enter(TestKey("A::<u8>", false)).unwrap_err();
        assert!(error.reason.contains("interprocedural cycle"));
        assert_eq!(calls.stack.len(), 1);
        assert!(calls.exit().is_err());
        assert!(calls.stack.is_empty());
    }

    #[test]
    fn mutual_cycle_retains_original_root_and_active_stack() {
        let mut calls = ActiveCalls::new();
        for name in ["root", "A", "B"] {
            calls.enter(TestKey(name, true)).unwrap();
        }
        let error = calls.enter(TestKey("A", true)).unwrap_err();
        assert!(error.reason.contains("repeats active frame 1"));
        assert!(
            error
                .reason
                .contains("root [override=true] -> frame 1: A [override=true] -> frame 2: B [override=true] -> repeated: A [override=true]")
        );
        // No ancestor may turn a failed child into a successful partial summary.
        for _ in 0..3 {
            assert_eq!(calls.exit().unwrap_err().reason, error.reason);
        }
        assert!(calls.stack.is_empty());
    }

    #[test]
    fn caller_location_is_diagnostic_only_and_survives_repeated_entry() {
        let mut calls = ActiveCalls::new();
        calls.enter("root").unwrap();
        let caller = CallerLocation { file: "src/cycle.rs".into(), line: 42 };
        let error = calls.enter_at("root", Some(caller)).unwrap_err();
        assert!(error.reason.contains("repeats active frame 0"));
        assert!(error.reason.contains("repeated: root [call at src/cycle.rs:42]"));
        assert!(!error.reason.contains("DefId"));
        assert!(!error.reason.contains("AnalysisKey"));
        assert_eq!(calls.stack.len(), 1);
        assert_eq!(calls.callers.len(), 1);
        assert!(calls.exit().is_err());
        assert!(calls.callers.is_empty());
    }

    #[test]
    fn diamond_and_repeated_completed_calls_are_allowed() {
        let mut calls = ActiveCalls::new();
        calls.enter("root").unwrap();
        for branch in ["left", "right", "left"] {
            calls.enter(branch).unwrap();
            calls.enter("leaf").unwrap();
            calls.exit().unwrap();
            calls.exit().unwrap();
        }
        calls.exit().unwrap();
        assert!(calls.stack.is_empty());
        assert!(calls.error.is_none());
    }

    #[test]
    fn exact_instance_and_body_selection_are_part_of_identity() {
        let mut calls = ActiveCalls::new();
        // Synthetic monomorphization/body keys; production uses rustc Instance.
        for key in [("F::<u8>", false), ("F::<u16>", false), ("F::<u8>", true)] {
            calls.enter(TestKey(key.0, key.1)).unwrap();
        }
        for _ in 0..3 {
            calls.exit().unwrap();
        }
    }

    #[test]
    fn discarded_override_has_no_source_body_edges() {
        let mut calls = ActiveCalls::new();
        calls.enter(TestKey("root", false)).unwrap();
        calls.enter(TestKey("discarded", true)).unwrap();
        // An unreachable override is an empty traversal, not its recursive source.
        calls.exit().unwrap();
        calls.exit().unwrap();
    }

    #[test]
    fn independent_roots_in_both_orders_do_not_share_errors() {
        for order in [[true, false], [false, true]] {
            for cyclic in order {
                let mut calls = ActiveCalls::new();
                calls.enter("root").unwrap();
                if cyclic {
                    assert!(calls.enter("root").is_err());
                    assert!(calls.exit().is_err());
                } else {
                    calls.enter("leaf").unwrap();
                    calls.exit().unwrap();
                    calls.exit().unwrap();
                }
                assert!(calls.stack.is_empty());
            }
        }
    }

    #[test]
    fn diagnostic_uses_display_without_exposing_internal_identity() {
        #[derive(PartialEq, Eq)]
        struct OpaqueKey {
            id: usize,
            name: &'static str,
        }

        impl Display for OpaqueKey {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} [provenance=source]", self.name)
            }
        }

        let diagnostic = |id| {
            let mut calls = ActiveCalls::new();
            calls.enter(OpaqueKey { id, name: "cycle::<u8>" }).unwrap();
            calls
                .enter_at(
                    OpaqueKey { id, name: "cycle::<u8>" },
                    Some(CallerLocation { file: "src/cycle.rs".into(), line: 17 }),
                )
                .unwrap_err()
                .reason
        };
        assert_eq!(diagnostic(62), diagnostic(93));
        assert!(
            diagnostic(62)
                .contains("repeated: cycle::<u8> [provenance=source] [call at src/cycle.rs:17]")
        );
        // Readable names are diagnostic only: distinct exact keys still enter.
        let mut calls = ActiveCalls::new();
        calls.enter(OpaqueKey { id: 62, name: "same_name" }).unwrap();
        calls.enter(OpaqueKey { id: 93, name: "same_name" }).unwrap();
        calls.exit().unwrap();
        calls.exit().unwrap();
    }

    #[test]
    fn diagnostic_is_bounded_without_limiting_analysis_depth() {
        let mut calls = ActiveCalls::new();
        for i in 0..100 {
            calls.enter(format!("frame-{i}-{}", "x".repeat(10000))).unwrap();
        }
        let error = calls.enter(format!("frame-50-{}", "x".repeat(10000))).unwrap_err();
        assert!(error.reason.len() < 51000);
        assert!(error.reason.contains("frames omitted"));
        assert!(error.reason.contains("frame truncated"));
        assert!(error.reason.contains("repeats active frame 50"));
        for _ in 0..100 {
            assert!(calls.exit().is_err());
        }
        assert!(calls.stack.is_empty());
    }
}
