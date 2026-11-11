// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Visitor that collects all instructions relevant to uninitialized memory access caused by delayed
//! UB. In practice, that means collecting all instructions where the place is featured.

use crate::kani_middle::{
    points_to::{MemLoc, PointsToGraph, unsupported_call},
    transform::{
        body::{InsertPosition, MutableBody, SourceInstruction},
        check_uninit::{
            PointeeInfo, PointeeLayout, TargetFinder,
            relevant_instruction::{InitRelevantInstruction, MemoryInitOp},
            ty_layout::contains_storage,
        },
    },
};
use rustc_middle::ty::TyCtxt;
use rustc_public::mir::{
    LocalDecl, MirVisitor, Operand, Place, Rvalue, Statement, Terminator, TerminatorKind,
    mono::Instance,
    visit::{Location, PlaceContext},
};
use std::collections::HashSet;

pub struct InstrumentationVisitor<'a, 'tcx> {
    /// All target instructions in the body.
    targets: Vec<InitRelevantInstruction>,
    /// Current analysis target, eventually needs to be added to a list of all targets.
    current_target: InitRelevantInstruction,
    /// Aliasing analysis data.
    points_to: &'a PointsToGraph<'tcx>,
    /// The list of places we should be looking for, ignoring others
    analysis_targets: &'a HashSet<MemLoc<'tcx>>,
    current_instance: Instance,
    /// The locals of the body being visited, to type call operands.
    locals: Vec<LocalDecl>,
    tcx: TyCtxt<'tcx>,
}

impl TargetFinder for InstrumentationVisitor<'_, '_> {
    fn find_all(mut self, body: &MutableBody) -> Vec<InitRelevantInstruction> {
        self.locals = body.locals().to_vec();
        for (bb_idx, bb) in body.blocks().iter().enumerate() {
            self.current_target = InitRelevantInstruction {
                source: if bb.statements.is_empty() {
                    SourceInstruction::Terminator { bb: bb_idx }
                } else {
                    SourceInstruction::Statement { idx: 0, bb: bb_idx }
                },
                before_instruction: vec![],
                after_instruction: vec![],
            };
            if bb_idx == 0 {
                // A typed by-value parameter has fresh stack storage but no MIR assignment.
                // Its caller retains the ordinary operand checks; seed only parameter bytes
                // that this analysis may check. In particular this covers an ordinary
                // IndexRange copied out of IntoIter on the drop path. References/pointers
                // initialize only their own value bytes, never the referenced storage.
                for idx in 1..=body.arg_count() {
                    let ty = self.locals[idx].ty;
                    let place = Place::from(idx);
                    let needs_get = self
                        .points_to
                        .resolve_place_stable(place.clone(), self.current_instance, self.tcx)
                        .intersection(self.analysis_targets)
                        .next()
                        .is_some();
                    if needs_get
                        && !ty.kind().is_union()
                        && !contains_storage(self.tcx, ty)
                        && let Ok(info) = PointeeInfo::from_ty(ty)
                        && let PointeeLayout::Sized { layout } = info.layout()
                    {
                        self.push_target(MemoryInitOp::SetStorage {
                            operand: Operand::Copy(place),
                            initialized: layout.clone(),
                            position: InsertPosition::Before,
                        });
                    }
                }
            }
            self.visit_basic_block(bb);
        }
        self.targets
    }
}

impl<'a, 'tcx> InstrumentationVisitor<'a, 'tcx> {
    pub fn new(
        points_to: &'a PointsToGraph<'tcx>,
        analysis_targets: &'a HashSet<MemLoc<'tcx>>,
        current_instance: Instance,
        tcx: TyCtxt<'tcx>,
    ) -> Self {
        Self {
            targets: vec![],
            current_target: InitRelevantInstruction {
                source: SourceInstruction::Statement { idx: 0, bb: 0 },
                before_instruction: vec![],
                after_instruction: vec![],
            },
            points_to,
            analysis_targets,
            current_instance,
            locals: vec![],
            tcx,
        }
    }

    fn push_target(&mut self, source_op: MemoryInitOp) {
        self.current_target.push_operation(source_op);
    }
}

impl MirVisitor for InstrumentationVisitor<'_, '_> {
    fn visit_statement(&mut self, stmt: &Statement, location: Location) {
        self.super_statement(stmt, location);
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
        // A block can have no statements; retain any entry operations while selecting
        // its terminator rather than a nonexistent statement at index statements.len().
        let bb = match self.current_target.source {
            SourceInstruction::Statement { bb, .. } | SourceInstruction::Terminator { bb } => bb,
        };
        self.current_target.source = SourceInstruction::Terminator { bb };
        // The points-to analysis does not follow these calls, so the aliasing it computed is only
        // valid on paths that do not reach them.
        if let TerminatorKind::Call { func, .. } = &term.kind
            && let Some(reason) = unsupported_call(func.ty(&self.locals).unwrap())
        {
            self.push_target(MemoryInitOp::Unsupported { reason });
        }
        self.super_terminator(term, location);
        // Push the current target from the terminator onto the list.
        self.targets.push(self.current_target.clone());
    }

    fn visit_rvalue(&mut self, rvalue: &Rvalue, location: Location) {
        match rvalue {
            Rvalue::AddressOf(..) | Rvalue::Ref(..) => {
                // These operations are always legitimate for us.
            }
            _ => self.super_rvalue(rvalue, location),
        }
    }

    fn visit_place(&mut self, place: &Place, ptx: PlaceContext, location: Location) {
        let trace_name = crate::kani_middle::trace::enabled()
            .then(|| crate::kani_middle::trace::clip(self.current_instance.name().as_str(), 320));
        let trace_selected = trace_name.as_deref().is_some_and(crate::kani_middle::trace::matches);
        // In order to check whether we should get-instrument the place, see if it resolves to the
        // analysis target.
        let (needs_get, get_witness) = {
            let resolved =
                self.points_to.resolve_place_stable(place.clone(), self.current_instance, self.tcx);
            let witness = resolved.intersection(self.analysis_targets).next();
            (
                witness.is_some(),
                if trace_selected { witness.map(crate::kani_middle::trace::debug) } else { None },
            )
        };

        // In order to check whether we should set-instrument the place, we need to figure out if
        // the place has a common ancestor of the same level with the target.
        //
        // This is needed because instrumenting the place only if it resolves to the target could give
        // false positives in presence of some aliasing relations.
        //
        // Here is a simple example:
        // ```
        // fn foo(val_1: u32, val_2: u32, flag: bool) {
        //   let reference = if flag {
        //     &val_1
        //   } else {
        //     &val_2
        //   };
        //   let _ = *reference;
        // }
        // ```
        // It yields the following aliasing graph:
        //
        // `val_1 <-- reference --> val_2`
        //
        // If `val_1` is a legitimate instrumentation target, we would get-instrument an instruction
        // that reads from `*reference`, but that could mean that `val_2` is checked, too. Hence,
        // if we don't set-instrument `val_2` we will get a false-positive.
        //
        // See `tests/expected/uninit/delayed-ub-overapprox.rs` for a more specific example.
        let (needs_set, set_witness) = {
            let mut has_common_ancestor = false;
            let mut set_witness = None;
            let mut self_ancestors =
                self.points_to.resolve_place_stable(place.clone(), self.current_instance, self.tcx);
            let mut target_ancestors = self.analysis_targets.clone();

            // The points-to graph can contain cycles (the analysis is field- and
            // context-insensitive, so e.g. a `Vec` can end up "pointing to" itself), in which
            // case the ancestor sets never become empty and this walk used to loop forever. Each
            // iteration is a deterministic function of the current pair of sets, so once a pair
            // repeats, no new intersection can be found: stop and report no common ancestor,
            // which is the answer the walk gives on every graph where it terminates.
            let mut visited_pairs = Vec::new();
            while !self_ancestors.is_empty() || !target_ancestors.is_empty() {
                if let Some(common_ancestor) = self_ancestors.intersection(&target_ancestors).next()
                {
                    has_common_ancestor = true;
                    if trace_selected {
                        set_witness = Some(crate::kani_middle::trace::debug(&common_ancestor));
                    }
                    break;
                }
                let state = (self_ancestors, target_ancestors);
                if visited_pairs.contains(&state) {
                    break;
                }
                self_ancestors = self.points_to.ancestors(&state.0);
                target_ancestors = self.points_to.ancestors(&state.1);
                visited_pairs.push(state);
            }

            (has_common_ancestor, set_witness)
        };

        if trace_selected {
            crate::kani_middle::trace::event(
                "relevance",
                serde_json::json!({
                    "instance": trace_name.as_deref().unwrap_or_default(),
                    "location": crate::kani_middle::trace::debug(&location),
                    "place": crate::kani_middle::trace::debug(&place),
                    "needs_get": needs_get,
                    "get_witness": get_witness,
                    "needs_set": needs_set,
                    "set_witness": set_witness,
                    "decision": if ptx.is_mutating() && needs_set { "select_set_ref" }
                        else if !ptx.is_mutating() && needs_get { "select_check_ref" }
                        else if ptx.is_mutating() { "skip_no_common_ancestor" }
                        else { "skip_not_target" },
                }),
            );
        }

        // If we are mutating the place, initialize it.
        if ptx.is_mutating() && needs_set {
            self.push_target(MemoryInitOp::SetRef {
                operand: Operand::Copy(place.clone()),
                value: true,
                position: InsertPosition::After,
            });
        } else if !ptx.is_mutating() && needs_get {
            // Otherwise, check its initialization.
            self.push_target(MemoryInitOp::CheckRef { operand: Operand::Copy(place.clone()) });
        }
        self.super_place(place, ptx, location)
    }
}
