// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Global transformation pass that injects checks that catch delayed UB caused by uninitialized memory.

use std::collections::HashMap;
use std::collections::HashSet;

use crate::args::ExtraChecks;
use crate::kani_middle::attributes::KaniAttributes;
use crate::kani_middle::kani_functions::{KaniFunction, KaniModel};
use crate::kani_middle::{
    points_to::{
        AnalysisBodyOverride, BodyProvenance, MemLoc, PointsToGraph, run_points_to_analysis,
    },
    reachability::CallGraph,
    transform::{
        BodyTransformation, GlobalPass, TransformationResult,
        body::{CheckType, InsertPosition, MutableBody, SourceInstruction},
        check_uninit::UninitInstrumenter,
    },
};
use crate::kani_queries::QueryDb;
use initial_target_visitor::{AnalysisTarget, InitialTargetVisitor};
use instrumentation_visitor::InstrumentationVisitor;
use rustc_middle::ty::TyCtxt;
use rustc_mir_dataflow::JoinSemiLattice;
use rustc_public::{
    mir::mono::{Instance, MonoItem},
    mir::{MirVisitor, TerminatorKind},
    ty::FnDef,
};
use rustc_session::config::OutputType;

mod initial_target_visitor;
mod instrumentation_visitor;

#[derive(Debug, Clone)]
pub struct DelayedUbPass {
    pub safety_check_type: CheckType,
    pub unsupported_check_type: CheckType,
    pub mem_init_fn_cache: HashMap<KaniFunction, FnDef>,
}

impl DelayedUbPass {
    pub fn new(
        safety_check_type: CheckType,
        unsupported_check_type: CheckType,
        queries: &QueryDb,
    ) -> Self {
        Self {
            safety_check_type,
            unsupported_check_type,
            mem_init_fn_cache: queries.kani_functions().clone(),
        }
    }
}

impl GlobalPass for DelayedUbPass {
    fn is_enabled(&self, query_db: &QueryDb) -> bool {
        let args = query_db.args();
        args.ub_check.contains(&ExtraChecks::Uninit)
    }

    fn transform(
        &mut self,
        tcx: TyCtxt,
        call_graph: &CallGraph,
        starting_items: &[MonoItem],
        instances: Vec<Instance>,
        transformer: &mut BodyTransformation,
    ) -> bool {
        let mut modified = false;
        // Collect all analysis targets (pointers to places reading and writing from which should be
        // tracked).
        let targets: HashSet<_> = instances
            .iter()
            .flat_map(|instance| {
                let body = instance.body().unwrap();
                let mut visitor = InitialTargetVisitor::new(body.clone(), tcx);
                visitor.visit_body(&body);
                // Convert all places into the format of aliasing graph for later comparison.
                visitor.into_targets().into_iter().map(move |analysis_target| match analysis_target
                {
                    AnalysisTarget::Place(place) => {
                        MemLoc::from_stable_stack_allocation(*instance, place, tcx)
                    }
                    AnalysisTarget::Anonymous(key) => MemLoc::Anonymous(key),
                    AnalysisTarget::Static(static_def) => {
                        MemLoc::from_stable_static_allocation(static_def, tcx)
                    }
                })
            })
            .collect();

        // Only perform this analysis if there is something to analyze.
        if !targets.is_empty() {
            // The source register function only panics; the contract pass replaces it with
            // the closure call. Following the source body loses the generated body's alias
            // edges, hence its normal-return setters. Use the emitted trampoline, and keep
            // discarded closures unreachable so analysis cannot re-enter unused contracts.
            // Other bodies retain the existing analysis path; do not analyze injected checks.
            let mut body_overrides = HashMap::new();
            for instance in &instances {
                let body = transformer.body_ref(tcx, *instance);
                let is_registration = KaniAttributes::for_instance(tcx, *instance)
                    .fn_marker()
                    .is_some_and(|marker| marker.as_str() == "kani_register_contract");
                let is_discarded_closure = instance.ty().kind().is_closure()
                    && body.blocks.len() == 1
                    && body.blocks[0].statements.is_empty()
                    && matches!(body.blocks[0].terminator.kind, TerminatorKind::Unreachable);
                if is_registration || is_discarded_closure {
                    let provenance = if is_registration {
                        let run = self.mem_init_fn_cache[&KaniModel::RunContract.into()];
                        let origin = Instance::resolve(run, &instance.args()).unwrap();
                        BodyProvenance::RegistrationOverride(origin)
                    } else {
                        BodyProvenance::DiscardedClosureOverride
                    };
                    body_overrides
                        .insert(*instance, AnalysisBodyOverride { body: body.clone(), provenance });
                }
            }
            let mut analysis_targets = HashSet::new();
            let mut global_points_to_graph = PointsToGraph::empty();
            let mut unsupported_roots = Vec::new();
            // Analyze aliasing for every harness.
            for entry_item in starting_items {
                // Convert each entry function into instance, if possible.
                let entry_fn = match entry_item {
                    MonoItem::Fn(instance) => Some(*instance),
                    MonoItem::Static(static_def) => {
                        let instance: Instance = (*static_def).into();
                        instance.has_body().then_some(instance)
                    }
                    MonoItem::GlobalAsm(_) => None,
                };
                if let Some(instance) = entry_fn {
                    let body = body_overrides
                        .get(&instance)
                        .map(|selected| selected.body.clone())
                        .unwrap_or_else(|| instance.body().unwrap());
                    match run_points_to_analysis(&body, tcx, instance, call_graph, &body_overrides)
                    {
                        Ok(results) => {
                            global_points_to_graph.join(&results);
                        }
                        Err(error) => unsupported_roots.push((instance, error)),
                    }
                }
            }

            // Since analysis targets are *pointers*, need to get its successors for instrumentation.
            analysis_targets.extend(global_points_to_graph.successors(&targets));
            // Anonymous constant targets already denote their referent, not a stack pointer.
            analysis_targets.extend(
                targets.iter().filter(|target| matches!(target, MemLoc::Anonymous(_))).copied(),
            );

            // If we are generating MIR, generate the points-to graph as well.
            if tcx.sess.opts.output_types.contains_key(&OutputType::Mir) {
                global_points_to_graph.dump("points-to.dot");
            }

            // Instrument each instance based on the final targets we found.
            for instance in instances {
                // Retrieve the body with all local instrumentation passes applied.
                let body = transformer.body(tcx, instance);
                // Instrument for delayed UB.
                let target_finder = InstrumentationVisitor::new(
                    &global_points_to_graph,
                    &analysis_targets,
                    instance,
                    tcx,
                );
                let (instrumentation_added, body) = UninitInstrumenter::run(
                    tcx,
                    body,
                    instance,
                    self.safety_check_type.clone(),
                    self.unsupported_check_type.clone(),
                    &mut self.mem_init_fn_cache,
                    target_finder,
                );
                // If some instrumentation has been performed, update the cached body in the local transformer.
                if instrumentation_added {
                    modified = true;
                    transformer.cache.entry(instance).and_modify(|transformation_result| {
                        *transformation_result = TransformationResult(body, true);
                    });
                }
            }

            // Insert at the failed entry root, AFTER ordinary instrumentation. No
            // partial summary was merged, and no shared callee is globally blocked.
            // Continue processing other roots rather than issuing a compiler error.
            for (instance, error) in unsupported_roots {
                let mut body = MutableBody::from(transformer.body(tcx, instance));
                let mut source = if body.blocks()[0].statements.is_empty() {
                    SourceInstruction::Terminator { bb: 0 }
                } else {
                    SourceInstruction::Statement { bb: 0, idx: 0 }
                };
                body.insert_check(
                    &self.unsupported_check_type,
                    &mut source,
                    InsertPosition::Before,
                    None,
                    &error.reason,
                );
                transformer.cache.insert(instance, TransformationResult(body.into(), true));
                modified = true;
            }
        }
        modified
    }
}
