// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Immutable byte masks belong to one GotocCtx/exported model. They are applied once, at each
//! reset completion, never when a pointer is used or when a transfer has moved the witness.

use super::GotocCtx;
use crate::args::ExtraChecks;
use crate::kani_middle::anonymous_allocations::{
    AnonymousOrigin, anonymous_origins, target_matches,
};
use crate::kani_middle::kani_functions::KaniModel;
use cbmc::InternedString;
use cbmc::goto_program::{
    DatatypeComponent, Expr, Location, Stmt, StmtBody, SwitchCase, SymbolValues, Type,
};
use rustc_public::mir::{
    ConstOperand, MirVisitor, Mutability,
    alloc::AllocId,
    mono::{Instance, MonoItem},
    visit::Location as MirLocation,
};
use rustc_public::ty::{Allocation, GenericArgs, MirConst};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Descriptor {
    allocation: Allocation,
    mask: Vec<bool>,
    frozen: bool,
    /// One byte array, field zero at offset zero, with no implicit/tail padding.
    layout: Vec<(u64, u64)>,
}

#[derive(Default)]
pub struct ImmutableAllocations {
    origins: HashMap<AllocId, Vec<AnonymousOrigin>>,
    bindings: HashMap<AllocId, InternedString>,
    allocations: HashMap<AllocId, Allocation>,
    symbols: BTreeMap<InternedString, Descriptor>,
    sealed: bool,
}

impl Descriptor {
    fn new(allocation: Allocation, frozen: bool) -> Self {
        Self {
            mask: allocation.bytes.iter().map(Option::is_some).collect(),
            layout: vec![(0, allocation.bytes.len() as u64)],
            allocation,
            frozen,
        }
    }

    fn admitted(&self) -> bool {
        self.frozen
            && self.allocation.mutability == Mutability::Not
            && self.allocation.provenance.ptrs.is_empty()
    }
}

impl ImmutableAllocations {
    /// A compatible alias retains the first descriptor; conflict is never OR/intersection/overwrite.
    fn register(
        &mut self,
        symbol: InternedString,
        descriptor: Descriptor,
    ) -> Result<(), Descriptor> {
        if let Some(previous) = self.symbols.get(&symbol) {
            if previous != &descriptor && (previous.admitted() || descriptor.admitted()) {
                return Err(previous.clone());
            }
        } else {
            self.symbols.insert(symbol, descriptor);
        }
        Ok(())
    }
}

impl GotocCtx<'_, '_> {
    pub fn observe_immutable_origins(&mut self, constant: &MirConst) {
        if !self.queries.args().ub_check.contains(&ExtraChecks::Uninit) {
            return;
        }
        assert!(
            !self.immutable_allocations.sealed,
            "anonymous allocation after immutable registry seal"
        );
        for origin in anonymous_origins(self.tcx, constant) {
            let origins = self.immutable_allocations.origins.entry(origin.key).or_default();
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }

    /// Collect typed origins before emission order can erase a reference type. The original
    /// monomorphic bodies supply source provenance; this does not change the shared body cache.
    pub fn prepare_immutable_allocations(&mut self, items: &[MonoItem]) {
        if !self.queries.args().ub_check.contains(&ExtraChecks::Uninit) {
            return;
        }
        for item in items {
            let instance = match item {
                MonoItem::Fn(instance) => *instance,
                MonoItem::Static(def) => Instance::from(*def),
                MonoItem::GlobalAsm(_) => continue,
            };
            if let Some(body) = instance.body() {
                // Use a small collector without retaining any body/cache state in the registry.
                let mut constants = ConstantCollector::default();
                constants.visit_body(&body);
                for constant in constants.0 {
                    self.observe_immutable_origins(&constant);
                }
            }
        }
    }

    /// Called on insertion AND reuse, with the address actually returned by alloc_map. The key
    /// is deliberately separate from Allocation equality (including Option bytes before zero fill).
    pub fn bind_immutable_allocation(
        &mut self,
        key: AllocId,
        allocation: &Allocation,
        address: &Expr,
    ) {
        if !self.queries.args().ub_check.contains(&ExtraChecks::Uninit) {
            return;
        }
        if self.immutable_allocations.sealed {
            self.tcx
                .dcx()
                .fatal(format!("immutable allocation {key:?} materialized after model seal"));
        }
        let cbmc::goto_program::ExprValue::AddressOf(object) = address.value() else {
            self.tcx
                .dcx()
                .fatal(format!("anonymous allocation {key:?} has no direct symbol address"));
        };
        let cbmc::goto_program::ExprValue::Symbol { identifier: symbol } = object.value() else {
            self.tcx.dcx().fatal(format!("anonymous allocation {key:?} has no canonical symbol"));
        };
        if let Some(previous) = self.immutable_allocations.bindings.insert(key, *symbol)
            && previous != *symbol
        {
            self.tcx
                .dcx()
                .fatal(format!("anonymous allocation {key:?} rebound from {previous} to {symbol}"));
        }
        if let Some(previous) = self.immutable_allocations.allocations.get(&key) {
            if previous != allocation {
                self.tcx.dcx().fatal(format!(
                    "anonymous allocation {key:?} descriptor changed during emission"
                ));
            }
        } else {
            self.immutable_allocations.allocations.insert(key, allocation.clone());
        }
    }

    /// Seal only after every producer/contract/quantifier pass and before metadata snapshots/export.
    pub fn finalize_immutable_allocations(&mut self) {
        if !self.queries.args().ub_check.contains(&ExtraChecks::Uninit) {
            return;
        }
        self.immutable_allocations.sealed = true;
        // Qualify only after closure: typed origins can be discovered after a coalesced symbol
        // was first requested through an erased view. Rebuild from every requested key and compare
        // full descriptors, so item order cannot turn missing evidence into a seed.
        let bindings: Vec<_> = self
            .immutable_allocations
            .bindings
            .iter()
            .map(|(key, symbol)| (*key, *symbol))
            .collect();
        for (key, symbol) in bindings {
            let allocation = self.immutable_allocations.allocations[&key].clone();
            let source = self.immutable_allocations.origins.get(&key).and_then(|origins| {
                origins.iter().find(|o| o.allocation == allocation && o.frozen_origin.is_some())
            });
            let descriptor = Descriptor::new(allocation, source.is_some());
            if let Some(source) = source {
                assert_eq!(descriptor.mask, source.mask, "source mask changed during emission");
            }
            if let Err(previous) = self.immutable_allocations.register(symbol, descriptor.clone()) {
                let first_byte = previous
                    .allocation
                    .bytes
                    .iter()
                    .zip(&descriptor.allocation.bytes)
                    .position(|(a, b)| a != b);
                self.tcx.dcx().fatal(format!("conflicting immutable descriptors: symbol {symbol}, requested {key:?}, lengths {} / {}, first byte difference {first_byte:?}, mutability {:?} / {:?}, freeze {} / {}, relocation counts {} / {}, layouts {:?} / {:?}", previous.mask.len(), descriptor.mask.len(), previous.allocation.mutability, descriptor.allocation.mutability, previous.frozen, descriptor.frozen, previous.allocation.provenance.ptrs.len(), descriptor.allocation.provenance.ptrs.len(), previous.layout, descriptor.layout));
            }
        }
        let model = self.symbol_table.machine_model();
        if !target_matches(model.pointer_width, model.is_big_endian) {
            self.tcx.dcx().fatal("immutable masks: rustc/backend target disagreement");
        }
        let seeds: Vec<_> = self
            .immutable_allocations
            .symbols
            .iter()
            .filter(|(_, d)| d.admitted() && !d.mask.is_empty())
            .map(|(symbol, descriptor)| (*symbol, descriptor.clone()))
            .collect();
        if seeds.is_empty() {
            return;
        }

        let reset_def = *self
            .queries
            .kani_functions()
            .get(&KaniModel::InitializeMemoryInitializationState.into())
            .unwrap_or_else(|| self.tcx.dcx().fatal("immutable masks: missing reset marker"));
        let reset = Instance::resolve(reset_def, &GenericArgs(vec![]))
            .unwrap_or_else(|_| self.tcx.dcx().fatal("immutable masks: unresolved reset marker"));
        let reset_name = reset.mangled_name();
        let reset_symbol = self.symbol_table.lookup(&reset_name).unwrap_or_else(|| {
            self.tcx.dcx().fatal("immutable masks: reset is absent from this model")
        });
        let SymbolValues::Stmt(body) = &reset_symbol.value else {
            self.tcx.dcx().fatal("immutable masks: reset has no definition in this model");
        };
        let body = body.clone();
        let mut crates = rustc_public::find_crates("kani");
        if crates.is_empty() {
            crates.extend(rustc_public::find_crates("core"));
        }
        let states: Vec<_> = crates
            .into_iter()
            .flat_map(|krate| krate.statics())
            .filter(|def| {
                crate::kani_middle::attributes::fn_marker(*def).as_deref()
                    == Some("KaniMemoryInitializationState")
            })
            .map(|def| Instance::from(def).mangled_name())
            .filter(|name| self.symbol_table.lookup(name).is_some())
            .collect();
        if states.len() != 1 {
            self.tcx.dcx().fatal("immutable masks: ambiguous/missing private state in this model");
        }
        let state = self.symbol_table.lookup(&states[0]).unwrap().to_expr();
        let object = state.clone().member("tracked_object_id", &self.symbol_table);
        let offset = state.clone().member("tracked_offset", &self.symbol_table);
        let value = state.member("value", &self.symbol_table);
        if object.typ() != &Type::size_t()
            || offset.typ() != &Type::size_t()
            || value.typ() != &Type::c_bool()
        {
            self.tcx.dcx().fatal("immutable masks: incompatible private state fields");
        }
        let mut seed_stmts = vec![];
        for (name, descriptor) in seeds {
            let symbol = self.symbol_table.lookup(name).unwrap();
            let n = descriptor.mask.len();
            if n as u128
                > rustc_public::target::MachineInfo::target_pointer_width()
                    .unsigned_int_max()
                    .unwrap_or(u128::MAX)
            {
                self.tcx
                    .dcx()
                    .fatal(format!("immutable masks: extent for {name} exceeds target usize"));
            }
            // The admitted emitter is exactly one [u8; n] field. Validate the actual returned
            // symbol, including a cache hit into a previously emitted object.
            let Type::StructTag(tag) = &symbol.typ else {
                self.tcx
                    .dcx()
                    .fatal(format!("immutable masks: {name} is not byte-exact allocation storage"));
            };
            let Type::Struct { components, .. } = &self.symbol_table.lookup(*tag).unwrap().typ
            else {
                self.tcx.dcx().fatal(format!("immutable masks: incomplete layout for {name}"));
            };
            let expected = vec![DatatypeComponent::field("0", Type::unsigned_int(8).array_of(n))];
            if descriptor.layout != vec![(0, n as u64)]
                || *components != expected
                || symbol.typ.sizeof(&self.symbol_table) != n as u64
                || !symbol.is_static_lifetime
                || !symbol.is_static_const
                || symbol.is_extern
                || symbol.is_thread_local
            {
                self.tcx
                    .dcx()
                    .fatal(format!("immutable masks: noncanonical layout/lifetime for {name}"));
            }
            let base = symbol.to_expr().address_of();
            let in_object =
                object.clone().eq(base.clone().pointer_object().cast_to(object.typ().clone()));
            let at_base = base.pointer_offset().eq(Expr::int_constant(0, Type::ssize_t()));
            let in_range = offset.clone().lt(Expr::int_constant(n, offset.typ().clone()));
            // No addition can overflow, and the index is evaluated only inside 0 <= offset < n.
            let mask = Expr::array_expr(
                value.typ().clone().array_of(n),
                descriptor.mask.into_iter().map(Expr::c_bool_constant).collect(),
            );
            let assign = Stmt::assign(value.clone(), mask.index(offset.clone()), Location::none());
            seed_stmts.push(Stmt::if_then_else(
                in_object.and(at_base).and(in_range),
                assign,
                None,
                Location::none(),
            ));
        }
        let mut completions = 0;
        let patched = seed_returns(&body, &seed_stmts, &mut completions);
        if completions == 0 {
            self.tcx.dcx().fatal("immutable masks: reset has no normal completion");
        }
        self.symbol_table.lookup_mut(reset_name).unwrap().update(SymbolValues::Stmt(patched));
    }
}

#[derive(Default)]
struct ConstantCollector(Vec<MirConst>);
impl MirVisitor for ConstantCollector {
    fn visit_const_operand(&mut self, constant: &ConstOperand, _: MirLocation) {
        self.0.push(constant.const_.clone());
    }
}

/// Preserve every original reset instruction and control edge, inserting immediately before each
/// normal return. Gotos still target the original labels, including a labeled return block.
fn seed_returns(stmt: &Stmt, seeds: &[Stmt], count: &mut usize) -> Stmt {
    let loc = *stmt.location();
    match stmt.body() {
        StmtBody::Return(_) => {
            *count += 1;
            Stmt::block(seeds.iter().cloned().chain([stmt.clone()]).collect(), loc)
        }
        StmtBody::Block(stmts) => {
            Stmt::block(stmts.iter().map(|s| seed_returns(s, seeds, count)).collect(), loc)
        }
        StmtBody::Label { label, body } => seed_returns(body, seeds, count).with_label(*label),
        StmtBody::Ifthenelse { i, t, e } => Stmt::if_then_else(
            i.clone(),
            seed_returns(t, seeds, count),
            e.as_ref().map(|s| seed_returns(s, seeds, count)),
            loc,
        ),
        StmtBody::Switch { control, cases, default } => Stmt::switch(
            control.clone(),
            cases
                .iter()
                .map(|c| SwitchCase::new(c.case().clone(), seed_returns(c.body(), seeds, count)))
                .collect(),
            default.as_ref().map(|s| seed_returns(s, seeds, count)),
            loc,
        ),
        StmtBody::While { cond, body } => {
            Stmt::while_loop(cond.clone(), seed_returns(body, seeds, count), loc)
        }
        StmtBody::For { init, cond, update, body } => Stmt::for_loop(
            seed_returns(init, seeds, count),
            cond.clone(),
            seed_returns(update, seeds, count),
            seed_returns(body, seeds, count),
            loc,
        ),
        StmtBody::AtomicBlock(_) => panic!("immutable masks: unexpected atomic reset body"),
        _ => stmt.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_public::ty::ProvenanceMap;

    fn descriptor(bytes: Vec<Option<u8>>, mutability: Mutability, frozen: bool) -> Descriptor {
        Descriptor::new(
            Allocation { bytes, provenance: ProvenanceMap { ptrs: vec![] }, align: 1, mutability },
            frozen,
        )
    }

    #[test]
    fn zero_is_initialized_hole_is_not() {
        let d = descriptor(vec![Some(0), None, Some(0)], Mutability::Not, true);
        assert_eq!(d.mask, [true, false, true]);
        assert!(d.admitted());
    }

    #[test]
    fn compatible_reuse_and_conflict_preserve_first_descriptor() {
        let mut registry = ImmutableAllocations::default();
        let symbol = "immutable-mask-unit-test".into();
        let original = descriptor(vec![Some(0), None], Mutability::Not, true);
        assert!(registry.register(symbol, original.clone()).is_ok());
        assert!(registry.register(symbol, original.clone()).is_ok());
        assert_eq!(registry.symbols.len(), 1);
        let conflict = descriptor(vec![None, Some(0)], Mutability::Not, true);
        assert!(registry.register(symbol, conflict).is_err());
        assert_eq!(registry.symbols[&symbol], original);
    }

    #[test]
    fn mutable_or_unqualified_is_not_admitted() {
        assert!(!descriptor(vec![Some(0)], Mutability::Mut, true).admitted());
        assert!(!descriptor(vec![Some(0)], Mutability::Not, false).admitted());
    }

    #[test]
    fn seed_preserves_labeled_reset_completion_and_original_edges() {
        let loc = Location::none();
        let original_reset =
            Stmt::assign(Expr::symbol_expression("state", Type::c_bool()), Expr::c_false(), loc);
        let seed =
            Stmt::assign(Expr::symbol_expression("state", Type::c_bool()), Expr::c_true(), loc);
        let body = Stmt::block(
            vec![original_reset, Stmt::goto("done", loc), Stmt::ret(None, loc).with_label("done")],
            loc,
        );
        let mut count = 0;
        let patched = seed_returns(&body, &[seed], &mut count);
        assert_eq!(count, 1);
        let StmtBody::Block(stmts) = patched.body() else { panic!("missing reset block") };
        assert!(
            matches!(stmts[0].body(), StmtBody::Assign { rhs, .. } if matches!(rhs.value(), cbmc::goto_program::ExprValue::CBoolConstant(false)))
        );
        assert!(matches!(stmts[1].body(), StmtBody::Goto { dest, .. } if *dest == "done"));
        let StmtBody::Label { label, body } = stmts[2].body() else { panic!("lost return label") };
        assert_eq!(*label, "done");
        let StmtBody::Block(completion) = body.body() else { panic!("missing completion block") };
        assert!(
            matches!(completion[0].body(), StmtBody::Assign { rhs, .. } if matches!(rhs.value(), cbmc::goto_program::ExprValue::CBoolConstant(true)))
        );
        assert!(matches!(completion[1].body(), StmtBody::Return(None)));
    }

    #[test]
    fn empty_mask_has_no_seed_index_or_object_query() {
        let d = descriptor(vec![], Mutability::Not, true);
        assert!(d.admitted());
        assert!(d.mask.is_empty());
    }
}
