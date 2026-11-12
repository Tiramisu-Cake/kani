// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::codegen_cprover_gotoc::{
    GotocCtx,
    codegen::{ty_stable::pointee_type_stable, typ},
};
use crate::kani_middle::attributes::KaniAttributes;
use cbmc::goto_program::FunctionContract;
use cbmc::goto_program::{Expr, Lambda, Location, Type};
use kani_metadata::AssignsContract;
use rustc_hir::def_id::DefId as InternalDefId;
use rustc_public::CrateDef;
use rustc_public::mir::mono::{Instance, MonoItem};
use rustc_public::mir::{Local, VarDebugInfoContents};
use rustc_public::rustc_internal;
use rustc_public::ty::{FnDef, RigidTy, TyKind};

impl GotocCtx<'_, '_> {
    /// Given the `proof_for_contract` target `function_under_contract` and the reachable `items`,
    /// find or create the `AssignsContract` that needs to be enforced and attach it to the symbol
    /// for which it needs to be enforced.
    ///
    /// 1. Gets the `#[kanitool::modifies_wrapper = "..."]` target, then resolves exactly one
    ///    instance of it. Panics if there are more or less than one instance.
    /// 2. The additional arguments for the inner checks are locations that may be modified.
    ///    Add them to the list of CBMC's assigns.
    /// 3. Returns the mangled name of the symbol it attached the contract to.
    /// 4. Returns the full path to the static marked with `#[kanitool::recursion_tracker]` which
    ///    is passed to the `--nondet-static-exclude` argument.
    ///    This flag expects the file path that `checked_with` is located in, the name of the
    ///    `checked_with` function and the name of the constant (`REENTRY`).
    pub fn handle_check_contract(
        &mut self,
        function_under_contract: InternalDefId,
        items: &[MonoItem],
    ) -> AssignsContract {
        let tcx = self.tcx;
        let modify = items
            .iter()
            .find_map(|item| {
                // Find the instance under contract
                let MonoItem::Fn(instance) = *item else { return None };
                if rustc_internal::internal(tcx, instance.def.def_id()) == function_under_contract {
                    self.find_modifies(instance)
                } else {
                    None
                }
            })
            .unwrap();
        self.attach_modifies_contract(modify);
        let recursion_tracker = self.find_recursion_tracker(items);
        AssignsContract { recursion_tracker, contracted_function_name: modify.mangled_name() }
    }

    /// The name and location for the recursion tracker should match the exact information added
    /// to the symbol table, otherwise our contract instrumentation will silently failed.
    /// This happens because Kani relies on `--nondet-static-exclude` from CBMC to properly
    /// handle this tracker. CBMC silently fails if there is no match in the symbol table
    /// that correspond to the argument of this flag.
    /// More details at https://github.com/model-checking/kani/pull/3045.
    ///
    /// We must use the pretty name of the tracker instead of the mangled name.
    /// This restriction comes from `--nondet-static-exclude` in CBMC.
    /// Mode details at https://github.com/diffblue/cbmc/issues/8225.
    fn find_recursion_tracker(&mut self, items: &[MonoItem]) -> Option<String> {
        // Return item tagged with `#[kanitool::recursion_tracker]`
        let mut recursion_trackers = items.iter().filter_map(|item| {
            let MonoItem::Static(static_item) = item else { return None };
            if !static_item.tool_attrs(&["kanitool".into(), "recursion_tracker".into()]).is_empty()
            {
                let span = static_item.span();
                let loc = self.codegen_span_stable(span);
                Some(format!(
                    "{}:{}",
                    loc.filename().expect("recursion location wrapper should have a file name"),
                    // The `--nondet-static-exclude` value must match the static's
                    // pretty name in the goto model. Since rust-lang/rust#149401,
                    // `name()` is crate-qualified for local items, but the pretty
                    // name is kept crate-relative (see `readable_name`), so strip
                    // the crate prefix here too; otherwise the recursion tracker
                    // `REENTRY` is not excluded from `--nondet-static` and gets
                    // havocked, breaking contract-recursion checking.
                    crate::kani_middle::strip_local_crate_prefix(static_item.name()),
                ))
            } else {
                None
            }
        });

        let recursion_tracker = recursion_trackers.next();
        assert!(
            recursion_trackers.next().is_none(),
            "Expected up to one recursion tracker (`REENTRY`) in scope"
        );
        recursion_tracker
    }

    /// Find the modifies recursively since we may have a recursion wrapper.
    /// I.e.: [recursion_wrapper ->]? check -> modifies.
    fn find_modifies(&mut self, instance: Instance) -> Option<Instance> {
        let contract_attrs =
            KaniAttributes::for_instance(self.tcx, instance).contract_attributes()?;
        let mut find_closure = |inside: Instance, name: &str| {
            let body = self.transformer.body_ref(self.tcx, inside);
            body.var_debug_info.iter().find_map(|var_info| {
                if var_info.name.as_str() == name {
                    let ty = match &var_info.value {
                        VarDebugInfoContents::Place(place) => place.ty(body.locals()).unwrap(),
                        VarDebugInfoContents::Const(const_op) => const_op.ty(),
                    };
                    if let TyKind::RigidTy(RigidTy::Closure(def, args)) = ty.kind() {
                        return Some(Instance::resolve(FnDef(def.def_id()), &args).unwrap());
                    }
                }
                None
            })
        };
        let check_instance = if contract_attrs.has_recursion {
            let recursion_check = find_closure(instance, contract_attrs.recursion_check.as_str())?;
            find_closure(recursion_check, contract_attrs.checked_with.as_str())?
        } else {
            find_closure(instance, contract_attrs.checked_with.as_str())?
        };
        find_closure(check_instance, contract_attrs.modifies_wrapper.as_str())
    }

    /// Convert the Kani level contract into a CBMC level contract by creating a
    /// CBMC lambda.
    fn codegen_modifies_contract(
        &mut self,
        goto_annotated_fn_name: &str,
        modifies: Instance,
        loc: Location,
    ) -> FunctionContract {
        let goto_annotated_fn_typ = self
            .symbol_table
            .lookup(goto_annotated_fn_name)
            .unwrap_or_else(|| panic!("Function '{goto_annotated_fn_name}' is not declared"))
            .typ
            .clone();

        // Resolve only the two exact verifier-private static identities, matching
        // declare_static/codegen_static. The transfer snapshot has scalar targets:
        // no runtime protocol operation writes its whole record or padding.
        let shadow_memory_assign = {
            let mut crates = rustc_public::find_crates("kani");
            if crates.is_empty() {
                // In case we are using `kani_core`.
                crates.extend(rustc_public::find_crates("core"));
            }
            let statics: Vec<_> = crates.into_iter().flat_map(|krate| krate.statics()).collect();
            let [main, buffer] =
                ["KaniMemoryInitializationState", "KaniMemoryInitializationArgumentBuffer"].map(
                    |marker| {
                        let mut matching = statics.iter().copied().filter(|static_def| {
                            crate::kani_middle::attributes::fn_marker(*static_def).as_deref()
                                == Some(marker)
                        });
                        let static_def = matching.next();
                        assert!(
                            matching.next().is_none(),
                            "Expected unique private static marker {marker}"
                        );
                        static_def
                            .map(|def| Instance::from(def).mangled_name())
                            .and_then(|name| self.symbol_table.lookup(&name).cloned())
                    },
                );
            let uninit_enabled =
                self.queries.args().ub_check.contains(&crate::args::ExtraChecks::Uninit);
            if !uninit_enabled && main.is_none() && buffer.is_none() {
                // Models without uninit instrumentation need neither private object.
                Vec::new()
            } else {
                let main = main.expect("Missing emitted KaniMemoryInitializationState");
                let buffer =
                    buffer.expect("Missing emitted KaniMemoryInitializationArgumentBuffer");
                assert_ne!(main.name, buffer.name, "Private uninit objects must be distinct");
                let mut assigns =
                    vec![Lambda::as_contract_for(&goto_annotated_fn_typ, None, main.to_expr())];
                for (field, expected_type) in [
                    ("active", Type::c_bool()),
                    ("selected_argument", Type::size_t()),
                    ("signature", Type::size_t()),
                    ("count", Type::size_t()),
                    ("written", Type::size_t()),
                    ("remaining", Type::size_t()),
                    ("last_stored", Type::size_t()),
                    ("last_loaded", Type::size_t()),
                    ("has_witness", Type::c_bool()),
                    ("value", Type::c_bool()),
                    ("saved_base", Type::unsigned_int(8).to_pointer()),
                    ("saved_byte", Type::unsigned_int(8).to_pointer()),
                    ("layout_size", Type::size_t()),
                ] {
                    let target = buffer.to_expr().member(field, &self.symbol_table);
                    assert_eq!(target.typ(), &expected_type, "Private buffer field {field}");
                    assigns.push(Lambda::as_contract_for(&goto_annotated_fn_typ, None, target));
                }
                assigns
            }
        };

        // The last argument is a tuple with addresses that can be modified.
        let modifies_local = Local::from(modifies.fn_abi().unwrap().args.len());
        let modifies_ty = self.local_ty_stable(modifies_local);
        let modifies_args =
            self.codegen_place_stable(&modifies_local.into(), loc).unwrap().goto_expr;
        let TyKind::RigidTy(RigidTy::Tuple(modifies_tys)) = modifies_ty.kind() else {
            unreachable!("found {:?}", modifies_ty.kind())
        };

        for ty in &modifies_tys {
            assert!(ty.kind().is_any_ptr(), "Expected pointer, but found {ty}");
        }

        let assigns: Vec<_> = modifies_tys
            .into_iter()
            // do not attempt to dereference (and assign) a ZST
            .filter(|ty| !self.is_zst_stable(pointee_type_stable(*ty).unwrap()))
            .enumerate()
            .map(|(idx, ty)| {
                let ptr = modifies_args.clone().member(idx.to_string(), &self.symbol_table);
                if self.is_fat_pointer_stable(ty) {
                    let unref = match ty.kind() {
                        TyKind::RigidTy(RigidTy::RawPtr(pointee_ty, _)) => pointee_ty,
                        kind => unreachable!("Expected a raw pointer, but found {:?}", kind),
                    };
                    // The pointee spans `len` elements for slices and `str`, and the size the
                    // vtable records for trait objects.
                    let len = || ptr.clone().member("len", &self.symbol_table);
                    let size = match unref.kind() {
                        TyKind::RigidTy(RigidTy::Slice(elt_type)) => {
                            let elt_size = elt_type.layout().unwrap().shape().size.bytes();
                            len().mul(Expr::size_constant(
                                elt_size.try_into().unwrap(),
                                &self.symbol_table,
                            ))
                        }
                        TyKind::RigidTy(RigidTy::Str) => len(),
                        TyKind::RigidTy(RigidTy::Dynamic(..)) => ptr
                            .clone()
                            .member("vtable", &self.symbol_table)
                            .dereference()
                            .member(typ::VTABLE_SIZE_FIELD, &self.symbol_table),
                        // For adt, see https://rust-lang.zulipchat.com/#narrow/stream/182449-t-compiler.2Fhelp
                        TyKind::RigidTy(RigidTy::Adt(..)) => {
                            todo!("Adt fat pointers not implemented")
                        }
                        kind => unreachable!("Generating a fat pointer to {:?}", kind),
                    };
                    Lambda::as_contract_for(
                        &goto_annotated_fn_typ,
                        None,
                        self.codegen_object_upto(ptr.member("data", &self.symbol_table), size),
                    )
                } else {
                    Lambda::as_contract_for(&goto_annotated_fn_typ, None, ptr.dereference())
                }
            })
            .chain(shadow_memory_assign)
            .collect();

        FunctionContract::new(assigns)
    }

    /// Convert the contract to a CBMC contract, then attach it to `instance`.
    /// `instance` must have previously been declared.
    ///
    /// This merges with any previously attached contracts.
    pub fn attach_modifies_contract(&mut self, instance: Instance) {
        // This should be safe, since the contract is pretty much evaluated as
        // though it was the first (or last) assertion in the function.
        assert!(self.current_fn.is_none());
        let body = self.transformer.body(self.tcx, instance);
        self.set_current_fn(instance, &body);
        let mangled_name = instance.mangled_name();
        let goto_contract = self.codegen_modifies_contract(
            &mangled_name,
            instance,
            self.codegen_span_stable(instance.def.span()),
        );
        self.symbol_table.attach_contract(&mangled_name, goto_contract);
        self.reset_current_fn();
    }
}
