// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Utility functions that help calculate type layout.

use std::fmt::Display;

use rustc_attr_ir::lang_items::LangItem;
use rustc_middle::ty::TyCtxt;
use rustc_public::{CrateDef, CrateDefType, rustc_internal};
use rustc_public::{
    abi::{FieldsShape, Scalar, TagEncoding, ValueRepr, VariantsShape},
    target::{MachineInfo, MachineSize},
    ty::{AdtKind, GenericArgKind, RigidTy, Ty, TyKind, UintTy, VariantIdx},
};
use rustc_public_bridge::IndexedVal;

/// Represents a chunk of data bytes in a data structure.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct DataBytes {
    /// Offset in bytes.
    offset: usize,
    /// Size of this data chunk.
    size: MachineSize,
}

/// Bytewise mask, representing which bytes of a type are data and which are padding. Here, `false`
/// represents padding bytes and `true` represents data bytes.
type Layout = Vec<bool>;

/// Create a byte-wise mask from known chunks of data bytes.
fn generate_byte_mask(size_in_bytes: usize, data_chunks: Vec<DataBytes>) -> Vec<bool> {
    let mut layout_mask = vec![false; size_in_bytes];
    for data_bytes in data_chunks.iter() {
        for layout_item in
            layout_mask.iter_mut().skip(data_bytes.offset).take(data_bytes.size.bytes())
        {
            *layout_item = true;
        }
    }
    layout_mask
}

// Depending on whether the type is statically or dynamically sized,
// the layout of the element or the layout of the actual type is returned.
pub enum PointeeLayout {
    /// Layout of sized objects.
    Sized { layout: Layout },
    /// Layout of slices, *const/mut str is included in this case and treated as *const/mut [u8].
    Slice { element_layout: Layout },
    /// Layout of unions, which are shared storage for multiple fields of potentially different layouts.
    Union { field_layouts: Vec<Layout> },
    /// Trait objects have an arbitrary layout.
    TraitObject,
}

impl PointeeLayout {
    /// Returns the size of the layout, if available.
    pub fn maybe_size(&self) -> Option<usize> {
        match self {
            PointeeLayout::Sized { layout } => Some(layout.len()),
            PointeeLayout::Slice { element_layout } => Some(element_layout.len()),
            PointeeLayout::Union { field_layouts } => {
                Some(field_layouts.iter().map(|field_layout| field_layout.len()).max().unwrap())
            }
            PointeeLayout::TraitObject => None,
        }
    }
}

pub struct PointeeInfo {
    pointee_ty: Ty,
    layout: PointeeLayout,
}

/// Byte masks for a sized struct that combines initialized data and uninitialized storage.
///
/// `read_mask` is the subset required for an ordinary typed read. `storage_mask` describes
/// bytes whose initialization state is tracked as storage (including padding inside a
/// `MaybeUninit<T>` slot). `padding_mask` is the remaining product padding.
pub(super) struct ProductLayout {
    pub(super) size: usize,
    pub(super) read_mask: Vec<bool>,
    pub(super) storage_mask: Vec<bool>,
    pub(super) padding_mask: Vec<bool>,
}

/// Different layout computation errors that could arise from the currently unsupported constructs.
pub enum LayoutComputationError {
    UnknownUnsizedLayout(Ty),
    EnumWithNicheEncoding(Ty),
    EnumWithMultiplePaddingVariants(Ty),
    UnsupportedType(Ty),
    UnionAsField(Ty),
    CompoundStorage(Ty),
}

impl Display for LayoutComputationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayoutComputationError::UnknownUnsizedLayout(ty) => {
                write!(f, "Cannot determine layout for an unsized type {ty}")
            }
            LayoutComputationError::EnumWithNicheEncoding(ty) => {
                write!(f, "Cannot determine layout for an Enum with niche encoding of type {ty}")
            }
            LayoutComputationError::EnumWithMultiplePaddingVariants(ty) => write!(
                f,
                "Cannot determine layout for an Enum of type {ty}, as it has multiple variants that have different padding."
            ),
            LayoutComputationError::UnsupportedType(ty) => {
                write!(f, "Cannot determine layout for an unsupported type {ty}.")
            }
            LayoutComputationError::UnionAsField(ty) => write!(
                f,
                "Cannot determine layout for a type that contains union of type {ty} as a field."
            ),
            LayoutComputationError::CompoundStorage(_) => {
                write!(f, "Kani does not support this compound storage layout.")
            }
        }
    }
}

/// Returns the type parameter of the specified standard-library wrapper.
pub(super) fn wrapper_inner(tcx: TyCtxt, ty: Ty, wrapper: LangItem) -> Option<Ty> {
    if let TyKind::RigidTy(RigidTy::Adt(def, args)) = ty.kind()
        && tcx.is_lang_item(rustc_internal::internal(tcx, def.def_id()), wrapper)
        && let Some(GenericArgKind::Type(inner)) = args.0.first()
    {
        Some(*inner)
    } else {
        None
    }
}

/// Recognizes a slot or a flat sequence of slots. Other enclosing types keep their union error.
pub(super) fn maybe_uninit_storage(tcx: TyCtxt, ty: Ty) -> Option<Ty> {
    let slot_ty = match ty.kind() {
        TyKind::RigidTy(RigidTy::Array(slot, _) | RigidTy::Slice(slot)) => slot,
        _ => ty,
    };
    wrapper_inner(tcx, slot_ty, LangItem::MaybeUninit)
}

impl PointeeInfo {
    /// Layout for copying storage or writing every byte with a bytewise intrinsic.
    pub(super) fn for_storage(tcx: TyCtxt, ty: Ty) -> Result<Self, LayoutComputationError> {
        let inner = maybe_uninit_storage(tcx, ty).unwrap();
        data_bytes_for_ty(&MachineInfo::target(), inner, 0)?;
        let layout = if let TyKind::RigidTy(RigidTy::Slice(slot)) = ty.kind() {
            let size = slot.layout().unwrap().shape().size.bytes();
            PointeeLayout::Slice { element_layout: vec![true; size] }
        } else {
            let size = ty.layout().unwrap().shape().size.bytes();
            PointeeLayout::Sized { layout: vec![true; size] }
        };
        Ok(Self { pointee_ty: ty, layout })
    }

    /// Layout for ordinary reads of a supported compound storage product.
    pub(super) fn for_product_read(tcx: TyCtxt, ty: Ty) -> Result<Self, LayoutComputationError> {
        let product =
            product_layout(tcx, ty)?.ok_or(LayoutComputationError::CompoundStorage(ty))?;
        Ok(Self { pointee_ty: ty, layout: PointeeLayout::Sized { layout: product.read_mask } })
    }

    /// Layout for bytewise operations over the complete extent of a compound storage product.
    pub(super) fn for_product_storage(tcx: TyCtxt, ty: Ty) -> Result<Self, LayoutComputationError> {
        let product =
            product_layout(tcx, ty)?.ok_or(LayoutComputationError::CompoundStorage(ty))?;
        Ok(Self {
            pointee_ty: ty,
            layout: PointeeLayout::Sized { layout: vec![true; product.size] },
        })
    }

    pub fn from_ty(ty: Ty) -> Result<Self, LayoutComputationError> {
        match ty.kind() {
            TyKind::RigidTy(rigid_ty) => match rigid_ty {
                RigidTy::Adt(adt_def, args) if adt_def.kind() == AdtKind::Union => {
                    assert!(adt_def.variants().len() == 1);
                    let fields: Result<_, _> = adt_def
                        .variant(VariantIdx::to_val(0))
                        .unwrap()
                        .fields()
                        .into_iter()
                        .map(|field_def| {
                            let ty = field_def.ty_with_args(&args);
                            let size_in_bytes = ty.layout().unwrap().shape().size.bytes();
                            data_bytes_for_ty(&MachineInfo::target(), ty, 0)
                                .map(|data_chunks| generate_byte_mask(size_in_bytes, data_chunks))
                        })
                        .collect();
                    Ok(PointeeInfo {
                        pointee_ty: ty,
                        layout: PointeeLayout::Union { field_layouts: fields? },
                    })
                }
                RigidTy::Str => {
                    let slicee_ty = Ty::unsigned_ty(UintTy::U8);
                    let size_in_bytes = slicee_ty.layout().unwrap().shape().size.bytes();
                    let data_chunks = data_bytes_for_ty(&MachineInfo::target(), slicee_ty, 0)?;
                    let layout = PointeeLayout::Slice {
                        element_layout: generate_byte_mask(size_in_bytes, data_chunks),
                    };
                    Ok(PointeeInfo { pointee_ty: ty, layout })
                }
                RigidTy::Slice(slicee_ty) => {
                    let size_in_bytes = slicee_ty.layout().unwrap().shape().size.bytes();
                    let data_chunks = data_bytes_for_ty(&MachineInfo::target(), slicee_ty, 0)?;
                    let layout = PointeeLayout::Slice {
                        element_layout: generate_byte_mask(size_in_bytes, data_chunks),
                    };
                    Ok(PointeeInfo { pointee_ty: ty, layout })
                }
                RigidTy::Dynamic(..) => {
                    Ok(PointeeInfo { pointee_ty: ty, layout: PointeeLayout::TraitObject })
                }
                _ => {
                    if ty.layout().unwrap().shape().is_sized() {
                        let size_in_bytes = ty.layout().unwrap().shape().size.bytes();
                        let data_chunks = data_bytes_for_ty(&MachineInfo::target(), ty, 0)?;
                        let layout = PointeeLayout::Sized {
                            layout: generate_byte_mask(size_in_bytes, data_chunks),
                        };
                        Ok(PointeeInfo { pointee_ty: ty, layout })
                    } else {
                        Err(LayoutComputationError::UnknownUnsizedLayout(ty))
                    }
                }
            },
            TyKind::Alias(..) | TyKind::Param(..) | TyKind::Bound(..) => {
                unreachable!("Should only encounter monomorphized types at this point.")
            }
        }
    }

    pub fn ty(&self) -> &Ty {
        &self.pointee_ty
    }

    pub fn layout(&self) -> &PointeeLayout {
        &self.layout
    }
}

/// Compute the separate read, storage, and padding masks for a sized struct product.
/// Ordinary and flat `MaybeUninit` layouts return `None` so their existing paths remain in use.
pub(super) fn product_layout(
    tcx: TyCtxt,
    ty: Ty,
) -> Result<Option<ProductLayout>, LayoutComputationError> {
    if let Some(slot_ty) = maybe_uninit_storage(tcx, ty) {
        if contains_storage(tcx, slot_ty) {
            return Err(LayoutComputationError::CompoundStorage(ty));
        }
        data_bytes_for_ty(&MachineInfo::target(), slot_ty, 0)
            .map_err(|_| LayoutComputationError::CompoundStorage(ty))?;
        return Ok(None);
    }
    let has_storage = contains_storage(tcx, ty);
    if !has_storage {
        return Ok(None);
    }
    validate_storage_shape(tcx, ty, false)?;

    if !matches!(ty.kind().rigid(), Some(RigidTy::Adt(def, _)) if def.kind() == AdtKind::Struct) {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }
    if !ty.layout().unwrap().shape().is_sized() {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }

    let size = ty.layout().unwrap().shape().size.bytes();
    let mut read_mask = vec![false; size];
    let mut storage_mask = vec![false; size];
    fill_product_node(tcx, ty, 0, &mut read_mask, &mut storage_mask)?;
    let padding_mask =
        (0..size).map(|idx| !read_mask[idx] && !storage_mask[idx]).collect::<Vec<_>>();

    // Validate the partition, including target padding and zero-sized fields. Every byte must
    // belong to exactly one of R, S, or P, and every marked extent must be in the target object.
    if read_mask.len() != size
        || storage_mask.len() != size
        || padding_mask.len() != size
        || (0..size).any(|idx| {
            usize::from(read_mask[idx])
                + usize::from(storage_mask[idx])
                + usize::from(padding_mask[idx])
                != 1
                || (read_mask[idx] && storage_mask[idx])
        })
    {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }

    Ok(Some(ProductLayout { size, read_mask, storage_mask, padding_mask }))
}

/// Find storage recursively through by-value fields. Pointer and reference pointees are not
/// part of the containing object's layout. A nested `MaybeUninit`, union, or storage enum is
/// rejected at the point where it would otherwise make the descriptor ambiguous.
pub(super) fn contains_storage(tcx: TyCtxt, ty: Ty) -> bool {
    if wrapper_inner(tcx, ty, LangItem::MaybeUninit).is_some() {
        return true;
    }
    if let Some(inner) = wrapper_inner(tcx, ty, LangItem::ManuallyDrop) {
        return contains_storage(tcx, inner);
    }
    match ty.kind().rigid() {
        Some(RigidTy::RawPtr(..) | RigidTy::Ref(..) | RigidTy::FnPtr(..)) => false,
        Some(RigidTy::Array(elem, _)) | Some(RigidTy::Slice(elem)) => contains_storage(tcx, *elem),
        Some(RigidTy::Adt(def, args)) => def.variants().iter().any(|variant| {
            variant.fields().iter().any(|field| contains_storage(tcx, field.ty_with_args(args)))
        }),
        Some(RigidTy::Tuple(tys)) => tys.iter().any(|field| contains_storage(tcx, *field)),
        _ => false,
    }
}

fn validate_storage_shape(
    tcx: TyCtxt,
    ty: Ty,
    inside_maybe_uninit: bool,
) -> Result<bool, LayoutComputationError> {
    if wrapper_inner(tcx, ty, LangItem::MaybeUninit).is_some() {
        let inner = wrapper_inner(tcx, ty, LangItem::MaybeUninit).unwrap();
        if inside_maybe_uninit || contains_storage(tcx, inner) {
            return Err(LayoutComputationError::CompoundStorage(ty));
        }
        data_bytes_for_ty(&MachineInfo::target(), inner, 0)
            .map_err(|_| LayoutComputationError::CompoundStorage(ty))?;
        return Ok(true);
    }
    if let Some(inner) = wrapper_inner(tcx, ty, LangItem::ManuallyDrop) {
        return validate_storage_shape(tcx, inner, inside_maybe_uninit);
    }
    match ty.kind().rigid() {
        Some(RigidTy::RawPtr(..) | RigidTy::Ref(..) | RigidTy::FnPtr(..)) => Ok(false),
        Some(RigidTy::Array(elem, _)) | Some(RigidTy::Slice(elem)) => {
            validate_storage_shape(tcx, *elem, inside_maybe_uninit)
        }
        Some(RigidTy::Adt(def, args)) => match def.kind() {
            AdtKind::Struct => {
                let mut found = false;
                for field in def.variants_iter().next().unwrap().fields() {
                    found |=
                        validate_storage_shape(tcx, field.ty_with_args(args), inside_maybe_uninit)?;
                }
                Ok(found)
            }
            AdtKind::Enum | AdtKind::Union => {
                let mut found = false;
                for variant in def.variants() {
                    for field in variant.fields() {
                        found |= validate_storage_shape(
                            tcx,
                            field.ty_with_args(args),
                            inside_maybe_uninit,
                        )?;
                    }
                }
                if found { Err(LayoutComputationError::CompoundStorage(ty)) } else { Ok(false) }
            }
        },
        Some(RigidTy::Tuple(tys)) => {
            let mut found = false;
            for field in tys {
                found |= validate_storage_shape(tcx, *field, inside_maybe_uninit)?;
            }
            if found { Err(LayoutComputationError::CompoundStorage(ty)) } else { Ok(false) }
        }
        _ => Ok(false),
    }
}

fn mark_range(
    mask: &mut [bool],
    offset: usize,
    size: usize,
    ty: Ty,
) -> Result<(), LayoutComputationError> {
    let Some(end) = offset.checked_add(size) else {
        return Err(LayoutComputationError::CompoundStorage(ty));
    };
    if end > mask.len() {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }
    for byte in &mut mask[offset..end] {
        if *byte {
            return Err(LayoutComputationError::CompoundStorage(ty));
        }
        *byte = true;
    }
    Ok(())
}

fn fill_product_node(
    tcx: TyCtxt,
    ty: Ty,
    offset: usize,
    read_mask: &mut [bool],
    storage_mask: &mut [bool],
) -> Result<(), LayoutComputationError> {
    let size = ty.layout().unwrap().shape().size.bytes();
    if offset.checked_add(size).is_none_or(|end| end > read_mask.len()) {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }
    if wrapper_inner(tcx, ty, LangItem::MaybeUninit).is_some() {
        let inner = wrapper_inner(tcx, ty, LangItem::MaybeUninit).unwrap();
        data_bytes_for_ty(&MachineInfo::target(), inner, 0)
            .map_err(|_| LayoutComputationError::CompoundStorage(ty))?;
        mark_range(storage_mask, offset, size, ty)?;
        return Ok(());
    }
    if let Some(inner) = wrapper_inner(tcx, ty, LangItem::ManuallyDrop) {
        return fill_product_node(tcx, inner, offset, read_mask, storage_mask);
    }
    if let Some(RigidTy::Array(elem, _)) = ty.kind().rigid()
        && wrapper_inner(tcx, *elem, LangItem::MaybeUninit).is_some()
    {
        let FieldsShape::Array { stride, count } = ty.layout().unwrap().shape().fields else {
            return Err(LayoutComputationError::CompoundStorage(ty));
        };
        let elem_size = elem.layout().unwrap().shape().size.bytes();
        let count_usize: usize =
            count.try_into().map_err(|_| LayoutComputationError::CompoundStorage(ty))?;
        let stride_bytes = stride.bytes();
        if count_usize > 1 && stride_bytes < elem_size {
            return Err(LayoutComputationError::CompoundStorage(ty));
        }
        if count_usize == 0 {
            if size != 0 {
                return Err(LayoutComputationError::CompoundStorage(ty));
            }
        } else {
            let last_start = (count_usize - 1)
                .checked_mul(stride_bytes)
                .ok_or(LayoutComputationError::CompoundStorage(ty))?;
            let total_extent = last_start
                .checked_add(elem_size)
                .ok_or(LayoutComputationError::CompoundStorage(ty))?;
            if total_extent > size {
                return Err(LayoutComputationError::CompoundStorage(ty));
            }
        }
        for idx in 0..count {
            let idx: usize =
                idx.try_into().map_err(|_| LayoutComputationError::CompoundStorage(ty))?;
            let elem_offset = idx
                .checked_mul(stride_bytes)
                .and_then(|delta| offset.checked_add(delta))
                .ok_or(LayoutComputationError::CompoundStorage(ty))?;
            let local_end = idx
                .checked_mul(stride_bytes)
                .and_then(|start| start.checked_add(elem_size))
                .ok_or(LayoutComputationError::CompoundStorage(ty))?;
            if local_end > size {
                return Err(LayoutComputationError::CompoundStorage(ty));
            }
            mark_range(storage_mask, elem_offset, elem_size, ty)?;
        }
        return Ok(());
    }

    let Some(RigidTy::Adt(def, args)) = ty.kind().rigid() else {
        return Err(LayoutComputationError::CompoundStorage(ty));
    };
    if def.kind() != AdtKind::Struct {
        return Err(LayoutComputationError::CompoundStorage(ty));
    }
    let shape = ty.layout().unwrap().shape();
    let FieldsShape::Arbitrary { ref offsets } = shape.fields else {
        return Err(LayoutComputationError::CompoundStorage(ty));
    };
    let fields = def.variants_iter().next().unwrap().fields();
    let mut nonzero_field_ranges = Vec::with_capacity(fields.len());
    for (idx, field) in fields.iter().enumerate() {
        let field_size = field.ty_with_args(args).layout().unwrap().shape().size.bytes();
        let field_start = offsets[idx].bytes();
        let field_end = field_start
            .checked_add(field_size)
            .ok_or(LayoutComputationError::CompoundStorage(ty))?;
        if field_end > size {
            return Err(LayoutComputationError::CompoundStorage(ty));
        }
        if field_size > 0 {
            if nonzero_field_ranges
                .iter()
                .any(|(start, end)| field_start < *end && *start < field_end)
            {
                return Err(LayoutComputationError::CompoundStorage(ty));
            }
            nonzero_field_ranges.push((field_start, field_end));
        }
    }
    for idx in shape.fields.fields_by_offset_order() {
        let field_ty = fields[idx].ty_with_args(args);
        let field_offset = offset
            .checked_add(offsets[idx].bytes())
            .ok_or(LayoutComputationError::CompoundStorage(ty))?;
        if contains_storage(tcx, field_ty) {
            fill_product_node(tcx, field_ty, field_offset, read_mask, storage_mask)?;
        } else {
            let chunks = data_bytes_for_ty(&MachineInfo::target(), field_ty, field_offset)
                .map_err(|_| LayoutComputationError::CompoundStorage(field_ty))?;
            for chunk in chunks {
                mark_range(read_mask, chunk.offset, chunk.size.bytes(), field_ty)?;
            }
        }
    }
    Ok(())
}

/// Retrieve a set of data bytes with offsets for a type.
fn data_bytes_for_ty(
    machine_info: &MachineInfo,
    ty: Ty,
    current_offset: usize,
) -> Result<Vec<DataBytes>, LayoutComputationError> {
    let layout = ty.layout().unwrap().shape();

    match layout.fields {
        // A zero-sized primitive, e.g. the never type `!`, has no data bytes to track (its
        // layout is not a scalar, so it must not reach the scalar case below).
        FieldsShape::Primitive if layout.size.bytes() == 0 => Ok(vec![]),
        FieldsShape::Primitive => Ok(vec![match layout.value_repr {
            ValueRepr::Scalar(Scalar::Initialized { value, .. }) => {
                DataBytes { offset: current_offset, size: value.size(machine_info) }
            }
            _ => unreachable!("FieldsShape::Primitive with a different ABI than ValueRepr::Scalar"),
        }]),
        FieldsShape::Array { stride, count } if count > 0 => {
            let TyKind::RigidTy(RigidTy::Array(elem_ty, _)) = ty.kind() else { unreachable!() };
            let elem_data_bytes = data_bytes_for_ty(machine_info, elem_ty, current_offset)?;
            let mut result = vec![];
            if !elem_data_bytes.is_empty() {
                for idx in 0..count {
                    let idx: usize = idx.try_into().unwrap();
                    let elem_offset = idx * stride.bytes();
                    let mut next_data_bytes = elem_data_bytes
                        .iter()
                        .cloned()
                        .map(|mut req| {
                            req.offset += elem_offset;
                            req
                        })
                        .collect::<Vec<_>>();
                    result.append(&mut next_data_bytes)
                }
            }
            Ok(result)
        }
        FieldsShape::Arbitrary { ref offsets } => {
            match ty.kind().rigid().unwrap_or_else(|| panic!("unexpected type: {ty:?}")) {
                RigidTy::Adt(def, args) => {
                    match def.kind() {
                        AdtKind::Enum => {
                            // Support basic enumeration forms
                            let ty_variants = def.variants();
                            match layout.variants {
                                VariantsShape::Empty => Ok(vec![]),
                                VariantsShape::Single { index } => {
                                    // Only one variant is reachable. This behaves like a struct.
                                    let fields = ty_variants[index.to_index()].fields();
                                    let mut fields_data_bytes = vec![];
                                    for idx in layout.fields.fields_by_offset_order() {
                                        let field_offset = offsets[idx].bytes();
                                        let field_ty = fields[idx].ty_with_args(args);
                                        fields_data_bytes.append(&mut data_bytes_for_ty(
                                            machine_info,
                                            field_ty,
                                            field_offset + current_offset,
                                        )?);
                                    }
                                    Ok(fields_data_bytes)
                                }
                                VariantsShape::Multiple {
                                    tag_encoding: TagEncoding::Niche { .. },
                                    ..
                                } => Err(LayoutComputationError::EnumWithNicheEncoding(ty)),
                                VariantsShape::Multiple { variants, tag, .. } => {
                                    // Retrieve data bytes for the tag.
                                    let tag_size = match tag {
                                        Scalar::Initialized { value, .. } => {
                                            value.size(machine_info)
                                        }
                                        Scalar::Union { .. } => {
                                            unreachable!("Enum tag should not be a union.")
                                        }
                                    };
                                    // For enums, tag is the only field and should have offset of 0.
                                    assert!(offsets.len() == 1 && offsets[0].bytes() == 0);
                                    let tag_data_bytes =
                                        vec![DataBytes { offset: current_offset, size: tag_size }];

                                    // Retrieve data bytes for the fields.
                                    let mut fields_data_bytes = vec![];
                                    // Iterate over all variants for the enum.
                                    for (index, variant) in variants.iter().enumerate() {
                                        let mut field_data_bytes_for_variant = vec![];
                                        let fields = ty_variants[index].fields();
                                        for field_idx in variant.fields_by_offset_order() {
                                            let field_offset = variant.offsets[field_idx].bytes();
                                            let field_ty = fields[field_idx].ty_with_args(args);
                                            field_data_bytes_for_variant.append(
                                                &mut data_bytes_for_ty(
                                                    machine_info,
                                                    field_ty,
                                                    field_offset + current_offset,
                                                )?,
                                            );
                                        }
                                        fields_data_bytes.push(field_data_bytes_for_variant);
                                    }

                                    if fields_data_bytes.is_empty() {
                                        // If there are no fields, return the tag data bytes.
                                        Ok(tag_data_bytes)
                                    } else if fields_data_bytes.iter().all(
                                        |data_bytes_for_variant| {
                                            // Byte layout for variant N.
                                            let byte_mask_for_variant = generate_byte_mask(
                                                layout.size.bytes(),
                                                data_bytes_for_variant.clone(),
                                            );
                                            // Byte layout for variant 0.
                                            let byte_mask_for_first = generate_byte_mask(
                                                layout.size.bytes(),
                                                fields_data_bytes.first().unwrap().clone(),
                                            );
                                            byte_mask_for_variant == byte_mask_for_first
                                        },
                                    ) {
                                        // If all fields have the same layout, return fields data
                                        // bytes.
                                        let mut total_data_bytes = tag_data_bytes;
                                        let mut field_data_bytes =
                                            fields_data_bytes.first().unwrap().clone();
                                        total_data_bytes.append(&mut field_data_bytes);
                                        Ok(total_data_bytes)
                                    } else {
                                        // Struct has multiple padding variants, Kani cannot
                                        // differentiate between them.
                                        Err(
                                            LayoutComputationError::EnumWithMultiplePaddingVariants(
                                                ty,
                                            ),
                                        )
                                    }
                                }
                            }
                        }
                        AdtKind::Union => unreachable!(),
                        AdtKind::Struct => {
                            let mut struct_data_bytes = vec![];
                            let fields = def.variants_iter().next().unwrap().fields();
                            for idx in layout.fields.fields_by_offset_order() {
                                let field_offset = offsets[idx].bytes();
                                let field_ty = fields[idx].ty_with_args(args);
                                struct_data_bytes.append(&mut data_bytes_for_ty(
                                    machine_info,
                                    field_ty,
                                    field_offset + current_offset,
                                )?);
                            }
                            Ok(struct_data_bytes)
                        }
                    }
                }
                RigidTy::Pat(base_ty, ..) => {
                    // This is similar to a structure with one field and with niche defined.
                    let mut pat_data_bytes = vec![];
                    pat_data_bytes.append(&mut data_bytes_for_ty(machine_info, *base_ty, 0)?);
                    Ok(pat_data_bytes)
                }
                RigidTy::Tuple(tys) => {
                    let mut tuple_data_bytes = vec![];
                    for idx in layout.fields.fields_by_offset_order() {
                        let field_offset = offsets[idx].bytes();
                        let field_ty = tys[idx];
                        tuple_data_bytes.append(&mut data_bytes_for_ty(
                            machine_info,
                            field_ty,
                            field_offset + current_offset,
                        )?);
                    }
                    Ok(tuple_data_bytes)
                }
                RigidTy::Bool
                | RigidTy::Char
                | RigidTy::Int(_)
                | RigidTy::Uint(_)
                | RigidTy::Float(_)
                | RigidTy::Never => {
                    unreachable!("Expected primitive layout for {ty:?}")
                }
                RigidTy::Str | RigidTy::Slice(_) | RigidTy::Array(_, _) => {
                    unreachable!("Expected array layout for {ty:?}")
                }
                RigidTy::RawPtr(_, _) | RigidTy::Ref(_, _, _) => Ok(match layout.value_repr {
                    ValueRepr::Scalar(Scalar::Initialized { value, .. }) => {
                        // Thin pointer, ABI is a single scalar.
                        vec![DataBytes { offset: current_offset, size: value.size(machine_info) }]
                    }
                    ValueRepr::ScalarPair {
                        a: Scalar::Initialized { value: value_first, .. },
                        b: Scalar::Initialized { value: value_second, .. },
                        ..
                    } => {
                        // Fat pointer, ABI is a scalar pair.
                        let FieldsShape::Arbitrary { offsets } = layout.fields else {
                            unreachable!()
                        };
                        // Since this is a scalar pair, only 2 elements are in the offsets vec.
                        assert!(offsets.len() == 2);
                        vec![
                            DataBytes {
                                offset: current_offset + offsets[0].bytes(),
                                size: value_first.size(machine_info),
                            },
                            DataBytes {
                                offset: current_offset + offsets[1].bytes(),
                                size: value_second.size(machine_info),
                            },
                        ]
                    }
                    _ => unreachable!("RigidTy::RawPtr | RigidTy::Ref with a non-scalar ABI."),
                }),
                RigidTy::FnDef(_, _)
                | RigidTy::FnPtr(_)
                | RigidTy::Closure(_, _)
                | RigidTy::Coroutine(_, _)
                | RigidTy::CoroutineClosure(_, _)
                | RigidTy::CoroutineWitness(_, _)
                | RigidTy::Foreign(_)
                | RigidTy::Dynamic(_, _) => Err(LayoutComputationError::UnsupportedType(ty)),
            }
        }
        FieldsShape::Union(_) => Err(LayoutComputationError::UnionAsField(ty)),
        FieldsShape::Array { .. } => Ok(vec![]),
    }
}

/// Returns true if `to_ty` has a smaller or equal size and padding bytes in `from_ty` are padding
/// bytes in `to_ty`.
pub fn tys_layout_compatible_to_size(from_ty: &Ty, to_ty: &Ty) -> bool {
    tys_layout_cmp_to_size(from_ty, to_ty, |from_byte, to_byte| from_byte || !to_byte)
}

/// Returns true if `to_ty` has a smaller or equal size and padding bytes in `from_ty` are padding
/// bytes in `to_ty`.
pub fn tys_layout_equal_to_size(from_ty: &Ty, to_ty: &Ty) -> bool {
    tys_layout_cmp_to_size(from_ty, to_ty, |from_byte, to_byte| from_byte == to_byte)
}

/// Returns true if `to_ty` has a smaller or equal size and comparator function returns true for all
/// byte initialization value pairs up to size.
fn tys_layout_cmp_to_size(from_ty: &Ty, to_ty: &Ty, cmp: impl Fn(bool, bool) -> bool) -> bool {
    // Retrieve layouts to assess compatibility.
    let from_ty_info = PointeeInfo::from_ty(*from_ty);
    let to_ty_info = PointeeInfo::from_ty(*to_ty);
    if let (Ok(from_ty_info), Ok(to_ty_info)) = (from_ty_info, to_ty_info) {
        let from_ty_layout = match from_ty_info.layout() {
            PointeeLayout::Sized { layout } => layout,
            PointeeLayout::Slice { element_layout } => element_layout,
            PointeeLayout::TraitObject | PointeeLayout::Union { .. } => return false,
        };
        let to_ty_layout = match to_ty_info.layout() {
            PointeeLayout::Sized { layout } => layout,
            PointeeLayout::Slice { element_layout } => element_layout,
            PointeeLayout::TraitObject | PointeeLayout::Union { .. } => return false,
        };
        // Ensure `to_ty_layout` does not have a larger size.
        if to_ty_layout.len() <= from_ty_layout.len() {
            // Check data and padding bytes pair-wise.
            if from_ty_layout.iter().zip(to_ty_layout.iter()).all(
                |(from_ty_layout_byte, to_ty_layout_byte)| {
                    // Run comparator on each pair.
                    cmp(*from_ty_layout_byte, *to_ty_layout_byte)
                },
            ) {
                return true;
            }
        }
    };
    false
}
