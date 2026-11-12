// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

// This module provides instrumentation for tracking memory initialization of raw pointers.
// For full documentation, see the usage of `kani_core::kani_mem_init!(std);` in library/kani_core/src/lib.rs

// Definitions in this module are not meant to be visible to the end user, only the compiler.
#![allow(dead_code)]

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! kani_mem_init {
    ($core:path) => {
        use $core as kani_mem_init_core;

        /// Global object for tracking memory initialization state.
        // `#[rustc_diagnostic_item]` cannot be applied to statics (rust-lang/rust
        // disallows it), so we identify this static via Kani's own `fn_marker` tool
        // attribute instead; the compiler looks it up by that marker.
        #[kanitool::fn_marker = "KaniMemoryInitializationState"]
        static mut MEM_INIT_STATE: MemoryInitializationState = MemoryInitializationState::new();

        /// Private transfer snapshot; DFCC grants writes only to its scalar fields.
        #[kanitool::fn_marker = "KaniMemoryInitializationArgumentBuffer"]
        static mut ARGUMENT_BUFFER: ArgumentBuffer = ArgumentBuffer::new();

        /// Bytewise mask, representing which bytes of a type are data and which are padding.
        /// For example, for a type like this:
        /// ```
        /// #[repr(C)]
        /// struct Foo {
        ///     a: u16,
        ///     b: u8,
        /// }
        /// ```
        /// the layout would be [true, true, true, false];
        type Layout<const LAYOUT_SIZE: usize> = [bool; LAYOUT_SIZE];

        /// Currently tracked non-deterministically chosen memory initialization state.
        struct MemoryInitializationState {
            pub tracked_object_id: usize,
            pub tracked_offset: usize,
            pub value: bool,
        }

        /// Source-following snapshot and protocol state, separate from the tracked byte.
        struct ArgumentBuffer {
            pub active: bool,
            pub selected_argument: usize,
            pub signature: usize,
            pub count: usize,
            pub written: usize,
            pub remaining: usize,
            pub last_stored: usize,
            pub last_loaded: usize,
            pub has_witness: bool,
            pub value: bool,
            pub saved_base: *const u8,
            pub saved_byte: *const u8,
            pub layout_size: usize,
        }

        impl ArgumentBuffer {
            pub const fn new() -> Self {
                Self {
                    active: false,
                    selected_argument: 0,
                    signature: 0,
                    count: 0,
                    written: 0,
                    remaining: 0,
                    last_stored: 0,
                    last_loaded: 0,
                    has_witness: false,
                    value: false,
                    saved_base: kani_mem_init_core::ptr::null(),
                    saved_byte: kani_mem_init_core::ptr::null(),
                    layout_size: 0,
                }
            }
        }

        impl MemoryInitializationState {
            /// This is a dummy initialization function -- the values will be eventually overwritten by a
            /// call to `initialize_memory_initialization_state`.
            pub const fn new() -> Self {
                Self { tracked_object_id: 0, tracked_offset: 0, value: false }
            }

            /// Return currently tracked memory initialization state if `ptr` points to the currently
            /// tracked object and the tracked offset lies within `LAYOUT_SIZE` bytes of `ptr`. Return
            /// `true` otherwise.
            ///
            /// Such definition is necessary since both tracked object and tracked offset are chosen
            /// non-deterministically.
            #[kanitool::disable_checks(pointer)]
            pub fn get<const LAYOUT_SIZE: usize>(
                &mut self,
                ptr: *const u8,
                layout: Layout<LAYOUT_SIZE>,
            ) -> bool {
                let obj = super::mem::pointer_object(ptr);
                let offset = super::mem::pointer_offset(ptr);
                if self.tracked_object_id == obj
                    && self.tracked_offset >= offset
                    && self.tracked_offset < offset + LAYOUT_SIZE
                {
                    !layout[self.tracked_offset - offset] || self.value
                } else {
                    true
                }
            }

            /// Set currently tracked memory initialization state if `ptr` points to the currently tracked
            /// object and the tracked offset lies within `LAYOUT_SIZE` bytes of `ptr`. Do nothing
            /// otherwise.
            ///
            /// Such definition is necessary since both tracked object and tracked offset are chosen
            /// non-deterministically.
            #[kanitool::disable_checks(pointer)]
            pub fn set<const LAYOUT_SIZE: usize>(
                &mut self,
                ptr: *const u8,
                layout: Layout<LAYOUT_SIZE>,
                value: bool,
            ) {
                let obj = super::mem::pointer_object(ptr);
                let offset = super::mem::pointer_offset(ptr);
                if self.tracked_object_id == obj
                    && self.tracked_offset >= offset
                    && self.tracked_offset < offset + LAYOUT_SIZE
                {
                    self.value = layout[self.tracked_offset - offset] && value;
                }
            }

            /// Copy memory initialization state by non-deterministically switching the tracked object
            /// and adjusting the tracked offset. Only bytes selected by `layout` preserve their state.
            #[kanitool::disable_checks(pointer)]
            pub fn copy<const LAYOUT_SIZE: usize>(
                &mut self,
                from_ptr: *const u8,
                to_ptr: *const u8,
                num_elts: usize,
                layout: Layout<LAYOUT_SIZE>,
            ) {
                let from_obj = super::mem::pointer_object(from_ptr);
                let from_offset = super::mem::pointer_offset(from_ptr);
                let to_obj = super::mem::pointer_object(to_ptr);
                let to_offset = super::mem::pointer_offset(to_ptr);
                self.copy_by_id::<LAYOUT_SIZE>(
                    from_obj,
                    from_offset,
                    to_obj,
                    to_offset,
                    num_elts,
                    layout,
                );
            }

            /// Copy initialization state using object identities and offsets captured while the
            /// source pointer was live. This also supports return-value transfers, whose source
            /// stack slot is no longer live when the caller consumes the argument buffer.
            #[kanitool::disable_checks(pointer)]
            pub fn copy_by_id<const LAYOUT_SIZE: usize>(
                &mut self,
                from_obj: usize,
                from_offset: usize,
                to_obj: usize,
                to_offset: usize,
                num_elts: usize,
                layout: Layout<LAYOUT_SIZE>,
            ) {
                if LAYOUT_SIZE == 0 {
                    return;
                }
                if self.tracked_object_id == from_obj
                    && self.tracked_offset >= from_offset
                    && self.tracked_offset < from_offset + num_elts * LAYOUT_SIZE
                {
                    let should_reset: bool = super::any();
                    if should_reset {
                        self.tracked_object_id = to_obj;
                        self.tracked_offset = to_offset + (self.tracked_offset - from_offset);
                        // A preserve mask never initializes a source byte. It discards padding.
                        self.value &= layout[(self.tracked_offset - to_offset) % LAYOUT_SIZE];
                        return;
                    }
                }
                // If this path did not follow the source byte, do not retain the old state of
                // overwritten destination bytes. Their new state is checked on the source path.
                if self.tracked_object_id == to_obj
                    && self.tracked_offset >= to_offset
                    && self.tracked_offset < to_offset + num_elts * LAYOUT_SIZE
                {
                    self.value = layout[(self.tracked_offset - to_offset) % LAYOUT_SIZE];
                }
            }

            /// Return currently tracked memory initialization state if `ptr` points to the currently
            /// tracked object and the tracked offset lies within `LAYOUT_SIZE * num_elts` bytes of `ptr`.
            /// Return `true` otherwise.
            ///
            /// Such definition is necessary since both tracked object and tracked offset are chosen
            /// non-deterministically.
            #[kanitool::disable_checks(pointer)]
            pub fn get_slice<const LAYOUT_SIZE: usize>(
                &mut self,
                ptr: *const u8,
                layout: Layout<LAYOUT_SIZE>,
                num_elts: usize,
            ) -> bool {
                let obj = super::mem::pointer_object(ptr);
                let offset = super::mem::pointer_offset(ptr);
                if self.tracked_object_id == obj
                    && self.tracked_offset >= offset
                    && self.tracked_offset < offset + num_elts * LAYOUT_SIZE
                {
                    !layout[(self.tracked_offset - offset) % LAYOUT_SIZE] || self.value
                } else {
                    true
                }
            }

            /// Set currently tracked memory initialization state if `ptr` points to the currently tracked
            /// object and the tracked offset lies within `LAYOUT_SIZE * num_elts` bytes of `ptr`. Do
            /// nothing otherwise.
            ///
            /// Such definition is necessary since both tracked object and tracked offset are chosen
            /// non-deterministically.
            #[kanitool::disable_checks(pointer)]
            pub fn set_slice<const LAYOUT_SIZE: usize>(
                &mut self,
                ptr: *const u8,
                layout: Layout<LAYOUT_SIZE>,
                num_elts: usize,
                value: bool,
            ) {
                let obj = super::mem::pointer_object(ptr);
                let offset = super::mem::pointer_offset(ptr);
                if self.tracked_object_id == obj
                    && self.tracked_offset >= offset
                    && self.tracked_offset < offset + num_elts * LAYOUT_SIZE
                {
                    self.value = layout[(self.tracked_offset - offset) % LAYOUT_SIZE] && value;
                }
            }
        }

        /// Set tracked object and tracked offset to a non-deterministic value.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "InitializeMemoryInitializationStateModel"]
        fn initialize_memory_initialization_state() {
            unsafe {
                MEM_INIT_STATE.tracked_object_id = super::any();
                MEM_INIT_STATE.tracked_offset = super::any();
                MEM_INIT_STATE.value = false;
                ARGUMENT_BUFFER.active = false;
                ARGUMENT_BUFFER.selected_argument = usize::MAX;
                ARGUMENT_BUFFER.has_witness = false;
            }
        }

        /// Get initialization state of `num_elts` items laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "IsPtrInitializedModel"]
        fn is_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const T,
            layout: Layout<LAYOUT_SIZE>,
        ) -> bool {
            if LAYOUT_SIZE == 0 {
                return true;
            }
            let (ptr, _) = ptr.to_raw_parts();
            unsafe { MEM_INIT_STATE.get(ptr as *const u8, layout) }
        }

        /// Set initialization state to `value` for `num_elts` items laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "SetPtrInitializedModel"]
        fn set_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const T,
            layout: Layout<LAYOUT_SIZE>,
            value: bool,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (ptr, _) = ptr.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.set(ptr as *const u8, layout, value);
            }
        }

        /// Get initialization state of `num_elts` items laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "IsSliceChunkPtrInitializedModel"]
        fn is_slice_chunk_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const T,
            layout: Layout<LAYOUT_SIZE>,
            num_elts: usize,
        ) -> bool {
            if LAYOUT_SIZE == 0 {
                return true;
            }
            let (ptr, _) = ptr.to_raw_parts();
            unsafe { MEM_INIT_STATE.get_slice(ptr as *const u8, layout, num_elts) }
        }

        /// Set initialization state to `value` for `num_elts` items laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "SetSliceChunkPtrInitializedModel"]
        fn set_slice_chunk_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const T,
            layout: Layout<LAYOUT_SIZE>,
            num_elts: usize,
            value: bool,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (ptr, _) = ptr.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.set_slice(ptr as *const u8, layout, num_elts, value);
            }
        }

        /// Get initialization state of the slice, items of which are laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "IsSlicePtrInitializedModel"]
        fn is_slice_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const [T],
            layout: Layout<LAYOUT_SIZE>,
        ) -> bool {
            if LAYOUT_SIZE == 0 {
                return true;
            }
            let (ptr, num_elts) = ptr.to_raw_parts();
            unsafe { MEM_INIT_STATE.get_slice(ptr as *const u8, layout, num_elts) }
        }

        /// Set initialization state of the slice, items of which are laid out according to the `layout` starting at address `ptr` to `value`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "SetSlicePtrInitializedModel"]
        fn set_slice_ptr_initialized<const LAYOUT_SIZE: usize, T>(
            ptr: *const [T],
            layout: Layout<LAYOUT_SIZE>,
            value: bool,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (ptr, num_elts) = ptr.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.set_slice(ptr as *const u8, layout, num_elts, value);
            }
        }

        /// Get initialization state of the string slice, items of which are laid out according to the `layout` starting at address `ptr`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "IsStrPtrInitializedModel"]
        fn is_str_ptr_initialized<const LAYOUT_SIZE: usize>(
            ptr: *const str,
            layout: Layout<LAYOUT_SIZE>,
        ) -> bool {
            if LAYOUT_SIZE == 0 {
                return true;
            }
            let (ptr, num_elts) = ptr.to_raw_parts();
            unsafe { MEM_INIT_STATE.get_slice(ptr as *const u8, layout, num_elts) }
        }

        /// Set initialization state of the string slice, items of which are laid out according to the `layout` starting at address `ptr` to `value`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "SetStrPtrInitializedModel"]
        fn set_str_ptr_initialized<const LAYOUT_SIZE: usize>(
            ptr: *const str,
            layout: Layout<LAYOUT_SIZE>,
            value: bool,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (ptr, num_elts) = ptr.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.set_slice(ptr as *const u8, layout, num_elts, value);
            }
        }

        /// Copy initialization state of `size_of::<T> * num_elts` bytes from one pointer to the other. Note
        /// that in this case `LAYOUT_SIZE == size_of::<T>`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "CopyInitStateModel"]
        fn copy_init_state<const LAYOUT_SIZE: usize, T>(
            from: *const T,
            to: *const T,
            num_elts: usize,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (from_ptr, _) = from.to_raw_parts();
            let (to_ptr, _) = to.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.copy::<LAYOUT_SIZE>(
                    from_ptr as *const u8,
                    to_ptr as *const u8,
                    num_elts,
                    [true; LAYOUT_SIZE],
                );
            }
        }

        /// Transfer one typed value's initialization state, preserving only bytes selected by `layout`.
        /// In this case `LAYOUT_SIZE == size_of::<T>`.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "CopyInitStateSingleModel"]
        fn copy_init_state_single<const LAYOUT_SIZE: usize, T>(
            from: *const T,
            to: *const T,
            layout: Layout<LAYOUT_SIZE>,
        ) {
            if LAYOUT_SIZE == 0 {
                return;
            }
            let (from_ptr, _) = from.to_raw_parts();
            let (to_ptr, _) = to.to_raw_parts();
            unsafe {
                MEM_INIT_STATE.copy::<LAYOUT_SIZE>(
                    from_ptr as *const u8,
                    to_ptr as *const u8,
                    1,
                    layout,
                );
            }
        }

        /// Start one current-call protocol. No selected witness is different from no protocol.
        /// The callee consumes every load before executing its body, so nested/recursive calls
        /// need no stack of buffers. A normal return creates a separate, mandatory index-0 pair.
        #[kanitool::fn_marker = "BeginArgumentTransferModel"]
        fn begin_argument_transfer(signature: usize, argument_count: usize) {
            unsafe {
                assert!(!ARGUMENT_BUFFER.active, "unfinished shadow transfer");
                assert!(argument_count > 0);
                ARGUMENT_BUFFER.active = true;
                ARGUMENT_BUFFER.signature = signature;
                ARGUMENT_BUFFER.count = argument_count;
                ARGUMENT_BUFFER.written = 0;
                ARGUMENT_BUFFER.remaining = argument_count;
                ARGUMENT_BUFFER.last_stored = 0;
                ARGUMENT_BUFFER.last_loaded = 0;
                ARGUMENT_BUFFER.selected_argument = usize::MAX;
                ARGUMENT_BUFFER.has_witness = false;
            }
        }

        /// Snapshot the witness while the source is live and BEFORE Call(Move) deinitializes it.
        /// All shadow arguments compete for one slot; no source state is reread at callee entry.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "StoreArgumentModel"]
        fn store_argument<const LAYOUT_SIZE: usize, T>(
            from: *const T,
            selected_argument: usize,
            signature: usize,
        ) {
            let (from_ptr, _) = from.to_raw_parts();
            let from_object = super::mem::pointer_object(from_ptr);
            let from_offset = super::mem::pointer_offset(from_ptr);
            unsafe {
                if selected_argument == 0 {
                    assert!(!ARGUMENT_BUFFER.active, "unfinished shadow transfer");
                    ARGUMENT_BUFFER.active = true;
                    ARGUMENT_BUFFER.signature = signature;
                    ARGUMENT_BUFFER.count = 0;
                    ARGUMENT_BUFFER.remaining = 1;
                    ARGUMENT_BUFFER.written = 1;
                    ARGUMENT_BUFFER.last_loaded = 0;
                } else {
                    assert!(ARGUMENT_BUFFER.active, "missing shadow transfer protocol");
                    assert!(ARGUMENT_BUFFER.signature == signature);
                    assert!(ARGUMENT_BUFFER.count > 0);
                    assert!(ARGUMENT_BUFFER.written < ARGUMENT_BUFFER.count);
                    assert!(ARGUMENT_BUFFER.last_stored < selected_argument);
                    ARGUMENT_BUFFER.last_stored = selected_argument;
                    ARGUMENT_BUFFER.written += 1;
                }
                // Return zero is mandatory; arguments are a demonic choice, including none.
                if selected_argument == 0 || super::any() {
                    ARGUMENT_BUFFER.selected_argument = selected_argument;
                    ARGUMENT_BUFFER.layout_size = LAYOUT_SIZE;
                    let has_witness = MEM_INIT_STATE.tracked_object_id == from_object
                        && MEM_INIT_STATE.tracked_offset >= from_offset
                        && MEM_INIT_STATE.tracked_offset - from_offset < LAYOUT_SIZE;
                    let captured_value = MEM_INIT_STATE.value;
                    let (saved_base, saved_byte) = if has_witness {
                        let relative_offset =
                            MEM_INIT_STATE.tracked_offset.wrapping_sub(from_offset);
                        assert!(relative_offset < LAYOUT_SIZE, "shadow carrier store range");
                        let saved_base = from_ptr.cast::<u8>();
                        let saved_byte = saved_base.wrapping_add(relative_offset);
                        // Metadata only: no reference or read of possibly uninitialized data.
                        assert!(
                            super::mem::pointer_object(saved_byte)
                                == super::mem::pointer_object(saved_base),
                            "shadow carrier store object"
                        );
                        let base_offset = super::mem::pointer_offset(saved_base);
                        let byte_offset = super::mem::pointer_offset(saved_byte);
                        assert!(base_offset == from_offset, "shadow carrier store base");
                        assert!(byte_offset >= base_offset, "shadow carrier store offset wrap");
                        assert!(
                            byte_offset.wrapping_sub(base_offset) == relative_offset,
                            "shadow carrier store round trip"
                        );
                        (saved_base, saved_byte)
                    } else {
                        (kani_mem_init_core::ptr::null(), kani_mem_init_core::ptr::null())
                    };
                    ARGUMENT_BUFFER.has_witness = has_witness;
                    ARGUMENT_BUFFER.saved_base = saved_base;
                    ARGUMENT_BUFFER.saved_byte = saved_byte;
                    ARGUMENT_BUFFER.value = captured_value;
                }
            }
        }

        /// Consume the current protocol only. Unselected arguments get data-byte initialization
        /// because another demonic path selects their source. Missing/mismatched protocol and
        /// missing return zero are errors, never an initialized fallback.
        #[kanitool::disable_checks(pointer)]
        #[kanitool::fn_marker = "LoadArgumentModel"]
        fn load_argument<const LAYOUT_SIZE: usize, T>(
            to: *const T,
            selected_argument: usize,
            signature: usize,
            argument_count: usize,
            layout: Layout<LAYOUT_SIZE>,
        ) {
            let (to_ptr, _) = to.to_raw_parts();
            unsafe {
                assert!(ARGUMENT_BUFFER.active, "missing shadow transfer protocol");
                assert!(ARGUMENT_BUFFER.signature == signature);
                assert!(ARGUMENT_BUFFER.count == argument_count);
                assert!(ARGUMENT_BUFFER.remaining > 0);
                if selected_argument == 0 {
                    assert!(argument_count == 0);
                    assert!(ARGUMENT_BUFFER.written == 1);
                    assert!(ARGUMENT_BUFFER.selected_argument == 0, "missing shadow return");
                } else {
                    assert!(argument_count > 0);
                    assert!(ARGUMENT_BUFFER.written == argument_count);
                    assert!(ARGUMENT_BUFFER.last_loaded < selected_argument);
                    ARGUMENT_BUFFER.last_loaded = selected_argument;
                }
                let selected = ARGUMENT_BUFFER.selected_argument == selected_argument;
                if selected {
                    assert!(ARGUMENT_BUFFER.layout_size == LAYOUT_SIZE);
                    ARGUMENT_BUFFER.selected_argument = usize::MAX;
                }
                if selected && ARGUMENT_BUFFER.has_witness && super::any() {
                    let saved_base = ARGUMENT_BUFFER.saved_base;
                    let saved_byte = ARGUMENT_BUFFER.saved_byte;
                    // The source may be dead. Decode stored bits, never its bytes or shadow.
                    assert!(
                        super::mem::pointer_object(saved_byte)
                            == super::mem::pointer_object(saved_base),
                        "shadow carrier load object"
                    );
                    let base_offset = super::mem::pointer_offset(saved_base);
                    let byte_offset = super::mem::pointer_offset(saved_byte);
                    assert!(byte_offset >= base_offset, "shadow carrier load offset wrap");
                    let relative_offset = byte_offset.wrapping_sub(base_offset);
                    assert!(relative_offset < LAYOUT_SIZE, "shadow carrier load range");
                    MEM_INIT_STATE.tracked_object_id = super::mem::pointer_object(to_ptr);
                    MEM_INIT_STATE.tracked_offset =
                        super::mem::pointer_offset(to_ptr) + relative_offset;
                    MEM_INIT_STATE.value = ARGUMENT_BUFFER.value && layout[relative_offset];
                } else {
                    MEM_INIT_STATE.set::<LAYOUT_SIZE>(to_ptr as *const u8, layout, true);
                }
                ARGUMENT_BUFFER.remaining -= 1;
                if ARGUMENT_BUFFER.remaining == 0 {
                    assert!(ARGUMENT_BUFFER.selected_argument == usize::MAX);
                    ARGUMENT_BUFFER.active = false;
                    ARGUMENT_BUFFER.has_witness = false;
                }
            }
        }
    };
}
