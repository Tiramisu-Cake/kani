#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;

#[inline(never)]
fn consume(value: u8) -> u8 {
    // Read only the initialized by-value parameter, never caller storage.
    unsafe { std::ptr::read_volatile(&raw const value) }
}

// u8 is intentionally shared by Move and Copy variants: the custom MIR operand,
// not the Rust Copy trait, selects the transfer. No padding or pointer cast.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn probe() -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let src: u8;
        let p: *const u8;
        let callee: u8;
        let observed: u8;

        {
            src = 0x51_u8;
            // Documented addr_of! form creates the RawPtr rvalue (&raw const src).
            p = std::ptr::addr_of!(src);
            // A bare place is Operand::Copy; there is no custom-MIR Copy() function.
            Call(callee = consume(src), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            // Same pre-transfer pointer, after the callee returns, no reinit.
            Call(observed = std::ptr::read_volatile::<u8>(p), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

fn main() {
    println!("custom_call_copy_read: original address-taken src is the call operand");
    // Copy preserves src even when the callee writes its own parameter.
    let (callee, source) = unsafe { probe() };
    println!("callee={callee:#04x} source={source:#04x}");
    assert_eq!(callee, 0x51, "callee parameter observation");
    assert_eq!(source, 0x51, "Copy must preserve the source byte");
}
