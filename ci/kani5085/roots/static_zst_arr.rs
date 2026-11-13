#[cfg_attr(kani, kani::proof)]
fn check() { static S: ([[u8; 0]; 2], u8) = ([[], []], 5); let x = S; assert!(x.1 == 5); }
fn main() { check() }
