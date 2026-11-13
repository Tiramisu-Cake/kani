#[cfg_attr(kani, kani::proof)]
fn check() { let x: ([[u8; 0]; 2], u8) = std::hint::black_box(([[], []], 5)); assert!(x.1 == 5); }
fn main() { check() }
