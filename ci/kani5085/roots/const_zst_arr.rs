#[cfg_attr(kani, kani::proof)]
fn check() {
    const S: ([[u8; 0]; 2], u8) = ([[], []], 5);
    let x = std::hint::black_box(S);
    assert!(x.1 == 5);
}
fn main() { check() }
