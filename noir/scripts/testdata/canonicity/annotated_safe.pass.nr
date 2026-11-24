// PASS fixture: annotated (turbofish-free) bit-decomposition at a safe width.
// The type annotation on `bits` is what fixes N=32; there is no turbofish.
fn safe_annotated_bits(x: Field) -> [bool; 32] {
    let bits: [bool; 32] = x.to_be_bits();
    bits
}
