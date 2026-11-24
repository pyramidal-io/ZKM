// PASS fixture: the safe side of the threshold boundary -- 31 bytes (248
// bits) and 253 bits are both strictly below the field's ~254-bit modulus, so
// neither admits a second `x + p` witness.
fn boundary_bytes(x: Field) -> [u8; 31] {
    let b: [u8; 31] = x.to_be_bytes();
    b
}

fn boundary_bits(x: Field) -> [bool; 253] {
    let bits: [bool; 253] = x.to_be_bits();
    bits
}
