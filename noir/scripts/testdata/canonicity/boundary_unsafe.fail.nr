// FAIL fixture: the unsafe side of the threshold boundary -- 32 bytes (256
// bits) and 254 bits are both at or above the field's ~254-bit modulus width,
// so each admits a second `x + p` witness.
fn boundary_bytes_unsafe(x: Field) -> Field {
    let b: [u8; 32] = x.to_be_bytes();
    b[0] as Field
}

fn boundary_bits_unsafe(x: Field) -> Field {
    let bits: [bool; 254] = x.to_be_bits();
    bits[0] as Field
}
