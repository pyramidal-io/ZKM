// PASS fixture: turbofish-spelled decompositions at safe widths -- 128 bits
// and 31 bytes, both comfortably under the field's ~254-bit modulus.
fn safe_turbofish_bits(x: Field) -> [bool; 128] {
    x.to_be_bits::<128>()
}

fn safe_turbofish_bytes(x: Field) -> [u8; 31] {
    x.to_be_bytes::<31>()
}
