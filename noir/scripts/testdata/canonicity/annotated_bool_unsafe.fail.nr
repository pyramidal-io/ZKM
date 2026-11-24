// FAIL fixture: 254-bit annotated decomposition -- this is the exact shape of
// the original zkm_lib::low_128_bits bug fixed in PR #4 (revocation-slot
// index derived from a non-canonical bit string).
fn unsafe_annotated_bits(value: Field) -> Field {
    let bits: [bool; 254] = value.to_be_bits();
    let mut acc: Field = 0;
    for i in 0..128 {
        acc = acc * 2 + (bits[253 - i] as Field);
    }
    acc
}
