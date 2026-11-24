// PASS fixture: the FIXED construction. std::field::bn254::decompose carries
// the in-circuit canonicity assertion (lo/hi range checks + a `< p` compare
// against the modulus limbs), so it never contains the banned call names at
// all -- this file must lint clean.
pub fn low_128_bits(value: Field) -> Field {
    let (lo, _hi) = std::field::bn254::decompose(value);
    lo
}
