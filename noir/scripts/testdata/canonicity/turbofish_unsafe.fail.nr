// FAIL fixture: 32-byte (256-bit) turbofish decomposition. 2^256 > p, so `x`
// and `x + p` (and `x + 2p`) are all valid 32-byte witnesses.
fn unsafe_turbofish_bytes(x: Field) -> Field {
    let b = x.to_be_bytes::<32>();
    b[0] as Field
}
