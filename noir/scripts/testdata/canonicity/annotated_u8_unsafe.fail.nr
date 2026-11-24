// FAIL fixture: 32-byte annotated (turbofish-free) decomposition -- the exact
// spelling `let b: [u8; 32] = x.to_be_bytes();` that both real ZKM/ZKA bugs
// took, and which a turbofish-only lint would never see.
fn unsafe_annotated_bytes(x: Field) -> Field {
    let b: [u8; 32] = x.to_be_bytes();
    b[0] as Field
}
