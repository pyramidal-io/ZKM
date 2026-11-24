// FAIL fixture: a bare `.to_be_bytes()` call with no turbofish AND no
// same-statement array-type annotation. The width cannot be statically
// resolved, so the lint must fail closed rather than assume it is safe.
fn unresolvable_call(x: Field) -> Field {
    let b = x.to_be_bytes();
    b[0] as Field
}
