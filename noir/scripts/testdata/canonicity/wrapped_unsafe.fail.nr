// FAIL fixture: the same unsafe shape as annotated_bool_unsafe.fail.nr, but
// wrapped across 3 lines the way `nargo fmt` wraps a long binding. The lint
// must reassemble the statement across the line breaks before matching --
// and must not be fooled by the `;` inside `[bool; 254]` on the first line.
fn unsafe_wrapped_bits(value: Field) -> Field {
    let bits: [bool; 254] =
        value
            .to_be_bits();
    let mut acc: Field = 0;
    for i in 0..128 {
        acc = acc * 2 + (bits[253 - i] as Field);
    }
    acc
}
