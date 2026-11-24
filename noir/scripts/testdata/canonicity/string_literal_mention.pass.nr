// PASS fixture: the banned shape appears only inside a string literal (an
// assert message), not as executable code. The lint must strip string
// contents before matching so this does not false-positive.
fn assert_something(x: Field) {
    assert(x != 0, "must not call to_be_bits::<254>() here");
}
