// REGRESSION FIXTURE — adversarial review, CRITICAL finding.
//
// An earlier awk implementation of this gate resolved a decomposition's width
// from the FIRST array annotation in the statement. Both statements below are
// idiomatic Noir that compiles, and both carry a genuine reintroduction of the
// PR #4 revocation-slot bug hidden behind a narrow annotation that sorts first.
// The gate reported "none found" on the real bug.
//
// The detector must consider EVERY annotation in a binding, never the leftmost.
pub fn low_128_bits(value: Field) -> Field {
    let (_pad, bits): ([bool; 8], [bool; 254]) = ([false; 8], value.to_be_bits());
    let mut low: Field = 0;
    low
}

pub fn tuple_masked(x: Field, y: Field) -> Field {
    let (a, b): ([u8; 16], [u8; 32]) = (x.to_be_bytes(), y.to_be_bytes());
    0
}
