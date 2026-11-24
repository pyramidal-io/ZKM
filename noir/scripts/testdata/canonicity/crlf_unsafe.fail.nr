// REGRESSION FIXTURE — adversarial review, CRITICAL finding.
//
// This file has CRLF line endings. An earlier awk implementation trimmed only
// spaces and tabs, so a trailing \r meant no line ever ended in ;{} — every
// statement ran to EOF, the whole file collapsed into one, and the leftmost
// annotation masked the entire file. There is no .gitattributes normalising
// line endings in this repo, so CRLF input is reachable from a contributor.
pub fn wide(value: Field) -> Field {
    let bits: [bool; 254] = value.to_be_bits();
    0
}
