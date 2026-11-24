// PASS fixture: the ONLY mentions of the banned `to_be_bits::<254>()` shape in
// this file are inside comments (//, ///, and /* */). A grep-only lint would
// false-positive here; this lint must strip comments before matching.
//
// Line comment:  to_be_bits::<254>() must never appear in real code.
/// Doc comment:  see also `to_be_bits::<254>()` for the historical bug.
/*
 * Block comment mentioning to_be_bits::<254>() too, spanning several lines
 * just to make sure the block-comment stripper survives it.
 */
pub fn low_128_bits(value: Field) -> Field {
    let (lo, _hi) = std::field::bn254::decompose(value);
    lo
}
