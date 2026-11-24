#!/usr/bin/env bash
# noir/scripts/check-field-canonicity.sh
#
# SOURCE-LEVEL CANONICITY GATE for ZKM's Noir circuits. DEFENCE IN DEPTH.
#
# The class: a decomposition of a Field into >= 254 bits (or >= 32 bytes) whose
# only binding is per-limb range checks plus ONE recomposition equation. That
# equation holds modulo p, so over BN254 both `x` and `x + k*p` satisfy it (~32%
# of the field admits a second witness) and an adversarial prover picks
# whichever suits them. If the limbs index anything -- a tree slot, a nullifier,
# a comparison -- the circuit is unsound.
#
# WHAT THE TOOLCHAIN DOES (MEASURED, nargo 1.0.0-beta.25 / bb 5.0.0). The stdlib
# `to_{le,be}_bits::<254>()` and `to_{le,be}_bytes::<32>()` are NOT that shape:
# at full width they also compare the limbs against the modulus in-circuit (the
# `!is_unconstrained()` block in noir_stdlib/src/field/mod.nr), which is why they
# compile to ~1160 / ~450 opcodes rather than ~257. A forged x + k*p witness
# injected into the production ACIR is rejected by the ACVM and fails bb verify,
# for k = 1 and k = 5 and for the x = 0 -> p boundary, while a hand-rolled
# decomposition of the shape above accepts the same forgery and verifies with a
# changed public output. Experiment and record:
#   scripts/canonicity-forgery/run.sh
#   docs/security/2026-10-04-field-canonicity-beta25-forgery.md
# Re-run it on every Noir toolchain bump: that, not this gate, is what would
# notice the stdlib dropping its comparison.
#
# WHY THE GATE STAYS. ZKM's convention is that every full-width decomposition
# goes through `std::field::bn254::decompose`, which carries its own `< p`
# assertion and yields 128-bit limbs whose further decomposition cannot wrap. The
# gate keeps that one auditable spelling, so the soundness of a slot index never
# rests on a width-dependent stdlib branch that reviewers must re-derive per
# toolchain. It replaced `zkm_lib::low_128_bits` (PR #4), whose
# `value.to_be_bits::<254>()` was treated as this bug; the stdlib source pinned at
# the time (beta.22) already carried the comparison, so that hazard was most
# likely never exploitable -- unverified by execution, since only beta.25 is
# measured. Honest tooling cannot tell the two apart either way: when the gate
# landed, reintroducing that code left all 166 tests and all 7 shape-class
# proofs green, because the witness solver only ever emits canonical limbs.
#
# WHAT IT DOES NOT SEE. The genuinely unsound shape -- limbs from an
# `unconstrained` hint, range-checked and recomposed by hand -- need not mention
# `to_*_bits`/`to_*_bytes` at all, and then passes this scanner. The compiler's
# under-constrained checks do not flag it either. Review hint-fed decompositions
# by hand.
# (`check-circuit-goldens.sh` also moves when a decomposition changes, because
# the bytecode changes -- but that is a blunt, undirected tripwire that fires on
# ANY circuit edit and cannot say what changed. It is not a substitute, and it
# must not be pruned as redundant with this gate.)
#
# The detector itself lives in scripts/lib/scan_decompositions.py. It TOKENIZES
# Noir rather than scanning raw lines, because a line-oriented regex is defeated
# by numeric separators (`::<2_54>`), widths past a fixed digit count, `//`
# inside string literals or block comments, statements split across lines, CRLF
# input, and — the one that actually got past an earlier awk implementation of
# this gate in review — a narrow array annotation sorting ahead of a wide one in
# the same binding. See that file's module docstring for the full list.
#
# Three checks, cheapest first. Check 1 must pass for checks 2 and 3 to mean
# anything, which is why the detector self-tests before it is trusted.
#   1. detector self-test (in-process cases, incl. every known evasion)
#   2. fixture corpus     (file-level verdicts, with the fixture counts pinned)
#   3. the real circuits
#
# Usage:
#   ./noir/scripts/check-field-canonicity.sh              # run all three checks
#   ./noir/scripts/check-field-canonicity.sh --self-test  # checks 1 + 2 only
#   ./noir/scripts/check-field-canonicity.sh path/to.nr   # scan given paths
#
# Exit 0 = clean, 1 = violation(s), 2 = usage/internal error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOIR_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCANNER="${SCRIPT_DIR}/lib/scan_decompositions.py"
TESTDATA_DIR="${SCRIPT_DIR}/testdata/canonicity"
PYTHON="${PYTHON:-python3}"

# The fixture corpus is pinned by COUNT as well as by verdict. Without this, a
# corpus that loses its .fail.nr half still reports "all verdicts correct" — the
# negative fixtures are the only ones that demonstrate the gate has teeth, so
# their silent disappearance must break the build.
readonly EXPECTED_PASS_FIXTURES=6
readonly EXPECTED_FAIL_FIXTURES=8

command -v "$PYTHON" >/dev/null 2>&1 || {
  echo "ERROR: python3 not on PATH (needed by ${SCANNER})" >&2; exit 2; }
[ -f "$SCANNER" ] || { echo "ERROR: detector missing at ${SCANNER}" >&2; exit 2; }

# ---------------------------------------------------------------------------
detector_self_test() {
  echo "==> [1/3] Detector self-test"
  if ! "$PYTHON" "$SCANNER" --self-test; then
    echo "::error::the decomposition detector failed its own self-test; every" >&2
    echo "::error::verdict it produces below is untrustworthy. Fix the detector." >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
fixture_corpus() {
  echo "==> [2/3] Fixture corpus: ${TESTDATA_DIR}"
  [ -d "$TESTDATA_DIR" ] || { echo "::error::fixtures missing at ${TESTDATA_DIR}" >&2; return 1; }

  local failures=0 n_pass=0 n_fail=0 f base expected actual
  for f in "${TESTDATA_DIR}"/*.nr; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    case "$base" in
      *.pass.nr) expected=0; n_pass=$((n_pass + 1)) ;;
      *.fail.nr) expected=1; n_fail=$((n_fail + 1)) ;;
      *) echo "    ERROR  ${base}: must be named *.pass.nr or *.fail.nr" >&2
         failures=$((failures + 1)); continue ;;
    esac

    actual=0
    "$PYTHON" "$SCANNER" "$f" >/dev/null 2>&1 || actual=$?

    if [ "$actual" -eq "$expected" ]; then
      printf '    ok (%s): %s\n' "$([ "$expected" -eq 0 ] && echo clean || echo rejected)" "$base"
    else
      printf '    FAILED %s: expected %s, got exit %s\n' "$base" \
        "$([ "$expected" -eq 0 ] && echo clean || echo rejected)" "$actual" >&2
      "$PYTHON" "$SCANNER" "$f" 2>&1 | sed 's/^/           /' >&2 || true
      failures=$((failures + 1))
    fi
  done

  if [ "$n_pass" -ne "$EXPECTED_PASS_FIXTURES" ] || [ "$n_fail" -ne "$EXPECTED_FAIL_FIXTURES" ]; then
    echo "::error::fixture count changed: found ${n_pass} *.pass.nr and ${n_fail} *.fail.nr," >&2
    echo "::error::expected ${EXPECTED_PASS_FIXTURES} and ${EXPECTED_FAIL_FIXTURES}. The negative" >&2
    echo "::error::fixtures are the only evidence this gate has teeth — if you added or removed" >&2
    echo "::error::one deliberately, update EXPECTED_*_FIXTURES in this script." >&2
    failures=$((failures + 1))
  fi

  [ "$failures" -eq 0 ] || { echo "    fixture corpus: FAIL (${failures})" >&2; return 1; }
  echo "    ${n_pass} clean + ${n_fail} rejected, all verdicts correct"
}

# ---------------------------------------------------------------------------
scan_circuits() {
  echo "==> [3/3] Scanning the real circuits"
  # The fixture dir is excluded: it deliberately contains unsound code. The
  # scanner exits 2 if it reached zero files, so an invocation that silently
  # scans nothing fails instead of reporting a clean tree.
  "$PYTHON" "$SCANNER" "$NOIR_DIR" --exclude "$TESTDATA_DIR"
}

# ---------------------------------------------------------------------------
explain_failure() {
  cat >&2 <<'EOF'

::error::A full-width field decomposition was found.
::error::
::error::A decomposition into >= 254 bits (or >= 32 bytes) is unique only if the
::error::circuit also proves its limbs encode a value < p; otherwise both x and
::error::x + k*p satisfy it, and if the value indexes anything -- a tree slot, a
::error::nullifier, a comparison -- an adversarial prover chooses the witness.
::error::The stdlib `to_*_bits`/`to_*_bytes` carry that comparison under the pinned
::error::toolchain (scripts/canonicity-forgery/run.sh), but ZKM does not rest
::error::soundness on a width-dependent stdlib branch, and neither `nargo test` nor
::error::the bb harness can tell a sound decomposition from an unsound one. Do not
::error::silence this gate; use the canonical spelling:
::error::
::error::    let (lo, hi) = std::field::bn254::decompose(value);
::error::
::error::(A "cannot statically resolve the width" report fails CLOSED on purpose:
::error::the width may be 32 bytes inferred from a callee. Add a turbofish.)
EOF
}

main() {
  if [ "${1:-}" = "--self-test" ]; then
    detector_self_test && fixture_corpus
    return $?
  fi

  # Explicit paths: scan just those (used by the fixture runner and ad-hoc).
  if [ "$#" -gt 0 ]; then
    "$PYTHON" "$SCANNER" "$@" || { explain_failure; return 1; }
    return 0
  fi

  local status=0
  detector_self_test || status=1
  echo
  fixture_corpus || status=1
  echo
  if [ "$status" -eq 0 ]; then
    scan_circuits || { explain_failure; status=1; }
  else
    echo "==> [3/3] SKIPPED: the detector or its corpus is broken, so a clean" >&2
    echo "    verdict on the real circuits would be meaningless." >&2
    status=1
  fi

  echo
  if [ "$status" -eq 0 ]; then
    echo "Field-canonicity gate: PASS"
  else
    echo "Field-canonicity gate: FAIL" >&2
  fi
  return "$status"
}

main "$@"
