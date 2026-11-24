#!/usr/bin/env bash
# noir/scripts/prove-shape-classes.sh
#
# REAL UltraHonk proving harness for the ZKM circuits.
#
# WHY THIS EXISTS
# ===============
# `nargo test` runs the ACVM: it SOLVES a witness and checks the assertions. It
# never builds a constraint system and never proves. Constraints that are
# satisfiable during execution but not at proof time are therefore invisible to
# it — a circuit can have 166 green tests and still be unprovable for a shape a
# deployment will actually generate. This script closes that gap by generating
# and verifying a REAL proof per transition SHAPE CLASS.
#
# ONE PROOF PER SHAPE CLASS, NOT PER WITNESS. What varies between witnesses of
# the same kind is field values; what varies between shape classes is which
# branches carry constraints. Proving is cheap here (~0.2 s), but the coverage
# argument is about branch shapes, not volume.
#
# WHAT THIS DOES **NOT** COVER — READ THIS BEFORE TRUSTING IT
# ===========================================================
# This harness is blind to the CANONICITY/soundness class (non-canonical field
# decomposition). The honest witness solver always emits the canonical
# decomposition, so a sound circuit and an unsound one produce identical
# witnesses, identical proofs and identical verdicts. No amount of proving
# detects it. `check-field-canonicity.sh` is the only gate that IDENTIFIES
# this class -- neither `nargo test` nor this harness can. (The structural
# goldens in check-circuit-goldens.sh happen to also fail if the bug is
# reintroduced via a bytecode/VK move, but that is a blunt, undirected second
# tripwire, not a gate FOR canonicity: it cannot classify what changed, so it
# is not a substitute and must not be pruned as redundant with the
# canonicity lint.) A green run here says NOTHING about canonicity.
#
# WITNESS GENERATION
# ==================
# A ZKM witness cannot be hand-written: the sibling arrays are iterated
# Poseidon2 empty-subtree roots and every root, commitment and nullifier must be
# mutually consistent with them. So each witness is emitted by an `emit_toml_*`
# Noir test built from the SAME fixture helpers the assertion suite uses
# (`split_of`, `delegate_full_of`, `restricted_case`, ...). One source of truth:
# the transition that gets PROVED is constructed by the same code as the
# transition that gets TESTED, so a proof can never drift from the statement the
# suite checks. `Prover.toml` is generated per run and removed afterwards — it is
# gitignored and must never be committed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOIR_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NARGO="${NARGO:-nargo}"
BB="${BB:-bb}"
SCHEME="ultra_honk"

command -v "$NARGO" >/dev/null || { echo "ERROR: nargo not on PATH" >&2; exit 2; }
command -v "$BB"    >/dev/null || { echo "ERROR: bb not on PATH" >&2; exit 2; }
command -v python3  >/dev/null || { echo "ERROR: python3 not on PATH" >&2; exit 2; }

cd "$NOIR_DIR"

WORK="target/shape_classes"
rm -rf "$WORK"; mkdir -p "$WORK"

# Cleanup: Prover.toml is gitignored and must not survive the run.
cleanup() { rm -f zkm_control_attestation/Prover.toml zkm_delegate_possession/Prover.toml zkm_issuance/Prover.toml zkm_issuance_zkc/Prover.toml zkm_mandate_transition/Prover.toml zkm_revocation_auth/Prover.toml zkm_revocation_insertion/Prover.toml zkm_spend_conjoined/Prover.toml zkm_spend_zkc_binding/Prover.toml; }
trap cleanup EXIT

# package | shape-class label | emitting test | expected public-input count
#
# The mandate-only form carries NO ZKA VALUE LEG — no `zka_note_root`, no
# `zka_nullifier`, no output commitments, and no `asset_id` — and that absence
# is the §5 deployment-safety property: a VK that cannot name a value note is
# structurally incapable of authorizing value movement. So the expected counts
# below are asserted, not merely recorded.
#
SHAPES=(
  "zkm_mandate_transition|SPLIT|emit_toml_split|9"
  "zkm_mandate_transition|RETIRE|emit_toml_retire|9"
  "zkm_mandate_transition|DELEGATE_FULL|emit_toml_delegate_full|9"
  "zkm_mandate_transition|DELEGATE_FULL@policy-v2|emit_toml_delegate_full_v2|9"
  "zkm_mandate_transition|DELEGATE_PARTIAL|emit_toml_delegate_partial|9"
  "zkm_mandate_transition|ROTATE|emit_toml_rotate|9"
  "zkm_mandate_transition|SPLIT@narrowed-policy|emit_toml_split_narrowed|9"
  "zkm_mandate_transition|SPLIT@slot-2-narrowed-policy|emit_toml_split_slot2_narrowed|9"
  "zkm_mandate_transition|ROTATE@narrowed-policy|emit_toml_rotate_narrowed|9"
  "zkm_mandate_transition|DELEGATE_PARTIAL@narrowed-policy|emit_toml_delegate_partial_narrowed|9"
  "zkm_mandate_transition|SPLIT@depth-255|emit_toml_split_at_depth_255|9"
  "zkm_spend_conjoined|SPEND/unrestricted-policy|emit_toml_spend_unrestricted|14"
  "zkm_spend_conjoined|SPEND/restricted-policy|emit_toml_spend_restricted|14"
  "zkm_spend_conjoined|SPEND/policy-v2|emit_toml_spend_v2|14"
  "zkm_spend_conjoined|SPEND/amount-one|emit_toml_spend_amount_one|14"
  "zkm_spend_conjoined|SPEND/full-note|emit_toml_spend_full_note|14"
  "zkm_delegate_possession|POSSESSION/full-rebind-companion|emit_toml_possession|3"
  "zkm_issuance|ISSUANCE|emit_toml_issuance|2"
  "zkm_issuance_zkc|ISSUANCE+ZKC/scoped|emit_toml_issuance_zkc_scoped|3"
  "zkm_issuance_zkc|ISSUANCE+ZKC/linkable|emit_toml_issuance_zkc_linkable|3"
  "zkm_revocation_auth|REVOCATION_AUTH|emit_toml_revocation_auth|2"
  "zkm_revocation_insertion|REVOCATION_INSERTION|emit_toml_revocation_insertion|6"
  "zkm_control_attestation|CONTROL_ATTESTATION|emit_toml_control_attestation|3"
  "zkm_spend_zkc_binding|SPEND+ZKC/scoped|emit_toml_spend_zkc_scoped|5"
  "zkm_spend_zkc_binding|SPEND+ZKC/linkable|emit_toml_spend_zkc_linkable|5"
)

status=0

echo "=============================================================="
echo " ZKM proving harness — real UltraHonk proof per shape class"
echo "=============================================================="
echo

for pkg in zkm_control_attestation zkm_delegate_possession zkm_issuance zkm_issuance_zkc zkm_mandate_transition zkm_revocation_auth zkm_revocation_insertion zkm_spend_conjoined zkm_spend_zkc_binding; do
  echo "==> Compiling $pkg"
  "$NARGO" compile --package "$pkg" >/dev/null
  echo "==> Writing verification key for $pkg"
  mkdir -p "$WORK/vk_$pkg"
  "$BB" write_vk -s "$SCHEME" -b "target/${pkg}.json" -o "$WORK/vk_$pkg" >/dev/null 2>&1
done
echo

# The compiles above are the first point in this script that populate
# nargo's git-dep cache for noir-lang/poseidon (if not already warm). Verify
# the fetched source before proving anything with it below -- see
# docs/poseidon-dependency-upgrade.md.
bash "${SCRIPT_DIR}/check-poseidon-source-integrity.sh"
# Negative fixture: prove the gate can still detect tampering locally, not just in CI.
bash "${SCRIPT_DIR}/check-poseidon-source-integrity.sh" --self-test
echo

for row in "${SHAPES[@]}"; do
  IFS='|' read -r pkg label test expected_pi <<<"$row"
  out="$WORK/$test"
  mkdir -p "$out"

  printf '==> %-34s (%s)\n' "$label" "$pkg"

  # 1. Emit the witness from the Noir fixture helpers, via the TOML assembler.
  #    --exact matters: `emit_toml_split` is a prefix of
  #    `emit_toml_split_at_depth_255`, and a substring match would emit BOTH
  #    tests' streams into one file (the assembler would then abort on the
  #    duplicate keys, but failing loudly here is clearer).
  "$NARGO" test --package "$pkg" --show-output --exact "$test" 2>&1 \
    | awk -f scripts/prover-toml.awk > "${pkg}/Prover.toml"

  # 2. Solve the witness (this is all `nargo test` would ever have done).
  "$NARGO" execute --package "$pkg" "${test}_w" >/dev/null 2>&1

  # 3. THE POINT OF THIS SCRIPT: a real proof against a real constraint system.
  if ! "$BB" prove -s "$SCHEME" -b "target/${pkg}.json" -w "target/${test}_w.gz" \
       -o "$out" -k "$WORK/vk_$pkg/vk" >"$out/prove.log" 2>&1; then
    echo "    FAIL: bb prove failed — this shape EXECUTES but does not PROVE."
    echo "          That is exactly the gap this harness exists to catch."
    sed 's/^/          /' "$out/prove.log" | tail -10
    status=1
    continue
  fi

  # 4. And it must verify.
  if ! "$BB" verify -s "$SCHEME" -k "$WORK/vk_$pkg/vk" -p "$out/proof" \
       -i "$out/public_inputs" >"$out/verify.log" 2>&1; then
    echo "    FAIL: proof generated but did NOT verify."
    sed 's/^/          /' "$out/verify.log" | tail -10
    status=1
    continue
  fi

  # 5. Public-input SHAPE is a §5 safety property, so pin it per shape class.
  actual_pi=$(( $(wc -c < "$out/public_inputs") / 32 ))
  if [ "$actual_pi" -ne "$expected_pi" ]; then
    echo "    FAIL: public-input count is $actual_pi, expected $expected_pi."
    if [ "$pkg" = "zkm_mandate_transition" ]; then
      echo "          The mandate-only VK's public vector has CHANGED SHAPE. §5 relies on"
      echo "          it carrying no ZKA value leg (no note root, no ZKA nullifier, no"
      echo "          output commitments, no asset_id), which is what makes it structurally"
      echo "          incapable of authorizing value movement. Re-derive that safety"
      echo "          argument before touching this number."
    fi
    status=1
    continue
  fi

  echo "    ok: proved + verified, $actual_pi public inputs"
done

# ---------------------------------------------------------------------------
# NEGATIVE TIER — proofs that MUST be rejected.
#
# A gate that only ever sees things succeed cannot tell you it is working. These
# assert that verification actually discriminates, so a green positive tier
# above means something.
# ---------------------------------------------------------------------------
echo
echo "==> Negative tier: verification must REJECT these"

split_dir="$WORK/emit_toml_split"
sc_dir="$WORK/emit_toml_spend_unrestricted"
zkc_sc_dir="$WORK/emit_toml_spend_zkc_scoped"

# `mkdir -p "$out"` runs BEFORE proving for every shape class above, so the
# directory existing proves nothing -- it exists even when `bb prove` failed
# and the loop `continue`d, or when the shape's row was renamed/removed from
# SHAPES entirely. Gate on the ARTIFACTS a successful prove+verify actually
# produces. A missing prerequisite is a harness defect (a negative case that
# silently never ran), not a pass -- report it as SKIPPED and fail the run,
# so a renamed/dropped shape class cannot vanish from the negative tier while
# this script still prints "every negative case rejected".
require_proof() {
  local dir="$1" what="$2"
  if [ -f "$dir/proof" ] && [ -f "$dir/public_inputs" ]; then
    return 0
  fi
  echo "    SKIPPED (prerequisite proof missing): $what" >&2
  status=1
  return 1
}

# N1. VK NON-INTERCHANGEABILITY. A mandate-only proof must not verify against
# the spend-conjoined VK, or vice versa. This is cheap and it does pin that
# the two VKs are not interchangeable -- but be honest about the mechanism:
# it does NOT reach a cryptographic separation result. bb's Oink verifier
# aborts on a bare public-input-COUNT mismatch (mandate-only has 9,
# spend-conjoined has 14 -- both +8 for the pairing points bb appends, so 17
# vs 22) before any pairing check runs. Re-measured in rev 10 (bb 5.0.0-nightly.
# 20260522, ultra_honk); the actual failure is:
#   Assertion failed: (num_public_inputs == static_cast<size_t>(vk->num_public_inputs))
#     Actual  : 17
#     Expected: 22
#     Reason  : OinkVerifier: num_public_inputs mismatch with VK
# (These numbers are measured from a real cross-VK verify, never derived on
# paper.)
# That mismatch is strictly implied by the public-input-count assertion in
# step 5 of the positive tier above (and by the goldens' pinned
# public_input_count in check-circuit-goldens.sh) -- no ZKM source change
# could make N1 fire on its own without also tripping those. Contrast with
# N2 below, which tampers a public input WITHOUT changing its count and so
# does exercise real verification.
if require_proof "$split_dir" "mandate-only SPLIT proof (for N1)"; then
  if "$BB" verify -s "$SCHEME" -k "$WORK/vk_zkm_spend_conjoined/vk" \
       -p "$split_dir/proof" -i "$split_dir/public_inputs" >/dev/null 2>&1; then
    echo "    FAIL: a MANDATE-ONLY proof verified against the SPEND-CONJOINED VK."
    echo "          The two VKs are interchangeable: a settlement layer could settle"
    echo "          a spend against a proof that carries no ZKA value leg."
    status=1
  else
    echo "    ok: mandate-only proof REJECTED by the spend-conjoined VK"
    echo "        (bb: OinkVerifier num_public_inputs mismatch, 17 != 22 --"
    echo "         rejected at the public-input-shape check, not a"
    echo "         cryptographic separation result; see comment above)"
  fi
fi

if require_proof "$sc_dir" "spend-conjoined proof (for N1)"; then
  if "$BB" verify -s "$SCHEME" -k "$WORK/vk_zkm_mandate_transition/vk" \
       -p "$sc_dir/proof" -i "$sc_dir/public_inputs" >/dev/null 2>&1; then
    echo "    FAIL: a SPEND-CONJOINED proof verified against the MANDATE-ONLY VK."
    status=1
  else
    echo "    ok: spend-conjoined proof REJECTED by the mandate-only VK"
  fi
fi

# N4. END-TO-END COMPOSITION MATCHING. The scoped ZKC recipient-control
# companion fixture is built over the canonical unrestricted spend fixture.
# Compare the actual bb-emitted public-input bytes for every field the
# settlement rule requires to match. This is deliberately cross-artifact: a
# unit test in either package alone cannot detect fixture/API drift in the
# other.
field_hex() {
  local file="$1" index="$2"
  python3 -c 'from pathlib import Path; import sys; data=Path(sys.argv[1]).read_bytes(); index=int(sys.argv[2]); print(data[index*32:(index+1)*32].hex(), end="")' "$file" "$index"
}

write_hex_fields() {
  python3 -c 'from pathlib import Path; import sys; data=Path(sys.argv[1]).read_bytes(); sys.stdout.write("".join(data[i:i+32].hex()+"\n" for i in range(0, len(data), 32)))' "$1"
}

decode_hex_file() {
  python3 -c 'from pathlib import Path; import sys; Path(sys.argv[2]).write_bytes(bytes.fromhex(Path(sys.argv[1]).read_text(encoding="utf-8")))' "$1" "$2"
}

contains_hex_field() {
  python3 -c 'from pathlib import Path; import sys; data=Path(sys.argv[1]).read_bytes(); target=bytes.fromhex(sys.argv[2]); raise SystemExit(0 if any(data[i:i+32] == target for i in range(0, len(data), 32)) else 1)' "$1" "$2"
}

if require_proof "$sc_dir" "spend-conjoined proof (for N4)" \
   && require_proof "$zkc_sc_dir" "scoped ZKC spend companion (for N4)"; then
  spend_nf=$(field_hex "$sc_dir/public_inputs" 1)
  spend_ctx=$(field_hex "$sc_dir/public_inputs" 8)
  spend_asset=$(field_hex "$sc_dir/public_inputs" 9)
  spend_recipient=$(field_hex "$sc_dir/public_inputs" 12)
  binding_nf=$(field_hex "$zkc_sc_dir/public_inputs" 0)
  binding_recipient=$(field_hex "$zkc_sc_dir/public_inputs" 1)
  binding_asset=$(field_hex "$zkc_sc_dir/public_inputs" 2)
  binding_ctx=$(field_hex "$zkc_sc_dir/public_inputs" 3)
  if [ "$spend_nf" != "$binding_nf" ] \
     || [ "$spend_recipient" != "$binding_recipient" ] \
     || [ "$spend_asset" != "$binding_asset" ] \
     || [ "$spend_ctx" != "$binding_ctx" ]; then
    echo "    FAIL: ZKC spend companion does not match the spend-conjoined proof."
    echo "          Required equalities: nf, zka_cm_recipient, asset_id, settlement_context."
    status=1
  else
    echo "    ok: scoped ZKC companion matches the spend proof on all four settlement fields"
  fi
fi

# N2. PUBLIC-INPUT BINDING. Re-present the SPLIT proof with `kind` flipped from
# 1 (SPLIT) to 2 (RETIRE) -- same VK, same public-input COUNT, only a value
# changed. Unlike N1 above, this does exercise real verification: §5 requires
# every proof to bind the transition kind; if a tampered vector still
# verified, the published `kind` would be a free lie-vector and a settlement
# layer could be told a SPLIT was a RETIRE. This also demonstrates the
# public-input goldens are load-bearing.
if require_proof "$split_dir" "mandate-only SPLIT proof (for N2)"; then
  write_hex_fields "$split_dir/public_inputs" > "$split_dir/pi.hex"
  sed '1s/1$/2/' "$split_dir/pi.hex" > "$split_dir/pi_tampered.hex"
  if cmp -s "$split_dir/pi.hex" "$split_dir/pi_tampered.hex"; then
    echo "    FAIL: tamper set-up did not change the public inputs (kind was not 1?)."
    status=1
  else
    decode_hex_file "$split_dir/pi_tampered.hex" "$split_dir/public_inputs_tampered"
    if "$BB" verify -s "$SCHEME" -k "$WORK/vk_zkm_mandate_transition/vk" \
         -p "$split_dir/proof" -i "$split_dir/public_inputs_tampered" >/dev/null 2>&1; then
      echo "    FAIL: proof verified against TAMPERED public inputs (kind 1 -> 2)."
      echo "          The published transition kind is not bound by the proof."
      status=1
    else
      echo "    ok: tampered public inputs (kind 1 -> 2) REJECTED"
    fi
  fi
fi

# N3. THE CONTROL ATTESTATION CARRIES NO `root_id` (§5, rev 7).
#
# This is the DIRECTED gate for rev 7's headline safety property, and unlike N1
# it is not implied by any count assertion. `zkm_control_attestation` proves the
# same secret knowledge as `zkm_revocation_auth` -- the `root_id` preimage --
# but must never hand its verifier a revocation capability. §7.1 revocation is
# `root_id` INSERTION, so a settlement layer needs a public `root_id` to act on;
# the attestation publishes `H(DOMAIN, root_id, disclosure_binding)` instead, and
# the safety argument is that the vector contains no `root_id` at all.
#
# The goldens' public_input_count and the SHAPES row above WOULD fire if someone
# added a fourth public input -- but they would only say "the count moved", not
# "the lineage id leaked", and they would not fire at all if `root_id` REPLACED
# an existing element. So this case reads the real bb-emitted public inputs and
# asserts the fixture's actual `root_id` is not among them. Mutation-checked:
# publishing `root_id` in place of `lineage_tag` makes exactly this case fail.
ca_dir="$WORK/emit_toml_control_attestation"
if require_proof "$ca_dir" "control-attestation proof (for N3)"; then
  fixture_root_id=$("$NARGO" test --package zkm_control_attestation --show-output \
    --exact emit_fixture_root_id 2>&1 | sed -n 's/^fixture_root_id=0x//p' | tr -d '\r')
  if [ -z "$fixture_root_id" ]; then
    echo "    SKIPPED (could not read the fixture root_id): harness defect, not a pass." >&2
    status=1
  else
    # bb writes public inputs as raw 32-byte big-endian fields; Noir's println
    # emits a Field as minimal-width hex, so left-pad before comparing.
    padded=$(printf '%064s' "$fixture_root_id" | tr ' ' '0')
    if contains_hex_field "$ca_dir/public_inputs" "$padded"; then
      echo "    FAIL: the lineage's root_id IS a public input of the control attestation."
      echo "          That makes the attestation replayable as a §7.1 revocation"
      echo "          insertion -- a disclosure recipient could kill the lineage."
      status=1
    else
      echo "    ok: root_id absent from the control-attestation public vector"
      echo "        (3 inputs: lineage_tag, settlement_context, disclosure_binding)"
    fi
  fi
fi

echo
# A zero amount must fail during witness construction, before a proof exists.
# Each emitter describes otherwise consistent freshly blinded notes; requiring
# the exact diagnostic avoids mistaking an unrelated witness error for this gate.
for test in emit_toml_spend_zero_amount emit_toml_spend_zero_input; do
  "$NARGO" test --package zkm_spend_conjoined --show-output --exact "$test" 2>&1 \
    | awk -f scripts/prover-toml.awk > zkm_spend_conjoined/Prover.toml
  if "$NARGO" execute --package zkm_spend_conjoined "${test}_w" > "$WORK/${test}.log" 2>&1; then
    echo "    FAIL: $test unexpectedly produced a witness"
    status=1
  elif ! grep -Fq 'spend amount must be positive' "$WORK/${test}.log"; then
    echo "    FAIL: $test rejected for a different reason"
    cat "$WORK/${test}.log"
    status=1
  else
    echo "    ok: $test REJECTED by the positive-amount constraint"
  fi
done

if [ "$status" -eq 0 ]; then
  echo "PASS: every shape class proved and verified; every negative case rejected."
  echo "      (Says nothing about canonicity — see check-field-canonicity.sh.)"
else
  echo "FAIL: see above." >&2
fi

# Keep the tree small: these artifacts are large and fully regenerable.
rm -rf "$WORK"
exit "$status"
