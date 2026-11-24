#!/usr/bin/env bash
# noir/scripts/check-circuit-goldens.sh
#
# STRUCTURAL GOLDENS for the ZKM bin circuits.
#
# WHY THIS EXISTS
# ================
# ZKA tried pinning soundness by asserting that decompose's PLO/PHI modulus
# limbs appear somewhere in the compiled bytecode. That does NOT work as a
# gate: bb's constant-deduplication keeps limb counts identical across a real
# fix, so a ">= 1 occurrence" check passes on unsound code just as happily as
# on sound code. This script pins STRUCTURE instead -- the VK hash, the
# public-input shape, and the ACIR bytecode -- properties that move iff the
# circuit actually moves.
#
# For each bin circuit (zkm_control_attestation, zkm_delegate_possession,
# zkm_issuance, zkm_issuance_zkc, zkm_mandate_transition, zkm_revocation_auth,
# zkm_spend_conjoined, zkm_spend_zkc_binding) this pins:
#   1. VK HASH            -- read verbatim from bb's own `write_vk` output
#                             (<dir>/vk_hash). We never re-hash the VK
#                             ourselves. This is the deploy-cascade tripwire:
#                             a settlement layer pins a VK, so an unnoticed VK
#                             move silently invalidates deployed verifiers.
#   2. PUBLIC INPUT COUNT  -- derived from the compiled artifact's ABI
#                             (parameters with visibility "public"), WITHOUT
#                             proving. This is a LOAD-BEARING SAFETY PROPERTY,
#                             not just a number, and it carries TWO arguments.
#                             (a) Both transition-circuit headers argue the
#                             mandate-only VK is "structurally incapable of
#                             authorizing value movement" precisely because it
#                             carries no ZKA value leg -- no note root, no ZKA
#                             nullifier, no output commitments, no asset_id.
#                             (b) zkm_control_attestation carries no `root_id`,
#                             which is what stops a
#                             disclosure recipient replaying it as a §7.1
#                             revocation. If either count changes, the matching
#                             safety argument has broken -- see the loud error
#                             below and the N3 case in prove-shape-classes.sh.
#   3. ACIR STRUCTURE      -- `nargo info`'s ACIR-opcode count for `main`,
#                             plus a sha256 of the compiled `bytecode` field
#                             ONLY (never the whole artifact JSON, which also
#                             carries toolchain/debug metadata that churns
#                             independent of the circuit).
#
# A diff against goldens/circuits.txt is a PROTOCOL CHANGE. It must be
# reviewed and understood before re-blessing -- `--bless` regenerates the
# file unconditionally and is meant to be run ONLY after you have confirmed
# the new values are intended, never as a reflex to make CI green.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOIR_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GOLDEN_FILE="${SCRIPT_DIR}/goldens/circuits.txt"

NARGO="${NARGO:-nargo}"
BB="${BB:-bb}"
SCHEME="ultra_honk"

command -v "$NARGO" >/dev/null || { echo "ERROR: nargo not on PATH" >&2; exit 2; }
command -v "$BB"    >/dev/null || { echo "ERROR: bb not on PATH" >&2; exit 2; }
command -v jq       >/dev/null || { echo "ERROR: jq not on PATH" >&2; exit 2; }
command -v python3  >/dev/null || { echo "ERROR: python3 not on PATH" >&2; exit 2; }
command -v shasum   >/dev/null || { echo "ERROR: shasum not on PATH" >&2; exit 2; }

cd "$NOIR_DIR"

BLESS=0
for arg in "$@"; do
  case "$arg" in
    --bless) BLESS=1 ;;
    *) echo "ERROR: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# package | known-truth expected public-input count (cross-check only; the
# derivation below must AGREE with these -- if it disagrees, the derivation
# is wrong, not these numbers).
CIRCUITS=(
  "zkm_control_attestation|3"
  "zkm_delegate_possession|3"
  "zkm_issuance|2"
  "zkm_issuance_zkc|3"
  "zkm_mandate_transition|9"
  "zkm_revocation_auth|2"
  "zkm_revocation_insertion|6"
  "zkm_spend_conjoined|14"
  "zkm_spend_zkc_binding|5"
)

WORK="target/.golden_check"
rm -rf "$WORK"; mkdir -p "$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# jq filter: sum of field-elements contributed by every public ABI parameter.
# u8/u64/u128/Field (integer/field/boolean) each occupy exactly ONE field
# element. Arrays/structs/tuples are walked recursively so this stays correct
# if a circuit ever grows a public array or struct param.
PUBLIC_INPUT_COUNT_JQ='
def elem_count:
  if .kind == "array" then (.length * (.type | elem_count))
  elif .kind == "struct" then ([.fields[].type | elem_count] | add // 0)
  elif .kind == "tuple" then ([.fields[] | elem_count] | add // 0)
  else 1
  end;
[.abi.parameters[] | select(.visibility == "public") | .type | elem_count] | add // 0
'

compute_row() {
  local pkg="$1"
  local artifact="target/${pkg}.json"

  "$NARGO" compile --package "$pkg" >/dev/null

  local pub_count bytecode_hash opcode_count vk_hash
  pub_count=$(jq "$PUBLIC_INPUT_COUNT_JQ" "$artifact")
  bytecode_hash=$(jq -r '.bytecode' "$artifact" | shasum -a 256 | awk '{print $1}')

  local info_out
  info_out=$("$NARGO" info --package "$pkg")
  opcode_count=$(echo "$info_out" | awk -F'|' '{
    for (i=1;i<=NF;i++) { gsub(/^[ \t]+|[ \t]+$/, "", $i) }
    if ($3 == "main") print $4
  }')
  if [ -z "$opcode_count" ]; then
    echo "ERROR: could not parse ACIR opcode count for '$pkg' out of \`nargo info\` output:" >&2
    echo "$info_out" >&2
    exit 2
  fi

  local vkdir="$WORK/vk_$pkg"
  mkdir -p "$vkdir"
  "$BB" write_vk -s "$SCHEME" -b "$artifact" -o "$vkdir" >/dev/null 2>&1
  vk_hash=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).read_bytes().hex(), end="")' "$vkdir/vk_hash")

  echo "${pkg}|${vk_hash}|${pub_count}|${opcode_count}|${bytecode_hash}"
}

# Cross-check the public-input derivation against known truth BEFORE doing
# anything else with it. If this disagrees, the DERIVATION is wrong -- fix
# the jq filter above, never the expected numbers.
for row in "${CIRCUITS[@]}"; do
  IFS='|' read -r pkg expected_pub <<<"$row"
  "$NARGO" compile --package "$pkg" >/dev/null
  actual_pub=$(jq "$PUBLIC_INPUT_COUNT_JQ" "target/${pkg}.json")
  if [ "$actual_pub" != "$expected_pub" ]; then
    echo "ERROR: public-input count derivation disagrees with known truth for '$pkg'." >&2
    echo "       Derived: $actual_pub   Known truth: $expected_pub" >&2
    echo "       The derivation logic is wrong -- fix it, do not change the expected number." >&2
    exit 2
  fi
done

# The compiles above are the first point in this script that populate
# nargo's git-dep cache for noir-lang/poseidon (if not already warm). Verify
# the fetched source before trusting anything derived from it below -- see
# docs/poseidon-dependency-upgrade.md.
bash "${SCRIPT_DIR}/check-poseidon-source-integrity.sh"
# Negative fixture: prove the gate can still detect tampering locally, not just in CI.
bash "${SCRIPT_DIR}/check-poseidon-source-integrity.sh" --self-test

if [ "$BLESS" -eq 1 ]; then
  mkdir -p "$(dirname "$GOLDEN_FILE")"
  {
    echo "# noir/scripts/goldens/circuits.txt"
    echo "#"
    echo "# STRUCTURAL GOLDENS for the ZKM bin circuits (zkm_control_attestation,"
    echo "# zkm_delegate_possession, zkm_issuance, zkm_mandate_transition,"
    echo "# zkm_issuance_zkc, zkm_revocation_auth, zkm_spend_conjoined,"
    echo "# zkm_spend_zkc_binding), generated by"
    echo "# check-circuit-goldens.sh --bless."
    echo "#"
    echo "# A diff against this file is a PROTOCOL CHANGE and requires review. It"
    echo "# must NOT be blindly re-blessed to make CI green -- understand WHY each"
    echo "# value moved before regenerating."
    echo "#"
    echo "# Regenerate (only once you have reviewed and intend the change):"
    echo "#   noir/scripts/check-circuit-goldens.sh --bless"
    echo "#"
    echo "# FIELDS (pipe-delimited):"
    echo "#   package | vk_hash | public_input_count | acir_opcode_count | bytecode_sha256"
    echo "#"
    echo "#   vk_hash              - UltraHonk verification-key hash, read verbatim from"
    echo "#                          bb write_vk's own <dir>/vk_hash (hex-dumped, never"
    echo "#                          re-hashed by us). The deploy-cascade tripwire: a"
    echo "#                          settlement layer pins a VK, so an unnoticed VK move"
    echo "#                          silently invalidates deployed verifiers."
    echo "#   public_input_count   - Count of ABI parameters with visibility \"public\", in"
    echo "#                          field-elements (u8/u64/u128/Field = 1 each)."
    echo "#                          LOAD-BEARING SAFETY PROPERTY, twice over."
    echo "#                          zkm_mandate_transition carries NO ZKA VALUE LEG (no"
    echo "#                          note root, no ZKA nullifier, no output commitments,"
    echo "#                          no asset_id) -- that absence is what makes its VK"
    echo "#                          \"structurally incapable of authorizing value"
    echo "#                          movement\". zkm_control_attestation carries NO"
    echo "#                          root_id -- that absence is what stops a disclosure"
    echo "#                          recipient replaying it as a §7.1 revocation. If"
    echo "#                          either count changes, the matching safety argument"
    echo "#                          has broken and must be re-derived, not re-blessed"
    echo "#                          away. (Both are stated in the circuits' own headers.)"
    echo "#   acir_opcode_count    - \`nargo info\`'s ACIR-opcode count for \`main\`. Moves"
    echo "#                          iff the circuit's constraint structure moves."
    echo "#   bytecode_sha256      - sha256 of the compiled \`.bytecode\` field ONLY, not"
    echo "#                          the whole artifact JSON (which also carries"
    echo "#                          toolchain/debug metadata that churns independent of"
    echo "#                          the circuit)."
    echo "#"
    echo "package|vk_hash|public_input_count|acir_opcode_count|bytecode_sha256"
    for row in "${CIRCUITS[@]}"; do
      IFS='|' read -r pkg _ <<<"$row"
      compute_row "$pkg"
    done
  } > "$GOLDEN_FILE"
  echo "Blessed goldens written to $GOLDEN_FILE"
  cat "$GOLDEN_FILE"
  exit 0
fi

# --- Check mode -------------------------------------------------------------

if [ ! -f "$GOLDEN_FILE" ]; then
  echo "ERROR: no golden file at $GOLDEN_FILE" >&2
  echo "       Run: noir/scripts/check-circuit-goldens.sh --bless" >&2
  exit 2
fi

# bash 3.2 (macOS default) has no associative arrays, so look each package's
# expected row up directly out of the golden file instead of pre-loading a map.
lookup_expected() {
  local pkg="$1"
  grep -m1 "^${pkg}|" "$GOLDEN_FILE" | cut -d'|' -f2-
}

status=0
for row in "${CIRCUITS[@]}"; do
  IFS='|' read -r pkg _ <<<"$row"

  # grep finds zero matches on an empty/header-only/partially-corrupted golden
  # file and exits 1; under `set -e` an unguarded assignment would kill the
  # whole script right here, silently swallowing this and every later
  # package's check. Guard it so a missing row is reported and the loop moves
  # on to check the remaining packages.
  expected_fields="$(lookup_expected "$pkg" || true)"
  if [ -z "$expected_fields" ]; then
    echo "FAIL: $pkg has no row in $GOLDEN_FILE" >&2
    status=1
    continue
  fi

  actual="$(compute_row "$pkg")"
  actual_fields="${actual#*|}"   # drop leading "pkg|"

  if [ "$actual_fields" = "$expected_fields" ]; then
    echo "ok: $pkg matches golden ($actual)"
    continue
  fi

  status=1
  IFS='|' read -r a_vk a_pub a_op a_bc <<<"$actual_fields"
  IFS='|' read -r e_vk e_pub e_op e_bc <<<"$expected_fields"

  echo "FAIL: $pkg does not match $GOLDEN_FILE" >&2
  echo "      This is a PROTOCOL CHANGE. Review it -- do not blindly --bless." >&2

  if [ "$a_vk" != "$e_vk" ]; then
    echo "      vk_hash:              expected $e_vk" >&2
    echo "                            actual   $a_vk" >&2
    echo "                            The VK changed. Any settlement layer that pinned" >&2
    echo "                            the old VK will silently reject/mis-verify proofs" >&2
    echo "                            against this circuit until it re-deploys the new" >&2
    echo "                            verifier. Treat this as a deploy-cascade event." >&2
  fi

  if [ "$a_pub" != "$e_pub" ]; then
    echo "      public_input_count:   expected $e_pub" >&2
    echo "                            actual   $a_pub" >&2
    if [ "$pkg" = "zkm_mandate_transition" ]; then
      echo "                            THE §5 SAFETY ARGUMENT JUST BROKE: zkm_mandate_transition's" >&2
      echo "                            public-input vector no longer matches the shape that makes" >&2
      echo "                            its VK \"structurally incapable of authorizing value" >&2
      echo "                            movement\" (no ZKA value leg: no note root, no ZKA" >&2
      echo "                            nullifier, no output commitments, no asset_id)." >&2
      echo "                            Re-derive that safety argument from scratch before touching" >&2
      echo "                            this golden -- do NOT re-bless without review." >&2
    elif [ "$pkg" = "zkm_control_attestation" ]; then
      echo "                            THE §5 DISCLOSURE SAFETY ARGUMENT MAY HAVE BROKEN:" >&2
      echo "                            zkm_control_attestation must publish (lineage_tag," >&2
      echo "                            settlement_context, disclosure_binding) and NO root_id --" >&2
      echo "                            publishing one makes the attestation replayable as a §7.1" >&2
      echo "                            revocation insertion. Check the N3 case in" >&2
      echo "                            prove-shape-classes.sh, which tests this directly, before" >&2
      echo "                            re-blessing." >&2
    else
      echo "                            zkm_spend_conjoined's public-input shape (asset_id and the" >&2
      echo "                            ZKA-linkage fields; NOT amount, which rev 7 made private," >&2
      echo "                            nor policy_hash, removed in rev 5) has changed. Any" >&2
      echo "                            settlement layer parsing the public-input vector by" >&2
      echo "                            position/count needs to be re-checked against this." >&2
    fi
  fi

  if [ "$a_op" != "$e_op" ]; then
    echo "      acir_opcode_count:    expected $e_op" >&2
    echo "                            actual   $a_op" >&2
  fi

  if [ "$a_bc" != "$e_bc" ]; then
    echo "      bytecode_sha256:      expected $e_bc" >&2
    echo "                            actual   $a_bc" >&2
  fi
done

if [ "$status" -eq 0 ]; then
  echo "PASS: all circuit goldens match."
else
  echo "FAIL: circuit goldens do not match. See above." >&2
fi

exit "$status"
