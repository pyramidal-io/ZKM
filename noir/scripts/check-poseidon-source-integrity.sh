#!/usr/bin/env bash
# check-poseidon-source-integrity.sh — fail-closed source-identity gate for the
# noir-lang/poseidon git dependency (declared by tag, which git allows to move).
#
# Verifies the dependency source that nargo ACTUALLY fetched (its on-disk cache)
# against a committed golden digest derived from the reviewed upstream commit.
# This is a verify-after-fetch check: unlike a `git ls-remote` tag gate, it holds
# even if the remote tag moves between the check and the fetch (TOCTOU), because
# it hashes what the build consumed, not what the remote claimed.
#
# Usage:
#   check-poseidon-source-integrity.sh [--dep-dir <path>] [--golden <file>]
#   check-poseidon-source-integrity.sh --self-test [--dep-dir <path>]
#   check-poseidon-source-integrity.sh --print-digest [--dep-dir <path>]
#     (prints the computed digest and exits; for regenerating the golden after
#      a REVIEWED dependency upgrade — see the upgrade runbook)
#
# Exit codes: 0 = verified; 1 = integrity failure or missing input (fail closed).
#
# The digest covers every regular file in the dependency checkout except .git/,
# target/, and .DS_Store, bound to relative paths, in a locale-pinned order.
# Portable across macOS bash 3.2 (no `set -e` + `[[ ]]` interaction, shasum) and
# Linux CI (sha256sum).
set -uo pipefail

PINNED_TAG="v0.3.0"
PINNED_COMMIT="0880c371e88e583d39515fd3f877538657ac41eb"
DEFAULT_DEP_DIR="${HOME}/nargo/github.com/noir-lang/poseidon/${PINNED_TAG}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEP_DIR="${DEFAULT_DEP_DIR}"
GOLDEN_FILE="${SCRIPT_DIR}/poseidon-${PINNED_TAG}.source.sha256"
SELF_TEST=0
PRINT_DIGEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dep-dir) DEP_DIR="$2"; shift 2 ;;
    --golden)  GOLDEN_FILE="$2"; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    --print-digest) PRINT_DIGEST=1; shift ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 1 ;;
  esac
done

if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
else
  SHA_CMD="shasum -a 256"
fi

compute_digest() {
  # $1 = directory. Digest = sha256 over the sorted list of "<sha256>  <relpath>"
  # lines for every regular file except .git/, target/, .DS_Store.
  ( cd "$1" && \
    find . -type f ! -path './.git/*' ! -path './target/*' ! -name '.DS_Store' -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 ${SHA_CMD} \
      | ${SHA_CMD} \
      | cut -d' ' -f1 )
}

file_count() {
  ( cd "$1" && \
    find . -type f ! -path './.git/*' ! -path './target/*' ! -name '.DS_Store' | wc -l | tr -d ' ' )
}

fail() {
  echo "POSEIDON SOURCE INTEGRITY: FAIL — $1" >&2
  exit 1
}

if [ ! -d "${DEP_DIR}" ]; then
  fail "dependency cache not found at ${DEP_DIR}. Run this check AFTER 'nargo compile' (which populates the cache). A missing cache is treated as failure (fail closed), never skipped."
fi

COUNT="$(file_count "${DEP_DIR}")"
if [ "${COUNT}" -eq 0 ]; then
  fail "dependency cache at ${DEP_DIR} contains no files"
fi

ACTUAL="$(compute_digest "${DEP_DIR}")"
if [ -z "${ACTUAL}" ]; then
  fail "could not compute digest of ${DEP_DIR}"
fi

if [ "${PRINT_DIGEST}" -eq 1 ]; then
  echo "${ACTUAL}"
  exit 0
fi

if [ "${SELF_TEST}" -eq 1 ]; then
  # Negative fixture: prove the digest detects a single-byte source change.
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP}"' EXIT
  cp -R "${DEP_DIR}" "${TMP}/dep"
  rm -rf "${TMP}/dep/.git" "${TMP}/dep/target"
  find "${TMP}/dep" -name '.DS_Store' -delete
  MUTANT="$(cd "${TMP}/dep" && find . -type f -name '*.nr' | LC_ALL=C sort | head -1)"
  if [ -z "${MUTANT}" ]; then
    fail "self-test: no .nr source file found to mutate"
  fi
  printf 'x' >> "${TMP}/dep/${MUTANT}"
  PRISTINE="$(compute_digest "${TMP}/dep")"  # digest of mutated copy
  if [ "${PRISTINE}" = "${ACTUAL}" ]; then
    fail "self-test: digest did NOT change after mutating ${MUTANT} — the gate cannot detect tampering"
  fi
  echo "POSEIDON SOURCE INTEGRITY: self-test OK (mutation of ${MUTANT} changed the digest)"
  exit 0
fi

if [ ! -f "${GOLDEN_FILE}" ]; then
  fail "golden digest file not found at ${GOLDEN_FILE}"
fi
GOLDEN="$(grep -v '^#' "${GOLDEN_FILE}" | grep -m1 . | tr -d '[:space:]')"
if ! printf '%s' "${GOLDEN}" | grep -Eq '^[0-9a-f]{64}$'; then
  fail "golden digest file ${GOLDEN_FILE} does not contain a 64-hex-char sha256"
fi

if [ "${ACTUAL}" != "${GOLDEN}" ]; then
  fail "source digest mismatch for noir-lang/poseidon ${PINNED_TAG}
  expected (golden, reviewed commit ${PINNED_COMMIT}): ${GOLDEN}
  actual   (fetched cache ${DEP_DIR}):                 ${ACTUAL}
The fetched dependency does not match the reviewed source. Either the upstream
tag was moved/repointed or the local cache was modified. Do NOT bypass this
gate. Remediation: delete the cache dir, re-fetch, re-run; if the mismatch
persists, the tag no longer points at the reviewed commit — follow the
Poseidon dependency upgrade runbook (review the diff before accepting)."
fi

# Corroborating check when the cache is a git clone: HEAD must be the pinned commit.
if [ -d "${DEP_DIR}/.git" ]; then
  HEAD_COMMIT="$(git -C "${DEP_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ "${HEAD_COMMIT}" != "${PINNED_COMMIT}" ]; then
    fail "cache git HEAD is ${HEAD_COMMIT}, expected pinned commit ${PINNED_COMMIT} (content digest matched, which suggests an inconsistent or tampered cache — delete ${DEP_DIR} and re-fetch)"
  fi
fi

echo "POSEIDON SOURCE INTEGRITY: OK (${PINNED_TAG} @ ${PINNED_COMMIT}, digest ${ACTUAL})"
