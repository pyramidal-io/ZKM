#!/usr/bin/env bash
# Verify the source tree that aztec-nargo fetches for the v6.0.0 dependency.
#
# Nargo resolves the public tag, rather than an immutable commit.  This checker
# makes that resolution fail closed before a TXE test consumes the dependency.
set -euo pipefail

readonly PINNED_TAG="v6.0.0"
readonly PINNED_COMMIT="0472012201fdff1429d184f8d25cecf13ca94326"
readonly PINNED_TREE="c61208aecb259512aad72fbea0986b9f10b1ed93"
readonly PINNED_ORIGIN="https://github.com/aztec-labs-eng/aztec-nr"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEP_DIR="${HOME}/nargo/github.com/aztec-labs-eng/aztec-nr/${PINNED_TAG}"
GOLDEN_FILE="${SCRIPT_DIR}/aztec-${PINNED_TAG}.source.sha256"
PRINT_DIGEST=0
SELF_TEST=0

usage() {
    cat <<'EOF'
Usage: check-aztec-source-integrity.sh [options]

Verify the immutable identity of the Aztec v6.0.0 source fetched by
aztec-nargo.  A normal invocation requires a clean Git checkout with the
expected origin, tag, commit, tree, file count, source digest, and LICENCE.

Options:
  --dep-dir PATH       Fetched aztec-nr checkout to verify.
  --golden PATH        Source identity manifest to verify against.
  --print-digest       Print the filtered source digest only; do not verify.
  --self-test          Exercise digest exclusions with a tiny temporary fixture.
  -h, --help           Show this help.
EOF
}

fail() {
    echo "Aztec source-integrity check failed: $*" >&2
    exit 1
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
    else
        sha256sum "$@"
    fi
}

source_digest() {
    (
        cd "$1"
        # Match every regular file in bytewise path order, while excluding
        # VCS metadata, generated target subtrees, and Finder metadata.
        if command -v shasum >/dev/null 2>&1; then
            find . \
                \( -type d \( -name .git -o -name target \) -prune \) -o \
                \( -type f ! -name '.DS_Store' -print0 \) |
                LC_ALL=C sort -z |
                xargs -0 shasum -a 256 |
                shasum -a 256 |
                awk '{print $1}'
        else
            find . \
                \( -type d \( -name .git -o -name target \) -prune \) -o \
                \( -type f ! -name '.DS_Store' -print0 \) |
                LC_ALL=C sort -z |
                xargs -0 sha256sum |
                sha256sum |
                awk '{print $1}'
        fi
    )
}

source_file_count() {
    (
        cd "$1"
        find . \
            \( -type d \( -name .git -o -name target \) -prune \) -o \
            \( -type f ! -name '.DS_Store' -print0 \) |
            tr -cd '\0' |
            wc -c |
            tr -d '[:space:]'
    )
}

golden_value() {
    local key="$1"
    local value
    if ! value="$(awk -F= -v key="$key" '
        $1 == key { count += 1; value = $2 }
        END {
            if (count == 1 && value != "") {
                print value
                exit 0
            }
            exit 1
        }
    ' "$GOLDEN_FILE")"; then
        fail "golden manifest must contain exactly one nonempty \"${key}=\" entry"
    fi
    printf '%s\n' "$value"
}

run_self_test() {
    local fixture_root baseline after_excluded mutation
    fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/zkm-aztec-integrity.XXXXXX")"
    trap 'rm -rf "$fixture_root"' EXIT

    mkdir -p "$fixture_root/src" "$fixture_root/target" "$fixture_root/.git"
    printf 'canonical source\n' >"$fixture_root/src/main.nr"
    baseline="$(source_digest "$fixture_root")"
    [[ "$(source_file_count "$fixture_root")" == "1" ]] ||
        fail "self-test fixture unexpectedly counted excluded files"

    printf 'generated artifact\n' >"$fixture_root/target/output"
    printf 'git internals\n' >"$fixture_root/.git/HEAD"
    printf 'Finder metadata\n' >"$fixture_root/.DS_Store"
    after_excluded="$(source_digest "$fixture_root")"
    [[ "$after_excluded" == "$baseline" ]] ||
        fail "self-test exclusion rules changed the source digest"

    printf 'mutated source\n' >>"$fixture_root/src/main.nr"
    mutation="$(source_digest "$fixture_root")"
    [[ "$mutation" != "$baseline" ]] ||
        fail "self-test failed to detect a source mutation"
    trap - EXIT
    rm -rf "$fixture_root"
    echo "Aztec source-integrity self-test passed."
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --dep-dir)
            [[ "$#" -ge 2 ]] || fail "--dep-dir requires a path"
            DEP_DIR="$2"
            shift 2
            ;;
        --golden)
            [[ "$#" -ge 2 ]] || fail "--golden requires a path"
            GOLDEN_FILE="$2"
            shift 2
            ;;
        --print-digest)
            PRINT_DIGEST=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[[ "$PRINT_DIGEST" -eq 0 || "$SELF_TEST" -eq 0 ]] ||
    fail "--print-digest and --self-test cannot be combined"

if [[ "$SELF_TEST" -eq 1 ]]; then
    run_self_test
    exit 0
fi

[[ -d "$DEP_DIR" ]] || fail "dependency directory does not exist: $DEP_DIR"

if [[ "$PRINT_DIGEST" -eq 1 ]]; then
    source_digest "$DEP_DIR"
    exit 0
fi

[[ -f "$GOLDEN_FILE" ]] || fail "golden manifest does not exist: $GOLDEN_FILE"

golden_format="$(golden_value format)"
golden_tag="$(golden_value tag)"
golden_commit="$(golden_value commit)"
golden_tree="$(golden_value tree)"
golden_file_count="$(golden_value file_count)"
golden_source_sha256="$(golden_value source_sha256)"
golden_license_sha256="$(golden_value license_sha256)"

[[ "$golden_format" == "zkm:aztec-source-integrity:v1" ]] ||
    fail "unsupported golden manifest format: $golden_format"
[[ "$golden_tag" == "$PINNED_TAG" ]] || fail "golden tag is not $PINNED_TAG"
[[ "$golden_commit" == "$PINNED_COMMIT" ]] || fail "golden commit does not match pinned commit"
[[ "$golden_tree" == "$PINNED_TREE" ]] || fail "golden tree does not match pinned tree"
[[ "$golden_file_count" =~ ^[0-9]+$ ]] || fail "golden file_count is not numeric"
[[ "$golden_source_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "golden source_sha256 is malformed"
[[ "$golden_license_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "golden license_sha256 is malformed"

checkout_root="$(cd "$DEP_DIR" && pwd -P)"
[[ "$(git -C "$DEP_DIR" rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]] ||
    fail "dependency is not a Git checkout"
[[ "$(git -C "$DEP_DIR" rev-parse --show-toplevel)" == "$checkout_root" ]] ||
    fail "dependency directory is not the Git checkout root"
[[ "$(git -C "$DEP_DIR" remote get-url origin)" == "$PINNED_ORIGIN" ]] ||
    fail "origin does not match $PINNED_ORIGIN"
[[ "$(git -C "$DEP_DIR" rev-parse HEAD)" == "$PINNED_COMMIT" ]] ||
    fail "HEAD does not match pinned commit"
[[ "$(git -C "$DEP_DIR" rev-parse "HEAD^{tree}")" == "$PINNED_TREE" ]] ||
    fail "HEAD tree does not match pinned tree"
[[ "$(git -C "$DEP_DIR" rev-parse "refs/tags/$PINNED_TAG^{}")" == "$PINNED_COMMIT" ]] ||
    fail "annotated tag $PINNED_TAG does not resolve to pinned commit"
[[ -z "$(git -C "$DEP_DIR" status --porcelain=v1 --untracked-files=all)" ]] ||
    fail "checkout is not clean"
git -C "$DEP_DIR" fsck --no-dangling --no-reflogs

actual_file_count="$(source_file_count "$DEP_DIR")"
[[ "$actual_file_count" == "$golden_file_count" ]] ||
    fail "file count was $actual_file_count, expected $golden_file_count"
actual_source_sha256="$(source_digest "$DEP_DIR")"
[[ "$actual_source_sha256" == "$golden_source_sha256" ]] ||
    fail "source digest was $actual_source_sha256, expected $golden_source_sha256"
[[ -f "$DEP_DIR/LICENCE" ]] || fail "LICENCE is missing"
actual_license_sha256="$(sha256 "$DEP_DIR/LICENCE" | awk '{print $1}')"
[[ "$actual_license_sha256" == "$golden_license_sha256" ]] ||
    fail "LICENCE digest was $actual_license_sha256, expected $golden_license_sha256"

echo "Aztec source integrity verified: $PINNED_TAG ($PINNED_COMMIT)."

# V6 splits the Noir interface into a separate repository. Its protocol types
# and SHA256 implementation are still transitive public Git dependencies.
# Pin both fetched checkouts before TXE consumes the compiled sources.
verify_transitive() {
    local repo="$1" tag="$2" commit="$3" tree="$4" digest="$5"
    local dependency="${HOME}/nargo/github.com/${repo}/${tag}"
    [[ -d "$dependency" ]] || fail "missing transitive dependency $repo"
    [[ "$(git -C "$dependency" remote get-url origin)" == "https://github.com/$repo" ]] || fail "$repo origin changed"
    [[ "$(git -C "$dependency" rev-parse HEAD)" == "$commit" ]] || fail "$repo commit changed"
    [[ "$(git -C "$dependency" rev-parse 'HEAD^{tree}')" == "$tree" ]] || fail "$repo tree changed"
    [[ "$(git -C "$dependency" rev-parse "refs/tags/$tag^{}")" == "$commit" ]] || fail "$repo tag changed"
    [[ -z "$(git -C "$dependency" status --porcelain=v1 --untracked-files=all)" ]] || fail "$repo checkout is not clean"
    [[ "$(source_digest "$dependency")" == "$digest" ]] || fail "$repo source digest changed"
    echo "Transitive source integrity verified: $repo $tag ($commit)."
}
verify_transitive AztecProtocol/aztec-packages v6.0.0 \
    0219f11d8133970df3974fe5ae65e006bf8c193a 26adfe78f6cd666661acff8e7b7a180c30d188d5 \
    c6bc3bd4e4b7ccdf5f189663dfda7b633887f5697be580497cbe9d43d512171e
verify_transitive noir-lang/sha256 v0.3.0 \
    9442e5b6856f98b2ec029882d7e90199ecff91ba a2195e3de699e078b05f30d692f68f39d187e4fc \
    fc2b0c1ca6747439846ae5d815bacefc5a0e615d236ab3705b1d1d1a01cdeeae
verify_transitive noir-lang/poseidon v0.4.0 \
    e105cdd5c79c222860d53c5dfdb8fa8012b291c0 b7e193dd876841ac99651df389f8e4453f4be9c5 \
    4453fa59e6482d7ce976a643bc62793161c8e08a98b1cdfe0711b667a1b6c104
