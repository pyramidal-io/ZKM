#!/usr/bin/env bash
# =============================================================================
# TXE test runner for the ZKM Aztec workspace (mirrors ZKA's aztec/scripts/
# txe-test.sh discipline, leaner).
#
# Runs, from anywhere:
#   1. Verify the audited local ZKA snapshot without a network fetch.
#   2. Clean compile of the workspace with `aztec compile --force` from the
#      workspace ROOT (postprocessing scans ./target relative to CWD; a member-
#      dir compile silently skips transpilation -- the ZKA TRAP 1a/1b).
#   3. A dedicated TXE oracle on ${TXE_PORT:-8082} in its own process group.
#   4. `aztec-nargo test` per package, SERIALLY (--test-threads 1): the stock
#      `aztec test` hardcodes 16 threads and flakes on LMDB (mdb_txn_begin: 22).
#
# Positional args select mandate tests; all pure library tests always run, e.g.:
#   ./scripts/txe-test.sh test::split_conserves_the_cap_across_two_children
#
# Env overrides: TXE_PORT (8082), TEST_THREADS (1), TXE_READY_TIMEOUT_SECONDS
# (60), TXE_LOG_TAIL_LINES (300; oracle log lines printed when a run fails),
# TXE_RESTART_EVERY (4; positive batch size, fresh oracle for each batch),
# TXE_STOP_TIMEOUT_SECONDS (10; graceful shutdown deadline before SIGKILL).
# macOS: /opt/homebrew/bin must lead PATH (Homebrew bash >= 4).
# =============================================================================
set -euo pipefail

AZTEC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TXE_PORT="${TXE_PORT:-8082}"
TEST_THREADS="${TEST_THREADS:-1}"
TXE_READY_TIMEOUT_SECONDS="${TXE_READY_TIMEOUT_SECONDS:-60}"
TXE_LOG_TAIL_LINES="${TXE_LOG_TAIL_LINES:-300}"
TXE_RESTART_EVERY="${TXE_RESTART_EVERY:-4}"
TXE_STOP_TIMEOUT_SECONDS="${TXE_STOP_TIMEOUT_SECONDS:-10}"
for value in TXE_READY_TIMEOUT_SECONDS TXE_STOP_TIMEOUT_SECONDS; do
    if [[ ! "${!value}" =~ ^[1-9][0-9]{0,3}$ ]]; then
        echo "$value must be an integer from 1 to 9999" >&2
        exit 1
    fi
done
if [[ ! "$TXE_RESTART_EVERY" =~ ^[1-9][0-9]{0,2}$ ]]; then
    echo "TXE_RESTART_EVERY must be an integer from 1 to 999" >&2
    exit 1
fi

export PATH="/opt/homebrew/bin:$PATH"
export NARGO_FOREIGN_CALL_TIMEOUT="${NARGO_FOREIGN_CALL_TIMEOUT:-300000}"

cd "$AZTEC_DIR"

[[ "$(aztec --version)" == "6.0.0" ]] || {
    echo "TXE requires Aztec 6.0.0 on PATH" >&2
    exit 1
}
aztec-nargo --version | grep -Fx 'nargo version = 1.0.0-rc.3' >/dev/null || {
    echo "TXE requires aztec-nargo 1.0.0-rc.3 on PATH" >&2
    exit 1
}

echo "== Verify the immutable ZKA dependency before compile =="
bash "${AZTEC_DIR}/scripts/check-zka-source-integrity.sh"

echo "== Clean compile (workspace root, --force) =="
rm -rf target zkm_aztec_lib/target zkm_mandate_aztec/target
aztec compile --force

echo "== Verify fetched Aztec dependency source integrity =="
bash "${AZTEC_DIR}/scripts/check-aztec-source-integrity.sh"
bash "${AZTEC_DIR}/scripts/check-aztec-source-integrity.sh" --self-test

echo "== Verify vendored ZKA dependency source integrity =="
bash "${AZTEC_DIR}/scripts/check-zka-source-integrity.sh"
bash "${AZTEC_DIR}/scripts/check-zka-source-integrity.sh" --self-test

# Nargo imports the ZKA interface but emits artifacts only for local members.
# Compile the verified snapshot and copy its generated artifact for TXE.
# Nargo searches ancestor workspaces, so compile outside ZKM's
# workspace. Check the copied bytes before and after compilation as well.
ZKA_BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zkm-zka-build.XXXXXX")"
trap 'rm -rf "$ZKA_BUILD_DIR"' EXIT
cp -R "${AZTEC_DIR}/vendor/zka/." "$ZKA_BUILD_DIR/"
bash "${AZTEC_DIR}/scripts/check-zka-source-integrity.sh" --dep-dir "$ZKA_BUILD_DIR"
echo "== Compile verified ZKA snapshot artifact =="
(cd "${ZKA_BUILD_DIR}/aztec" && aztec compile --force &&
    aztec-nargo test --silence-warnings --package zka_aztec_lib)
bash "${AZTEC_DIR}/scripts/check-zka-source-integrity.sh" --dep-dir "$ZKA_BUILD_DIR"
cp \
    "${ZKA_BUILD_DIR}/aztec/target/zka_transfer_aztec-ZKATransfer.json" \
    "${AZTEC_DIR}/target/zka_transfer_aztec-ZKATransfer.json"
rm -rf "$ZKA_BUILD_DIR"
trap - EXIT

echo "== Pure tests (no oracle) =="
aztec-nargo test --silence-warnings --package zkm_aztec_lib

# Capture discovery's status before parsing its output. A process substitution
# would hide a failed listing command that happened to print some test names.
if test_listing="$(aztec-nargo test --list-tests --silence-warnings \
    --package zkm_mandate_aztec "$@")"; then
    :
else
    status=$?
    printf '%s\n' "$test_listing" >&2
    echo "TXE test discovery failed" >&2
    exit "$status"
fi
names=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ ! "$line" =~ ^zkm_mandate_aztec\ ([a-zA-Z_][a-zA-Z_0-9]*::)*[a-zA-Z_][a-zA-Z_0-9]*$ ]]; then
        echo "Malformed TXE test discovery output: $line" >&2
        exit 1
    fi
    name="${line#zkm_mandate_aztec }"
    for previous in "${names[@]}"; do
        if [[ "$previous" == "$name" ]]; then
            echo "Duplicate TXE test discovered: $name" >&2
            exit 1
        fi
    done
    names+=("$name")
done <<< "$test_listing"
if (( ${#names[@]} == 0 )); then
    echo "No TXE tests discovered for zkm_mandate_aztec" >&2
    exit 1
fi
echo "== Discovered ${#names[@]} TXE tests; at most ${TXE_RESTART_EVERY} per oracle =="

TXE_LOG="$(mktemp -t zkm-txe.XXXXXX.log)"
TEST_LOG="$(mktemp -t zkm-txe-tests.XXXXXX.log)"
TXE_PGID=""
TEST_PGID=""
TXE_STATE=stopped
TXE_STATUS=0
terminate_group() {
    local pgid="$1"
    [[ -n "$pgid" ]] || return 0
    kill -- -"$pgid" 2>/dev/null || true
    local deadline=$((SECONDS + TXE_STOP_TIMEOUT_SECONDS))
    while kill -0 "$pgid" 2>/dev/null && (( SECONDS < deadline )); do
        sleep 0.2
    done
    kill -KILL -- -"$pgid" 2>/dev/null || true
}
stop_oracle() {
    if [[ -n "$TXE_PGID" ]]; then
        TXE_STATE=running
        TXE_STATUS=0
        oracle_is_running || TXE_STATE=exited
        terminate_group "$TXE_PGID"
        wait "$TXE_PGID" 2>/dev/null || TXE_STATUS=$?
        TXE_PGID=""
        # A normal requested TERM exits cleanly or with 128 + SIGTERM.
        # SIGKILL, including an OOM just after the last liveness check, must
        # remain a failure even when the test command already returned zero.
        if [[ "$TXE_STATE" != running || ( "$TXE_STATUS" != 0 && "$TXE_STATUS" != 143 ) ]]; then
            echo "TXE oracle stopped unexpectedly (state ${TXE_STATE}, wait status ${TXE_STATUS})" >&2
            return 1
        fi
    fi
}
cleanup() {
    local status=$?
    terminate_group "$TEST_PGID"
    [[ -z "$TEST_PGID" ]] || wait "$TEST_PGID" 2>/dev/null || true
    stop_oracle || true
    if [[ "$status" -ne 0 ]]; then
        {
            echo "--- TXE oracle was ${TXE_STATE} at failure (wait status ${TXE_STATUS}) ---"
            for file in /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.max; do
                [[ -r "$file" ]] && echo "${file}: $(tr '\n' ' ' <"$file")"
            done
            echo "--- TXE log (last ${TXE_LOG_TAIL_LINES} lines) ---"
            tail -n "$TXE_LOG_TAIL_LINES" "$TXE_LOG"
        } >&2 || true
    fi
    rm -f "$TXE_LOG" "$TEST_LOG"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

oracle_is_running() {
    local state
    [[ -n "$TXE_PGID" ]] && kill -0 "$TXE_PGID" 2>/dev/null || return 1
    state="$(ps -o stat= -p "$TXE_PGID" 2>/dev/null)" || return 1
    [[ -n "$state" && "$state" != *Z* && "$state" != *X* ]]
}
start_oracle() {
    # Never accept readiness supplied by a surviving or unrelated listener.
    if nc -z 127.0.0.1 "$TXE_PORT" 2>/dev/null; then
        echo "TXE port :${TXE_PORT} is already in use" >&2
        return 1
    fi
    echo "== Starting TXE oracle on :${TXE_PORT} =="
    set -m
    aztec start --txe --port "$TXE_PORT" >>"$TXE_LOG" 2>&1 &
    TXE_PGID=$!
    set +m
    local deadline=$((SECONDS + TXE_READY_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
        if ! oracle_is_running; then
            echo "TXE oracle exited during startup" >&2
            return 1
        fi
        if nc -z 127.0.0.1 "$TXE_PORT" 2>/dev/null; then
            oracle_is_running || return 1
            return 0
        fi
        sleep 0.2
    done
    echo "TXE oracle did not come up on :${TXE_PORT} within ${TXE_READY_TIMEOUT_SECONDS}s" >&2
    return 1
}

# Nargo's --exact accepts the discovered names as separate arguments. Verify
# the reported count too: a successful command that selected zero tests cannot
# turn a malformed filter or a future CLI change into a green gate.
run_batch() {
    local status=0 count
    set -m
    aztec-nargo test --silence-warnings \
        --oracle-resolver "http://127.0.0.1:${TXE_PORT}" \
        --test-threads "$TEST_THREADS" --package zkm_mandate_aztec \
        --exact "$@" >"$TEST_LOG" 2>&1 &
    TEST_PGID=$!
    set +m
    while kill -0 "$TEST_PGID" 2>/dev/null; do
        if ! oracle_is_running; then
            terminate_group "$TEST_PGID"
            wait "$TEST_PGID" 2>/dev/null || true
            TEST_PGID=""
            cat "$TEST_LOG"
            echo "TXE oracle exited during test execution; aborting remaining tests" >&2
            return 1
        fi
        sleep 0.2
    done
    wait "$TEST_PGID" || status=$?
    TEST_PGID=""
    cat "$TEST_LOG"
    (( status == 0 )) || return "$status"
    if ! oracle_is_running; then
        echo "TXE oracle exited during test execution" >&2
        return 1
    fi
    # rc.3 colors its summary even when stdout is redirected.
    count="$(sed -E $'s/\033\\[[0-9;]*m//g' "$TEST_LOG" \
        | sed -nE 's/^\[zkm_mandate_aztec\] ([0-9]+) tests? passed$/\1/p')"
    if [[ "$count" != "$#" ]]; then
        echo "TXE batch coverage mismatch: expected $# tests, reported ${count:-no count}" >&2
        return 1
    fi
}

executed=0
while (( executed < ${#names[@]} )); do
    batch=("${names[@]:executed:TXE_RESTART_EVERY}")
    start_oracle
    echo "== TXE batch: ${#batch[@]} tests ($executed/${#names[@]} completed) =="
    run_batch "${batch[@]}"
    executed=$((executed + ${#batch[@]}))
    stop_oracle
done
echo "== All Aztec workspace tests passed; TXE coverage ${executed}/${#names[@]} =="
