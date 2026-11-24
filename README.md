# ZKM public source snapshot

This repository is a source-only, non-production reference for the ZKM
protocol materials included in this snapshot. It is intended for review,
reproducibility work, and interoperability-oriented development.

The protocol specification is [the ZKM specification](docs/zkm_specification.md),
generated from the canonical source with only reviewed informative tracking
references and public-manifest provenance wording replaced. Its normative text
is unchanged by that projection.
Read it together with the included protocol-family manifests and vectors before
implementing or evaluating protocol behavior. The included `PUBLIC_SURFACE`
manifest defines the complete tracked file set for this snapshot; an unlisted
tracked file is a gate failure. `protocol-family/public-projection-v1.json`
records the scanner-clean manifest projection separately, so
`snapshot-lock.json` remains valid under the strict canonical lock schema.

## Reproducible verification

Run the following as one fail-fast Bash block from the repository root. The
protocol and license checks require Python 3.11 or newer and Git. The circuit checks require the exact
Nargo and Barretenberg versions declared in `.noir-version`; the Solidity
build requires Foundry `1.7.1` and the authenticated solc `0.8.27` binary.
Gitleaks `8.30.1` and TruffleHog `3.97.0` must already be installed from the
checksum-pinned archives named below.

```bash
(
set -euo pipefail
python3 .github/scripts/check-public-surface.py
python3 .github/scripts/check-third-party-licenses.py --profile static

test "$(gitleaks version)" = "8.30.1"
test "$(trufflehog --version)" = "trufflehog 3.97.0"
scanner_output="$(mktemp)"
trap 'rm -f "$scanner_output"' EXIT
if ! gitleaks dir . --redact=100 --ignore-gitleaks-allow --no-banner >"$scanner_output" 2>&1; then
  echo "gitleaks rejected the public snapshot" >&2
  exit 1
fi
: >"$scanner_output"
if ! trufflehog filesystem . --json --no-update --fail --fail-on-scan-errors >"$scanner_output" 2>&1; then
  echo "trufflehog rejected the public snapshot" >&2
  exit 1
fi
: >"$scanner_output"

python3 scripts/check-zkm-statement-registry.py
python3 scripts/check-zkm-statement-registry.py --self-test
python3 scripts/check-zkc-envelope-kat.py
python3 scripts/validate_protocol_family.py validate --repo zkm --root .
python3 scripts/migrate-revocation-v2.py --self-test
bash noir/scripts/check-field-canonicity.sh --self-test
bash noir/scripts/check-field-canonicity.sh

source .noir-version
test "$(nargo --version | sed -n 's/^nargo version = //p')" = "$NARGO_VERSION"
test "$(bb --version | head -1 | tr -d '\r')" = "$BB_VERSION"

expected_poseidon=0880c371e88e583d39515fd3f877538657ac41eb
test "$(git ls-remote https://github.com/noir-lang/poseidon refs/tags/v0.3.0 | cut -f1)" = "$expected_poseidon"
(cd noir && nargo check)
bash noir/scripts/check-poseidon-source-integrity.sh
bash noir/scripts/check-poseidon-source-integrity.sh --self-test
(cd noir && nargo fmt --check)
(cd noir && nargo test --workspace)
bash noir/scripts/check-circuit-goldens.sh
bash noir/scripts/prove-shape-classes.sh
forge --version | grep -F "1.7.1"
solc_path="$(command -v solc-0.8.27)"
"$solc_path" --version | grep -F "Version: 0.8.27+commit.40a35a09.Linux.g++"
forge soldeer install
python3 .github/scripts/check-third-party-licenses.py \
  --profile noir-solidity \
  --poseidon-dir "$HOME/nargo/github.com/noir-lang/poseidon/v0.3.0" \
  --forge-std-dir dependencies/forge-std-1.9.7
forge build --force --offline --use "$solc_path"
)
```

The registry check re-derives the committed statement surface; the
protocol-family validator binds it to the projected manifest and lock. The
circuit-golden check recompiles every circuit and compares verification-key
hashes, public-input shapes, ACIR structure, and bytecode digests. The shape
harness then constructs and verifies real UltraHonk proofs; it is not
interchangeable with the unit or structural gates.

`noir-lang/poseidon` is a mutable Nargo git-tag dependency: beta.25 does not
honour a commit pin or write a lock file. Do not treat the tag lookup as enough.
The source-integrity check must run after `nargo check`, and its self-test must
also pass. A missing cache, changed tag, changed fetched source, or a toolchain
version mismatch is a failure to investigate, not a condition to bypass.

The Aztec profile uses a separate fail-fast runner so its large toolchain cannot
silently disappear from the release gate:

```bash
bash .github/scripts/run-aztec-ci.sh
```

That script verifies the mutable `aztec-nr` tag, runs the shipped TXE
harness in the official Aztec `6.0.0` linux/amd64 image pinned by manifest
digest, and verifies the exact fetched source and license bytes after compile.
It requires Docker and an amd64-capable runtime; emulation on another
architecture is valid but slower. The runtime image no longer bundles Nargo;
the profile authenticates the official Noir `1.0.0-rc.3` archive separately
(amd64 SHA-256 `5792dd962afce1eed834570f95d9f72cc4a09d45cd846d3b80b7a57392732973`).
The standalone Noir/Barretenberg profile retains its separate pins below.

The pinned tree of the transitive `noir-lang/sha256` v0.3.0 dependency has no
license file; its `package.json` MIT declaration belongs to the TypeScript oracle
server, not the Noir library. The maintainers accept the Apache-2.0 `LICENSE`
that upstream added in commit `50f5fda729d94848aabcd9d54dc7751460e9143a` as
license evidence for v0.3.0. The license gate binds the vendored copy at
`aztec/licenses/noir-lang-sha256/LICENSE` by SHA-256 and allows this kind of
evidence for that one dependency only.

Public CI authenticates every downloaded executable before it can run. Its
Linux/amd64 pins are Nargo `1.0.0-beta.25`
(`bf3410ab94933a4aebd1f988b67ae974c6c227f9456ed0f1e4a3716bb8a30fe9`),
Barretenberg `5.0.0`
(`4b42a64a0587e1e15089f7a20c87fa2d8a092acb4fc95465a798a73b98ba794d`),
Gitleaks `8.30.1`
(`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`),
TruffleHog `3.97.0`
(`62224de2f9dd7cd418800feb953760a302ed2f82a7c547fe1146a4874fb179e4`),
Foundry `1.7.1`
(`cf7e688ed0c4c48adffca788b496076e31060b67ac5afe1e43dbb5499c20c88b`),
and solc `0.8.27+commit.40a35a09`
(`b9977d500c17cba6f0032ca939ef98c4decf6363f19f386d05fb02f708115264`).
The exact release URLs and archive names are executable configuration in
`.github/workflows/ci.yml`. The Aztec image pin is
`sha256:59b10cc8e89bb9226db1f771a5abbe5d5f8d71483c00c7472187e6ddc7adab8d`.
The workflow runs both scanners before any package manager, compiler, or test
can create output and never prints an unredacted finding payload.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting. The
dependency declarations, approved SPDX expressions, source/archive pins, and
license-file digests are closed by `THIRD_PARTY_LICENSES.json`; an unknown or
changed external dependency fails CI.

The Aztec profile includes a byte-identical, integrity-pinned ZKA source closure
in `aztec/vendor/zka/`. It requires no ZKA credentials or repository fetch;
its license is included and checked by the offline license gate.
