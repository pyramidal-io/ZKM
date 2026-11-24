# Poseidon dependency upgrade runbook

ZKM depends on [`noir-lang/poseidon`](https://github.com/noir-lang/poseidon) for its Poseidon2 permutation, declared in `noir/zkm_lib/Nargo.toml`:

```toml
poseidon = { tag = "v0.3.0", git = "https://github.com/noir-lang/poseidon" }
```

Pinned upstream commit: `0880c371e88e583d39515fd3f877538657ac41eb` (tag `v0.3.0`).

## Why the tag alone is not trusted

Git tags are mutable — anyone with push access to `noir-lang/poseidon` can re-point `v0.3.0` at a different commit at any time, and `nargo` would fetch whatever the tag currently resolves to without complaint.

`nargo` gives us no way to pin harder than a tag for a git dependency:

- `rev`/`commit` keys in the `[dependencies]` table are **silently ignored** by nargo — a `Nargo.toml` with `rev = "..."` looks pinned but pins nothing. Verified against both `nargo` 1.0.0-beta.21 and 1.0.0-beta.22.
- There is no `Nargo.lock` (or equivalent) that records the resolved commit of a git dependency the way `Cargo.lock`/`package-lock.json` would.

**Do not add a `rev` or `commit` key to this dependency.** It would look like a pin and enforce nothing — see the hard rule in the CI wiring below.

Because of this, commit-level integrity has to be enforced out-of-band, with two independent, complementary checks:

1. **Pre-fetch remote-tag check** — the Forgejo protected tool `zkm-poseidon-tag-pin`, declared in `config/forgejo/zkm-protected-tools-v1.json` and run as `bash scripts/forgejo/check-poseidon-tag-pin.sh`. It runs `git ls-remote https://github.com/noir-lang/poseidon refs/tags/v0.3.0` and fails if the resolved commit isn't the pinned one. Its expected SHA is `POSEIDON_EXPECTED_SHA` (defaulting to the reviewed commit in the script). Cheap (no toolchain needed) and catches an obviously re-pointed tag early, but it is TOCTOU-vulnerable: the tag could be moved again between this check and the moment `nargo check` actually fetches the dependency a few steps later, and it never inspects the bytes nargo's cache ends up containing.

2. **Verify-after-fetch source-digest gate (this runbook's subject)** — the Forgejo protected tool `zkm-poseidon-source-integrity`, declared in `config/forgejo/zkm-protected-tools-v1.json` and run as `bash noir/scripts/check-poseidon-source-integrity.sh` after `nargo check` populates nargo's dependency cache. It hashes what nargo *actually fetched* into `${HOME}/nargo/github.com/noir-lang/poseidon/v0.3.0/`, comparing it fail-closed against the golden digest in `noir/scripts/poseidon-v0.3.0.source.sha256`. Because it hashes the consumed bytes rather than a remote claim, it holds even if the tag moves again after check 1 ran.

Defense in depth beneath both: the AFP-KDC / revocation KATs in `noir/zkm_lib/src/lib.nr` fail loudly if the Poseidon2 hash output itself ever changes, and `scripts/poseidon2.py` is an independent Python reimplementation used as a cross-language reference by other conformance checks in this repo. Neither is a substitute for checks 1 and 2 — they catch a *changed hash output*, not necessarily a *changed but hash-preserving* supply-chain compromise, and they only run where they're wired in.

## What the digest gate checks

`noir/scripts/check-poseidon-source-integrity.sh`:

- Locates the dependency source at `--dep-dir` (default: nargo's own cache path for this tag, `${HOME}/nargo/github.com/noir-lang/poseidon/v0.3.0/`). A missing cache dir is a **failure**, never a skip — the gate is fail closed, not fail open.
- Computes a sha256 over every regular file in that directory (excluding `.git/`, `target/`, `.DS_Store`), bound to relative paths, in a locale-pinned sort order, then sha256s that sorted list. This is deterministic regardless of filesystem iteration order or OS (portable across macOS `shasum` and Linux `sha256sum`).
- Compares the result against the golden in `noir/scripts/poseidon-v0.3.0.source.sha256`, which was derived from a fresh clone of the pinned, reviewed commit.
- **Corroborating check:** if the cache directory is itself a git checkout (`.git/` present), also asserts `git rev-parse HEAD` equals the pinned commit. A content-digest match with a HEAD mismatch is flagged as an inconsistent/tampered cache rather than silently accepted.
- `--self-test` proves the gate can actually detect tampering: it copies the fetched cache, mutates one byte of a `.nr` source file, and asserts the digest changes. This runs as a paired CI step (`Poseidon integrity gate self-test (negative fixture)`) immediately after the real check, so a gate that degraded into a no-op would itself be caught.
- `--print-digest` computes and prints the digest without comparing against the golden — used only for regenerating the golden below, never in a gate path.

Any failure mode — mismatched digest, missing cache, HEAD mismatch, missing or malformed golden file — exits non-zero. There is no "warn and continue" mode.

## Upgrade procedure

Follow this exactly, in order, whenever bumping the `noir-lang/poseidon` pin (including re-pinning to the *same* tag if it was found to have moved):

1. **Review the upstream diff.** Diff the currently-pinned commit against the candidate commit on `noir-lang/poseidon` directly (e.g. `git log --stat <old-commit>..<new-commit>` in a scratch clone, or the GitHub compare view). This is a security-relevant cryptographic primitive — do not fast-forward the pin without reading what changed.

2. **Update the tag in `Nargo.toml`.** Edit `noir/zkm_lib/Nargo.toml`'s `poseidon = { tag = "...", git = "..." }` line to the new tag. Update the header comment above it (the pinned commit + rationale) to match. Do **not** add a `rev`/`commit` key (see above — nargo ignores it).

3. **Update the pin constants in the gate scripts.** Edit `noir/scripts/check-poseidon-source-integrity.sh`'s `PINNED_TAG` and `PINNED_COMMIT` variables to the new tag/commit. Update the expected SHA in `scripts/forgejo/check-poseidon-tag-pin.sh` (or the protected runner's `POSEIDON_EXPECTED_SHA` setting, if it is explicitly configured) in the same reviewed change. This is a deliberate, reviewed edit to the gate itself — not something the gate can do for you, by design (a gate that could silently re-pin itself would defeat the point of it).

4. **Regenerate the golden digest** from a *fresh clone* of the new pinned commit — never from nargo's local cache, which may already reflect a stale or tampered fetch:

   ```bash
   git clone https://github.com/noir-lang/poseidon /tmp/poseidon-upgrade
   git -C /tmp/poseidon-upgrade checkout <new-commit>
   noir/scripts/check-poseidon-source-integrity.sh \
     --print-digest --dep-dir /tmp/poseidon-upgrade
   ```

   Replace the digest line in `noir/scripts/poseidon-v0.3.0.source.sha256` with the printed value (and rename the file if the tag component of its name changes, e.g. `poseidon-v0.4.0.source.sha256` — the script derives its default golden path from `PINNED_TAG`, so the filename must track the constant from step 3). Update the two leading comment lines (commit + "regenerate ONLY after a reviewed upgrade" pointer) to match.

5. **Update KAT goldens if hash outputs changed.** If the upstream diff from step 1 changes Poseidon2's actual output (not just refactoring), the KATs in `noir/zkm_lib/src/lib.nr` (and the Python reference in `scripts/poseidon2.py` / `scripts/_poseidon2_constants.py`) will need updating too. Run `nargo test --workspace` in `noir/` and the Python conformance scripts to find every KAT that needs re-deriving — do not pre-emptively edit them before confirming they actually fail.

6. **ZKA only: artifact regeneration cascade.** ZKA additionally has a downstream cascade that does *not* apply to ZKM: a Poseidon2 change moves verifier bytecode → CREATE2 addresses → `POOL_CONTEXT` → the e2e fixture, which must be regenerated **last**, in that order. See ZKA's own `docs/zka_specification.md` / artifact-regen tooling for the full sequence. ZKM has no on-chain verifier deployment, so this step does not apply here.

7. **Apply the same bump consistently across all three repos.** ZKA, ZKC, and ZKM all pin `noir-lang/poseidon` and are expected to stay in lockstep (shared KAT goldens, same proving stack). Bumping only one repo leaves the other two on a stale pin and breaks the shared-goldens assumption — treat this as one coordinated change across all three, not three independent ones.

8. **Verify locally before pushing.** Run, in the `noir/` workspace:

   ```bash
   nargo check   # populates the fresh dependency cache
   noir/scripts/check-poseidon-source-integrity.sh
   noir/scripts/check-poseidon-source-integrity.sh --self-test
   nargo test --workspace
   noir/scripts/check-circuit-goldens.sh   # add --bless only after reviewing the diff
   noir/scripts/prove-shape-classes.sh
   ```

   All must pass before opening a PR.

## The gate must never be bypassed

The executable policy source is the protected-tool manifest `config/forgejo/zkm-protected-tools-v1.json`; the workflow invokes the listed command and paired self-test. Keep their order and required heavy-tier status aligned with the manifest when upgrading the dependency.

Do not:

- Make the protected `zkm-poseidon-source-integrity` command or its paired `self_test` optional, suppress their failures with `|| true` or `continue-on-error`, or bypass them for changes classified into the heavy tier. They run after the protected compile check populates the dependency cache.
- Delete or skip the golden file instead of regenerating it through the procedure above.
- Add a `rev`/`commit` key to `Nargo.toml` as a substitute for this gate — it does not pin anything (see "Why the tag alone is not trusted").
- Treat a gate failure as something to silence rather than investigate. A failure here means either the upstream tag moved unexpectedly (treat as a supply-chain incident — do not just re-bless) or a reviewed, intentional upgrade is in flight and hasn't finished steps 3–4 above yet.

If the gate is failing and you did not just start an upgrade per this runbook, stop and treat it as a security incident, not a CI flake.
