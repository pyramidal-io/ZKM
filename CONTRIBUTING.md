# Contributing

Contributions must preserve the source-only scope of this reference snapshot.
Keep changes focused, document their rationale, and update deterministic
vectors or validation material when a protocol-facing change requires it.

Before proposing a change, run the verification commands in `README.md`.
`PUBLIC_SURFACE` is closed-world: update it only when the final public tracked
file set intentionally changes, and never use it to mask an unexpected file.

Protocol-facing edits must keep all of these checks passing:

- the statement-registry derivation and protocol-family projection validator;
- the revocation-v2 migration self-test;
- the exact `.noir-version` Nargo and Barretenberg checks; and
- the Poseidon remote-tag and post-fetch source-integrity checks, followed by
  formatting, workspace tests, and the circuit structural goldens;
- real proof generation/verification for every Noir shape class;
- the digest-pinned Aztec `6.0.0` image, fetched-source integrity check, and TXE
  workspace tests;
- the locked Foundry dependency install and Solidity build; and
- both fail-closed public secret scanners; and
- the closed third-party dependency and license inventory.

Nargo `1.0.0-beta.25` cannot commit-pin its git dependencies or generate a
dependency lock file. Do not add a nominal `rev` or `commit` field to
`noir/zkm_lib/Nargo.toml`: that would look secure while providing no pin. A
Poseidon or toolchain update requires a reviewed update to the declared
versions, source digest, and structural goldens; never use `--bless` merely to
make a changed circuit pass.

An external dependency change must update `THIRD_PARTY_LICENSES.json` in the
same review, including its immutable source or archive identity, SPDX
expression, and exact license-file digest. Do not bypass a missing cache,
unknown dependency, moved tag, or license mismatch.

Report suspected vulnerabilities privately through the repository control
described in `SECURITY.md`; do not put proof-of-concept details in a public
issue before maintainers can assess them.
