# `protocol-family/` — public projection provenance

This scanner-clean public snapshot deliberately distinguishes canonical family
artifacts from the reviewed public projection. It is a source-only reference;
it does not assert that every file at a canonical family path has the same
bytes as the canonical family package.

## Unmodified canonical family inputs

`interface-manifest-v1.schema.json`, `golden-vectors-v1.json`, and
`../scripts/validate_protocol_family.py` are selected unchanged from the
reviewed ZKM source. They retain their canonical-family validation role.

## Scanner-clean public projection

The public `interface-manifest-v1.json` removes only the AFP-KDC fixture
binding and assertion that cannot be shipped under the trusted no-exception
scanner policy. The public `snapshot-lock.json` retains the named canonical
family revision and unchanged digests, but recomputes `manifest_sha256` from
the exact projected manifest bytes. The separate `public-projection-v1.json`
record identifies that scanner-clean projection explicitly, without extending
the strict canonical snapshot-lock schema.

The public cutover note, ZKM statement registry, and registry checker are also
reviewed projections: they retain the runnable statement/circuit consumer
surface while omitting claims that the excluded standalone fixture or its
checker is available. Run `../scripts/validate_protocol_family.py validate
--repo zkm --root .` together with the registry checker to validate this
public projection. A cross-repository canonical-family audit must instead use
the canonical family package under its own reviewed controls.

The statement checker compares the exact §5 statement set with the cutover
note's normative statement/package, lifecycle and retirement tables, and checks
both public vectors. Only `zkm_spend_conjoined` is value-moving; the
recipient-control companion does not settle value. Public return values are part
of a circuit's public ABI and cannot be added without changing the declared
vector.
