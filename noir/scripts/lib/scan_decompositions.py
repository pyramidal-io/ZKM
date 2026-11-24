#!/usr/bin/env python3
"""Report Noir statements that decompose a Field into >= 254 bits or >= 32 bytes.

The class this guards: a full-width decomposition bound only by per-limb range
checks and a single recomposition equation. That equation holds modulo p, so
over BN254 (2^253 < p < 2^254) both `x` and `x + k*p` are valid witnesses with
different limbs -- ~32% of the field admits a second one -- and an adversarial
prover picks whichever suits them.

The stdlib calls this scanner matches are NOT that shape under the pinned
toolchain. MEASURED (nargo 1.0.0-beta.25, bb 5.0.0): at full width
`to_{le,be}_bits::<254>()` and `to_{le,be}_bytes::<32>()` also compare their
limbs against the modulus in-circuit, and a forged x + k*p witness is rejected
by the ACVM and fails bb verify; a hand-rolled decomposition of the shape above
accepts the same forgery. See scripts/canonicity-forgery/run.sh and
docs/security/2026-10-04-field-canonicity-beta25-forgery.md.

So this is DEFENCE IN DEPTH, and a convention: ZKM spells every full-width
decomposition `std::field::bn254::decompose`, which carries its own `< p`
assertion, instead of resting a slot index on a width-dependent stdlib branch.
It replaced `zkm_lib::low_128_bits` (PR #4), whose `to_be_bits::<254>()` was
taken to be this bug; the stdlib pinned then (beta.22) already had the
comparison in source, so that was most likely never exploitable (not measured).
Honest tooling cannot tell either way -- the witness solver only emits canonical
limbs, so when this gate landed, reintroducing that code left all 166 tests and
all 7 shape-class proofs green.

BLIND SPOT. The genuinely unsound shape -- limbs from an `unconstrained` hint,
recomposed by hand -- need not name `to_*_bits`/`to_*_bytes` at all, and then
this scanner passes it. Review hint-fed decompositions by hand.

A REGEX OVER RAW LINES IS NOT SUFFICIENT. Every one of these is legal Noir that
a line-oriented scan misses:

    x.to_be_bits::<2_54>()                       numeric separators are permitted
    x.to_be_bits::<1000>()                       width past a fixed digit count
    let s = "https://e"; x.to_be_bits::<254>()   `//` inside a string literal
    /* note // here */ x.to_be_bits::<254>()     `//` inside a block comment
    let b:\n  [bool; 254] =\n  x.to_be_bits();   statement split across lines

and, found by adversarial review of this repo's earlier awk implementation,
which resolved the width from the FIRST array annotation in the statement:

    let (_pad, bits): ([bool; 8], [bool; 254]) = ([false; 8], v.to_be_bits());
    let (a, b): ([u8; 16], [u8; 32]) = (x.to_be_bytes(), y.to_be_bytes());

Both are idiomatic Noir, both compile, and both hid a genuine reintroduction of
the PR #4 bug behind a narrow annotation that happened to sort first. The fix is
structural: consider EVERY annotation in a binding, not the leftmost. CRLF input
was a second blind spot -- a `\r` left on the line meant no line ever looked
terminated, so the whole file collapsed into one statement and the leftmost
annotation then masked the entire file.

So this tokenizes first -- stripping line comments, nestable block comments, and
string/raw-string/format-string literals -- then splits into statements and
matches the surviving code.

Usage: scan_decompositions.py <root-dir> [--exclude DIR]... | --self-test
Prints `path:line: statement` per finding; exit 1 if any, 0 if none.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator  # noqa: F401  (used in string annotations)
import re
import sys

# Widths at or above which range checks plus recomposition alone stop
# determining the input (the stdlib adds a modulus comparison at exactly these
# widths; see the module docstring).
# 254 bits and 32 bytes (256 bits) both exceed the BN254 scalar field; 128-bit,
# 32-bit and <= 31-byte decompositions cannot wrap p and are deliberately fine.
MIN_BITS = 254
MIN_BYTES = 32

# Widths are matched as [0-9_]+, not \d+: Noir permits `_` as a visual separator
# inside a numeric literal, so `2_54` is 254 and must not slip past.
_TURBOFISH = re.compile(r"\bto_(?:be|le)_(bits|bytes)\s*::\s*<\s*([0-9][0-9_]*)\s*>")
_ANNOTATION = re.compile(r"\[\s*(bool|u1|u8)\s*;\s*([0-9][0-9_]*)\s*\]")
_CALL = re.compile(r"\bto_(?:be|le)_(bits|bytes)\b")


def strip_noncode(src: str) -> str:
    """Blank out comments and string literals, preserving line structure.

    Replaced spans keep their newlines so reported line numbers stay true to the
    original file.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue

        if ch == "/" and nxt == "*":
            depth, i = 1, i + 2  # Noir block comments nest
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
            continue

        # raw string: r"..." / r#"..."# / r##"..."## ...
        if ch == "r" and (nxt == '"' or nxt == "#"):
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                j += 1
                while j < n and not src.startswith(close, j):
                    if src[j] == "\n":
                        out.append("\n")
                    j += 1
                i = min(j + len(close), n)
                continue

        # plain or format string; `f` only prefixes a string literal
        if ch == '"' or (ch == "f" and nxt == '"'):
            j = i + 1 if ch == '"' else i + 2
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                if src[j] == "\n":
                    out.append("\n")
                j += 1
            i = j
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def statements(code: str) -> "Iterator[tuple[int, str]]":
    """Yield (start_line, statement_text) for each `;`/`{`/`}`-terminated run.

    `str.strip()` also removes a trailing `\\r`, so a CRLF file is handled
    identically to an LF one. That is load-bearing, not incidental: with `\\r`
    retained no line ever ends in `;{}`, every statement runs to EOF, and the
    scanner goes blind on the whole file. There is no .gitattributes in this
    repo normalising line endings, so CRLF input is reachable.
    """
    buf: list[str] = []
    start = 0
    for lineno, raw in enumerate(code.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if not buf:
            start = lineno
        buf.append(line)
        if line[-1] in ";{}":
            yield start, " ".join(buf)
            buf = []
    if buf:
        yield start, " ".join(buf)


def width(literal: str) -> int:
    """Noir permits `_` as a visual separator inside a numeric literal."""
    return int(literal.replace("_", ""))


def bindings(chunk: str) -> "Iterator[str]":
    """Split a chunk on statement-terminating `;`, ignoring `;` inside brackets.

    A chunk from `statements()` runs to the end of a physical line, so it can
    hold more than one statement. It must be split before an annotation is
    correlated with a call, or an unrelated wide annotation and an unrelated
    narrow call sitting on the same line combine into a false positive.

    The split is bracket-aware because a Noir array type spells its length with
    a semicolon -- `[bool; 254]` -- and a naive split would tear every
    annotation in half.
    """
    depth = start = 0
    for i, ch in enumerate(chunk):
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            yield chunk[start:i]
            start = i + 1
    yield chunk[start:]


def offending(stmt: str) -> str | None:
    """Reason `stmt` is rejected, or None if it is clean.

    A turbofish carries its own width, so it is judged alone. An annotated
    decomposition splits the width from the call (`let b: [bool; 254] =
    x.to_be_bits();`), so both must be present in the same binding.

    EVERY annotation in the binding is considered, never just the first. A
    leftmost-match implementation is exactly how this gate was defeated in
    review: `let (_pad, bits): ([bool; 8], [bool; 254]) = (..., v.to_be_bits())`
    resolved to 8 and reported clean while carrying a real 254-bit
    decomposition.

    Annotation matching stays deliberately loose within a binding -- it is NOT
    anchored to `let ... =` -- so that a width carried by a return type,
    `fn wide(x: Field) -> [bool; 254] { x.to_be_bits() }`, is still caught.
    Tightening to the assignment form would trade a false positive for a false
    negative, which is the strictly worse direction for a soundness gate.

    UNRESOLVED WIDTHS FAIL CLOSED. A call with no turbofish and no annotation
    anywhere in its binding is REJECTED rather than skipped, because its width
    can still be 32 bytes -- inferred from a callee's parameter type, e.g.
    `let slot = slot_of(value.to_be_bytes());` where `slot_of` takes [u8; 32].
    That is the PR #4 bug shape with the width moved one frame away, and
    silently skipping it would leave a hole in the only gate that identifies
    this class. The remedy is a one-word edit -- add an explicit turbofish --
    and ZKM has no such site today, so this costs nothing to hold.
    """
    for binding in bindings(stmt):
        calls = _CALL.findall(binding)
        if not calls:
            continue

        turbos = _TURBOFISH.findall(binding)
        for kind, digits in turbos:
            if width(digits) >= (MIN_BITS if kind == "bits" else MIN_BYTES):
                return f"{width(digits)}-{kind[:-1] if kind.endswith('s') else kind} decomposition via turbofish is >= the field size"

        annotations = _ANNOTATION.findall(binding)
        for kind, digits in annotations:
            if width(digits) >= (MIN_BYTES if kind == "u8" else MIN_BITS):
                unit = "byte" if kind == "u8" else "bit"
                return f"{width(digits)}-{unit} decomposition (width from a [{kind}; N] annotation) is >= the field size"

        # Every call accounted for by a turbofish is resolved; the rest need an
        # annotation somewhere in the binding, or we cannot judge them at all.
        if len(calls) > len(turbos) and not annotations:
            return (
                "cannot statically resolve the width of this decomposition "
                "(no turbofish, no array-type annotation in the binding) -- "
                "add an explicit turbofish, e.g. .to_be_bytes::<16>()"
            )
    return None


# (source, must_flag) -- every evasion this scanner was written to close, plus
# the widths that must NOT be flagged. Run via --self-test by the gate itself, so
# a detector that quietly stops detecting fails the build instead of passing it.
SELF_TEST: list[tuple[str, bool]] = [
    # -- must flag: the plain spellings ------------------------------------
    ("let b: [bool; 254] = x.to_be_bits();", True),
    ("let b = x.to_be_bits::<254>();", True),
    ("let b: [u8; 32] = x.to_be_bytes();", True),
    ("let b = x.to_be_bytes::<32>();", True),
    ("let b: [u1; 254] = x.to_be_bits();", True),        # pre-beta.20 element type
    # -- must flag: lexical evasions ---------------------------------------
    ("let b = x.to_be_bits::<2_54>();", True),           # numeric separator
    ("let b = x.to_be_bytes::<3_2>();", True),
    ("let b = x.to_be_bits::<1000>();", True),           # width past 3 digits
    ("let b = x.to_le_bits::<254>();", True),            # little-endian variants
    ("let b: [u8; 64] = x.to_le_bytes();", True),
    ('let s = "https://e"; let b = x.to_be_bits::<254>();', True),   # // in string
    ("/* note // here */ let b = x.to_be_bits::<254>();", True),     # // in block comment
    ("/* outer /* inner */ */ let b = x.to_be_bits::<254>();", True),  # nested
    ('let s = f"x{y}//z"; let b = x.to_be_bits::<254>();', True),    # format string
    ('let s = r#"raw // "#; let b = x.to_be_bits::<254>();', True),  # raw string
    ("let b:\n    [bool; 254] =\n    x.to_be_bits();", True),        # wrapped statement
    ("let b: [bool; 254] = x.to_be_bits();\r\nlet y = 1;", True),    # CRLF input
    # -- must flag: MULTI-ANNOTATION MASKING (the review's CRITICAL finding) --
    # A narrow annotation sorting first must not mask a wide one in the same
    # binding. Both of these compile, and both are the real PR #4 bug shape.
    (
        "let (_pad, bits): ([bool; 8], [bool; 254]) = ([false; 8], v.to_be_bits());",
        True,
    ),
    (
        "let (a, b): ([u8; 16], [u8; 32]) = (x.to_be_bytes(), y.to_be_bytes());",
        True,
    ),
    # two bindings on one physical line, the SECOND of which is wide
    ("let lo: [u8; 16] = x.to_be_bytes(); let hi: [u8; 32] = y.to_be_bytes();", True),
    # width carried by a return type rather than a `let` binding -- annotation
    # matching must NOT be anchored to `=`, or this becomes a false negative
    ("fn wide(x: Field) -> [bool; 254] { x.to_be_bits() }", True),
    ("fn wide(x: Field) -> [u8; 32] { x.to_be_bytes() }", True),
    # -- must flag: width inferred from a callee's signature (fail closed) --
    ("let slot = slot_of(value.to_be_bytes());", True),
    ("let b = x.to_be_bits();", True),
    # -- must NOT flag ------------------------------------------------------
    ("let b: [bool; 128] = index.to_be_bits();", False),   # cannot wrap p
    ("let b: [bool; 32] = idx.to_be_bits();", False),
    ("let b: [bool; 16] = idx.to_be_bits();", False),
    ("let b: [bool; 253] = x.to_be_bits();", False),       # boundary: 2^253 < p
    ("let b: [u8; 31] = x.to_be_bytes();", False),         # boundary: 248 bits < p
    ("let (lo, _hi) = std::field::bn254::decompose(value);", False),  # the fix
    ("let buf: [u8; 32] = [0; 32];", False),               # annotation, no call
    ("// let b: [bool; 254] = x.to_be_bits();", False),    # commented-out rationale
    ("/// The earlier construction decomposed via `to_be_bits::<254>()`.", False),
    ("/* let b = x.to_be_bits::<254>(); */", False),
    ('let s = "let b: [bool; 254] = x.to_be_bits();";', False),  # inside a string
    ('assert(ok, "use to_be_bytes::<32>() nowhere");', False),   # inside an assert msg
    # two statements on one physical line: the wide annotation belongs to the
    # buffer, the call is a sound 128-bit decomposition -- must not be conflated
    ("let buf: [u8; 32] = [0; 32]; let b: [bool; 128] = x.to_be_bits();", False),
    ("let n: [u8; 64] = other(); let i: [bool; 32] = idx.to_be_bits();", False),
]


def self_test() -> int:
    failures = 0
    for source, must_flag in SELF_TEST:
        code = strip_noncode(source)
        flagged = any(offending(stmt) is not None for _, stmt in statements(code))
        if flagged != must_flag:
            want = "flag" if must_flag else "ignore"
            print(f"::error::self-test: expected to {want}: {source!r}")
            failures += 1
    if failures:
        print(f"    self-test: {failures}/{len(SELF_TEST)} cases FAILED")
        return 1
    print(f"    self-test: {len(SELF_TEST)} cases ok")
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()

    excludes: list[pathlib.Path] = []
    roots: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--exclude":
            if i + 1 >= len(args):
                print("error: --exclude needs a directory", file=sys.stderr)
                return 2
            excludes.append(pathlib.Path(args[i + 1]).resolve())
            i += 2
            continue
        roots.append(args[i])
        i += 1

    if len(roots) != 1:
        print(f"usage: {argv[0]} <root-dir> [--exclude DIR]... | --self-test", file=sys.stderr)
        return 2

    root = pathlib.Path(roots[0])
    if not root.exists():
        print(f"error: no such path: {root}", file=sys.stderr)
        return 2

    paths = sorted(root.rglob("*.nr")) if root.is_dir() else [root]
    scanned = 0
    found = False
    for path in paths:
        resolved = path.resolve()
        if any(resolved == e or e in resolved.parents for e in excludes):
            continue
        scanned += 1
        code = strip_noncode(path.read_text(encoding="utf-8", errors="replace"))
        for line, stmt in statements(code):
            reason = offending(stmt)
            if reason is not None:
                print(f"{path}:{line}: {reason}")
                print(f"    {stmt}")
                found = True

    # A scan that reached no files is a broken invocation, not a clean tree --
    # reporting "none found" there is the false PASS this gate must never emit.
    if scanned == 0:
        print(f"error: scanned 0 .nr files under {root}", file=sys.stderr)
        return 2

    print(f"    scanned {scanned} .nr file(s)", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
