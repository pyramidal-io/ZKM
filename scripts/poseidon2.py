"""Pure-Python Poseidon2 over the BN254 scalar field (t = 4 sponge).

Bit-for-bit compatible with `Poseidon2::hash` from noir-lang/poseidon v0.3.0
(the Noir stdlib `poseidon2_permutation` builtin / barretenberg Poseidon2),
which is what every ZKM circuit uses via `noir/zkm_lib`.

Reference implementation for ZKM migration tooling and AFP-KDC v1.0.2
conformance. Standard library only. Copied from ZKC-Core's reference
implementation and verified against:
  - the published AFP-KDC v1.0.2 parameter table and raw-sponge vectors,
  - the barretenberg permutation test vector,
  - the zkm_lib Poseidon KATs in `noir/zkm_lib`.
"""

from __future__ import annotations

from _poseidon2_constants import INTERNAL_DIAG_MINUS_ONE, ROUND_CONSTANTS

# BN254 (alt_bn128) scalar field modulus.
FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

_T = 4
_RATE = 3
_ROUNDS_F = 8
_ROUNDS_P = 56


def _sbox(x: int) -> int:
    x2 = x * x % FIELD_MODULUS
    x4 = x2 * x2 % FIELD_MODULUS
    return x4 * x % FIELD_MODULUS


def _matmul_external(s: list) -> None:
    """In-place multiplication by the t=4 external MDS matrix.

    | 5 7 1 3 |
    | 4 6 1 1 |
    | 1 3 5 7 |
    | 1 1 4 6 |
    """
    p = FIELD_MODULUS
    t0 = (s[0] + s[1]) % p
    t1 = (s[2] + s[3]) % p
    t2 = (s[1] + s[1] + t1) % p
    t3 = (s[3] + s[3] + t0) % p
    t4 = (4 * t1 + t3) % p
    t5 = (4 * t0 + t2) % p
    s[0] = (t3 + t5) % p
    s[1] = t5
    s[2] = (t2 + t4) % p
    s[3] = t4


def _matmul_internal(s: list) -> None:
    """In-place multiplication by the internal matrix (diag + all-ones)."""
    p = FIELD_MODULUS
    total = (s[0] + s[1] + s[2] + s[3]) % p
    for i in range(_T):
        s[i] = (s[i] * INTERNAL_DIAG_MINUS_ONE[i] + total) % p


def permutation(state) -> tuple:
    """Poseidon2 permutation on a 4-element BN254 state."""
    if len(state) != _T:
        raise ValueError("poseidon2 permutation requires a 4-element state")
    s = [x % FIELD_MODULUS for x in state]

    _matmul_external(s)

    half_f = _ROUNDS_F // 2
    for r in range(half_f):
        rc = ROUND_CONSTANTS[r]
        for i in range(_T):
            s[i] = _sbox((s[i] + rc[i]) % FIELD_MODULUS)
        _matmul_external(s)

    for r in range(half_f, half_f + _ROUNDS_P):
        s[0] = _sbox((s[0] + ROUND_CONSTANTS[r][0]) % FIELD_MODULUS)
        _matmul_internal(s)

    for r in range(half_f + _ROUNDS_P, _ROUNDS_F + _ROUNDS_P):
        rc = ROUND_CONSTANTS[r]
        for i in range(_T):
            s[i] = _sbox((s[i] + rc[i]) % FIELD_MODULUS)
        _matmul_external(s)

    return tuple(s)


def hash_fields(inputs, message_size: int | None = None) -> int:
    """`Poseidon2::hash(inputs, message_size)` from noir-lang/poseidon.

    Sponge with rate 3, capacity 1, IV = message_size << 64.
    """
    inputs = [x % FIELD_MODULUS for x in inputs]
    if message_size is None:
        message_size = len(inputs)
    if message_size > len(inputs):
        raise ValueError("message_size exceeds input length")

    state = [0, 0, 0, (message_size << 64) % FIELD_MODULUS]
    for chunk_start in range(0, message_size - (message_size % _RATE), _RATE):
        for i in range(_RATE):
            state[i] = (state[i] + inputs[chunk_start + i]) % FIELD_MODULUS
        state = list(permutation(state))

    remainder = message_size % _RATE
    if remainder:
        start = message_size - remainder
        for i in range(remainder):
            state[i] = (state[i] + inputs[start + i]) % FIELD_MODULUS

    if message_size == 0 or remainder:
        state = list(permutation(state))

    return state[0]


def poseidon2(a: int, b: int) -> int:
    """zkm_lib::poseidon2."""
    return hash_fields([a, b])


def poseidon3(a: int, b: int, c: int) -> int:
    """zkm_lib::poseidon3."""
    return hash_fields([a, b, c])


def poseidon4(a: int, b: int, c: int, d: int) -> int:
    """zkm_lib::poseidon4."""
    return hash_fields([a, b, c, d])
