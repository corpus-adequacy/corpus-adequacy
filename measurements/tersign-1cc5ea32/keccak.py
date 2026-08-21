"""Vendored pure-Python Keccak-256 (the pre-NIST Keccak padding, as used by Ethereum).

stdlib-only by design: hashlib.sha3_256 is NIST SHA-3 (domain byte 0x06) and produces
DIFFERENT digests; evidence-record digests use legacy Keccak (domain byte 0x01).

Self-checked at import against two independent known-answer vectors; import fails loudly
if the implementation drifts. Cross-checked byte-for-byte against the TypeScript reference
(viem keccak256) — see tools/cross_check_ts.mjs in this repository.
"""

_MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a):
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        a = [
            [b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]
        a[0][0] ^= _RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088-bit rate / 512-bit capacity
    p = bytearray(data)
    padlen = rate - (len(p) % rate)
    if padlen == 1:
        p += b"\x81"
    else:
        p += b"\x01" + b"\x00" * (padlen - 2) + b"\x80"
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            lane = int.from_bytes(p[off + 8 * i : off + 8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = _keccak_f(state)
    out = bytearray()
    for i in range(rate // 8):
        out += state[i % 5][i // 5].to_bytes(8, "little")
        if len(out) >= 32:
            break
    return bytes(out[:32])


def keccak256_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


# -- known-answer self-check: fail loudly on import if the permutation drifts ------------
_KAT = {
    # measured against viem's keccak256 (see tools/cross_check_ts.mjs), not transcribed
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
}
for _msg, _want in _KAT.items():
    _got = keccak256(_msg).hex()
    if _got != _want:
        raise RuntimeError(f"vendored keccak256 self-check FAILED for {_msg!r}: {_got} != {_want}")
