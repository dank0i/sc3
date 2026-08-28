"""The MVsilicon AP82xx / BP10xx code cipher, as reverse engineered from the FIFINE SC3.

The scheme is a pure address-keyed XOR stream with two byteswap toggles.  For a
32-bit flash address `a` (always word-aligned):

    plaintext(a) = bswap^g(a)( ciphertext_LE(a) ^ ks(a) )
    ks(a)        = bswap^e(a)( L(a) ^ C[phi(a)] ^ R[s(a)] )

    L(a)   = ((a << 20) ^ (a >> 2)) & 0xFFFFFFFF
    phi(a) = 4-bit nibble-XOR-fold of (a >> 2)          -> index into C
    C      = 16 key-INDEPENDENT constants
    R      = 10 key-DEPENDENT words                     -> selected by s(a)
    e, s, g = per-address labels

`g` is a deterministic function of `(e, s)`:

    g = 0  iff  (e, s) in {(0,3), (1,5), (1,7), (1,8)}
    g = 1  otherwise

so a word has 14 realised candidates, not 36.  Only 14 of the 18 possible (e, s)
pairs occur in the SC3 image: e=1 pairs with every s in 0..8, e=0 pairs with only
s in {0, 1, 3, 5, 8}.  A tenth R word, R[9], occurs with (e=1, s=9) on roughly
621 words of the SC3 image.

WHAT IS NOT SOLVED: there is no closed form for e(a) and s(a).  They were
recovered per address by a known-plaintext attack (see docs/cipher.md) and are
distributed with this repo as a label table.  Decryption of a *new* image with a
*new* key needs both its R table and its own label solve.

Three exact invariance laws hold over the SC3 image:

    ks(a) ^ ks(a ^ d)  is constant  for d in {0x880, 0x110000, 0x110880}

with the constant taking one of two values, {0x88000220, 0x20020088} for d=0x880.
The labels are invariant under those deltas, which is what makes label
propagation work; see `law_partners()`.
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF

# Key-independent constant table, indexed by phi(a).
C = (
    0x00000000, 0x14A98027, 0x2B8C9A38, 0x2E86EA45,
    0x5B939ACC, 0xE64E5F89, 0x814C87E6, 0x8ACCE9D8,
    0xA6DBFDF0, 0x172715FE, 0xD586D309, 0xC24C4816,
    0xF97C9ADA, 0xFFA6FB85, 0x7CB74D7E, 0x534758F1,
)

# Key-dependent R tables, indexed by s(a).  R[0..8] were solved from exposed
# keystream (zero-padded flash); R[9] was found later and is rare.
#
# R[9] is only established for the SC3.  The SY002 and O-NOORUS tables are the
# nine values that were solved from their zero-pad keystream; no tenth value was
# derived for them, so a full decrypt of those images is NOT possible with this
# table alone.
R_SC3 = (
    0x02CB99CA, 0x0BD40F34, 0x2A10CB15, 0x2B792BE3, 0x731CEEF9,
    0x8CE31106, 0x9297505B, 0xD486D41C, 0xE7F1036D, 0x454F888C,
)
R_SY002 = (
    0x0D71D5DA, 0x13059487, 0x3B3591EC, 0x551410C0, 0xAAEBEF3F,
    0xAB820FC9, 0xD7109DB5, 0xDE0F0B4B, 0xF28E2A25,
)
R_ONOORUS = (
    0x0A7A8487, 0x521F419D, 0x5376A16B, 0x75BE694D, 0x7CA1FFB3,
    0x999B6514, 0xADE0BE62, 0xEBF13A25, 0xF5857B78,
)

R_TABLES = {
    "sc3": R_SC3,
    "sy002": R_SY002,
    "onoorus": R_ONOORUS,
}

# The 14 realised (e, s) pairs, plus the rare (1, 9).  Order is the canonical
# label encoding used by the on-disk label tables; do not reorder.
ES_TABLE = (
    (0, 0), (0, 1), (0, 3), (0, 5), (0, 8),
    (1, 0), (1, 1), (1, 2), (1, 3), (1, 4),
    (1, 5), (1, 6), (1, 7), (1, 8), (1, 9),
)

# (e, s) pairs for which the outer byteswap g is 0.
G0_PAIRS = frozenset({(0, 3), (1, 5), (1, 7), (1, 8)})

# Exact keystream invariance deltas (address deltas, in bytes).
LAW_DELTAS = (0x880, 0x110000, 0x110880)

# ks(a) ^ ks(a ^ 0x880) is always one of these two.
LAW_0X880_VALUES = (0x88000220, 0x20020088)

# Nibble masks whose parity gives the four bits of phi.
_PHI_MASKS = (0x44444444, 0x88888888, 0x11111110, 0x22222220)

# Parity of the low 16 bits, for a branch-free phi().
_PARITY16 = bytes(bin(i).count("1") & 1 for i in range(1 << 16))


def bswap32(x: int) -> int:
    """Reverse the four bytes of a 32-bit word."""
    return (
        ((x & 0x000000FF) << 24)
        | ((x & 0x0000FF00) << 8)
        | ((x >> 8) & 0x0000FF00)
        | ((x >> 24) & 0x000000FF)
    )


def _parity(v: int) -> int:
    return _PARITY16[v & 0xFFFF] ^ _PARITY16[(v >> 16) & 0xFFFF]


def L(a: int) -> int:
    """The address-linear term of the keystream."""
    return (((a << 20) & MASK32) ^ (a >> 2)) & MASK32


def phi(a: int) -> int:
    """4-bit nibble-XOR-fold of (a >> 2); the index into C.

    The masks fold a>>2 rather than a, which is why bits 0 and 1 of the address
    never participate.  Written as parities of masked words so it stays a couple
    of instructions rather than a loop.
    """
    return (
        _parity(a & _PHI_MASKS[0])
        | (_parity(a & _PHI_MASKS[1]) << 1)
        | (_parity(a & _PHI_MASKS[2]) << 2)
        | (_parity(a & _PHI_MASKS[3]) << 3)
    )


def base(a: int) -> int:
    """The key-independent part of the keystream: L(a) ^ C[phi(a)]."""
    return L(a) ^ C[phi(a)]


def g_of(e: int, s: int) -> int:
    """The outer byteswap toggle, which is a function of (e, s) alone."""
    return 0 if (e, s) in G0_PAIRS else 1


def keystream(a: int, e: int, s: int, R=R_SC3) -> int:
    """ks(a) for a given label pair."""
    x = base(a) ^ R[s]
    return bswap32(x) if e else x


def decrypt_word(ct: int, a: int, e: int, s: int, R=R_SC3) -> int:
    """One ciphertext word -> plaintext, given its labels."""
    v = ct ^ keystream(a, e, s, R)
    return v if g_of(e, s) == 0 else bswap32(v)


def encrypt_word(pt: int, a: int, e: int, s: int, R=R_SC3) -> int:
    """The exact inverse of decrypt_word (bswap is an involution)."""
    v = pt if g_of(e, s) == 0 else bswap32(pt)
    return v ^ keystream(a, e, s, R)


def candidates(ct: int, a: int, R=R_SC3):
    """Every realised plaintext candidate for one ciphertext word.

    Yields ``(e, s, plaintext)``.  14 entries for R tables of 9 words, 15 when a
    tenth R word is present.
    """
    for e, s in ES_TABLE:
        if s >= len(R):
            continue
        yield e, s, decrypt_word(ct, a, e, s, R)


def law_partners(a: int, limit: int | None = None):
    """Addresses whose labels are forced equal to a's by the invariance laws.

    The three deltas plus 0 form a group of order 4 under XOR, so an address has
    three partners.  ``limit`` drops partners past the end of the image.
    """
    for d in LAW_DELTAS:
        p = a ^ d
        if limit is None or p < limit:
            yield p


def check_law_0x880(ks_a: int, ks_partner: int) -> bool:
    """True if a pair of keystream words satisfies the 0x880 law."""
    return (ks_a ^ ks_partner) in LAW_0X880_VALUES
