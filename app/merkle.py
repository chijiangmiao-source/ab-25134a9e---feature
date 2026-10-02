"""RFC 9162 Merkle tree hashing, inclusion and consistency proofs.

Inputs are *leaf hashes*: callers hash raw leaf data with HASH(0x00 || d)
before handing leaves in.  The checkpoint protocol only ever compares roots
and verifies consistency between two advertised heads, so inclusion proof
support is included for completeness and for the acceptance test-suite.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "hash_leaf",
    "tree_hash",
    "consistency_proof",
    "verify_consistency",
    "inclusion_proof",
    "verify_inclusion",
]


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_leaf(data: bytes) -> bytes:
    return H(b"\x00" + data)


def _hash_nodes(a: bytes, b: bytes) -> bytes:
    return H(b"\x01" + a + b)


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    if n < 2:
        raise ValueError("need n >= 2")
    k = 1 << (n.bit_length() - 1)
    return k >> 1 if k == n else k


def tree_hash(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash per RFC 9162 Section 2.1.1."""
    n = len(leaves)
    if n == 0:
        return H(b"")
    if n == 1:
        return leaves[0]
    k = _largest_pow2_lt(n)
    return _hash_nodes(tree_hash(leaves[:k]), tree_hash(leaves[k:]))


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [tree_hash(leaves)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [tree_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [tree_hash(leaves[:k])]


def consistency_proof(old_size: int, leaves: list[bytes]) -> list[bytes]:
    """Minimal PROOF(old_size, D_n), 0 < old_size < n."""
    n = len(leaves)
    if not (0 < old_size < n):
        raise ValueError("require 0 < old_size < new_size")
    return _subproof(old_size, leaves, True)


def verify_consistency(
    first: int,
    first_hash: bytes,
    second: int,
    second_hash: bytes,
    proof: list[bytes],
) -> None:
    """RFC 9162 Section 2.1.4.2 verifier; raises ValueError on failure."""
    if not (0 < first < second):
        raise ValueError("require 0 < first < second")
    if len(first_hash) != 32 or len(second_hash) != 32:
        raise ValueError("hashes must be 32 bytes")
    for node in proof:
        if len(node) != 32:
            raise ValueError("proof entries must be 32 bytes")
    if not proof:
        raise ValueError("empty consistency path")

    path = list(proof)
    # 2. If first is an exact power of 2, prepend first_hash.
    if first & (first - 1) == 0:
        path.insert(0, first_hash)

    fn = first - 1
    sn = second - 1

    # 4. If LSB(fn) set, right-shift until not set.
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ValueError("proof too long for claimed sizes")
        if (fn & 1) or (fn == sn):
            fr = _hash_nodes(c, fr)
            sr = _hash_nodes(c, sr)
            if not (fn & 1):
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _hash_nodes(sr, c)
        fn >>= 1
        sn >>= 1

    if sn != 0 or fr != first_hash or sr != second_hash:
        raise ValueError("consistency proof does not match both tree heads")


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if not (0 <= index < n):
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [tree_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [tree_hash(leaves[:k])]


def verify_inclusion(
    leaf_hash: bytes,
    index: int,
    size: int,
    root: bytes,
    proof: list[bytes],
) -> None:
    if not (0 <= index < size):
        raise ValueError("leaf_index >= tree_size")
    fn, sn, r = index, size - 1, leaf_hash
    for p in proof:
        if sn == 0:
            raise ValueError("inclusion proof too long")
        if (fn & 1) or fn == sn:
            r = _hash_nodes(p, r)
            if not (fn & 1):
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _hash_nodes(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0 or r != root:
        raise ValueError("inclusion proof does not match root")
