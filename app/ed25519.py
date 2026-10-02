"""Pure-python Ed25519 (pure EdDSA over SHA-512) per RFC 8032.

No third-party dependencies: the container image builds with the CPython
standard library only.  Constant-time properties are not pursued here; this
implementation exists so the service can verify signatures over the exact
canonical binary checkpoint message without relying on OpenSSL CLI plumbing.
"""

from __future__ import annotations

import hashlib
import os

__all__ = [
    "PublicKeyError",
    "SignatureError",
    "generate_keypair",
    "public_key_from_seed",
    "sign",
    "verify",
]

p = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


By = 4 * pow(5, p - 2, p) % p
Bx = _x_recover(By)
B = (Bx, By)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dxxyy = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxxyy, p - 2, p)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxxyy, p - 2, p)
    return x3 % p, y3 % p


def _scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    h = hashlib.sha512(m).digest()
    return sum(2**i * _bit(h, i) for i in range(512))


def _secret_scalar(seed: bytes) -> int:
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return a


def _is_on_curve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % p == 0


def _decodepoint(s: bytes):
    y = sum(2**i * _bit(s, i) for i in range(0, 255))
    if y >= p:
        raise SignatureError("point coordinate out of range")
    x = _x_recover(y)
    if (x & 1) != _bit(s, 255):
        x = p - x
    P = (x, y)
    if not _is_on_curve(P):
        raise SignatureError("point is not on the Edwards curve")
    return P


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


class PublicKeyError(ValueError):
    """Raised when an Ed25519 public key is malformed."""


class SignatureError(ValueError):
    """Raised when a signature is malformed or does not verify."""


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise PublicKeyError("Ed25519 seed must be 32 bytes")
    A = _scalarmult(B, _secret_scalar(seed))
    return _encodepoint(A)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (32-byte seed, 32-byte public key)."""
    seed = os.urandom(32)
    return seed, public_key_from_seed(seed)


def sign(message: bytes, seed: bytes) -> bytes:
    if len(seed) != 32:
        raise PublicKeyError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    public = _encodepoint(_scalarmult(B, a))
    r = _hint(h[32:64] + message)
    R = _scalarmult(B, r)
    S = (r + _hint(_encodepoint(R) + public + message) * a) % l
    return _encodepoint(R) + _encodeint(S)


def verify(message: bytes, signature: bytes, public_key: bytes) -> None:
    """Verify or raise SignatureError.  Returns None on success."""
    if len(public_key) != 32:
        raise PublicKeyError("Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        raise SignatureError("Ed25519 signature must be 64 bytes")
    R = _decodepoint(signature[:32])
    A = _decodepoint(public_key)
    if A == (0, 1):
        raise PublicKeyError("public key is the identity point")
    S = _decodeint(signature[32:])
    if S >= l:
        raise SignatureError("signature scalar S out of range")
    h = _hint(_encodepoint(R) + public_key + message)
    if _scalarmult(B, S) != _edwards(R, _scalarmult(A, h)):
        raise SignatureError("signature does not verify")
