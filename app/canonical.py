"""Canonical binary checkpoint message.

The Ed25519 signature is computed over these raw bytes -- never over the JSON
transport encoding.  Layout (all integers big-endian):

    offset  size  field
    0       16    MAGIC
    16      2     log_id length (u16)
    18      N     log_id (ASCII)
    18+N    32    public key
    50+N    8     tree size (u64)
    58+N    8    timestamp milliseconds (u64)
    66+N    32    root hash
"""

from __future__ import annotations

import struct

MAGIC = b"SEAFLOOR-LOGCPT1"  # exactly 16 bytes
assert len(MAGIC) == 16

LOG_ID_MAX_LEN = 256


def encode_message(
    log_id: str,
    public_key: bytes,
    tree_size: int,
    timestamp_ms: int,
    root_hash: bytes,
) -> bytes:
    if not isinstance(log_id, str):
        raise ValueError("log_id must be a string")
    raw_id = log_id.encode("ascii")
    if not raw_id:
        raise ValueError("log_id must not be empty")
    if len(raw_id) > LOG_ID_MAX_LEN:
        raise ValueError(f"log_id longer than {LOG_ID_MAX_LEN} bytes")
    if not all(0x20 <= b <= 0x7E for b in raw_id):
        raise ValueError("log_id must be printable ASCII (0x20-0x7E)")
    if len(public_key) != 32:
        raise ValueError("public_key must be 32 bytes")
    if not (0 <= tree_size <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("tree_size out of u64 range")
    if not (0 <= timestamp_ms <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("timestamp_ms out of u64 range")
    if len(root_hash) != 32:
        raise ValueError("root_hash must be 32 bytes")
    return (
        MAGIC
        + struct.pack(">H", len(raw_id))
        + raw_id
        + public_key
        + struct.pack(">Q", tree_size)
        + struct.pack(">Q", timestamp_ms)
        + root_hash
    )
