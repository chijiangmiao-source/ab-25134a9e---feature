"""SQLite-backed durable storage for trusted checkpoints and fork evidence.

Every state transition happens in one ``BEGIN IMMEDIATE`` transaction so that
concurrent (or retried) submissions are serialized against the durable log
state: the winner advances the tree, the loser re-reads the new head and gets
the same verdict the winner got.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    log_id       TEXT PRIMARY KEY,
    public_key   BLOB NOT NULL,
    tree_size    INTEGER NOT NULL,
    root_hash    BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    signature    BLOB NOT NULL,
    status       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id       TEXT NOT NULL REFERENCES logs(log_id),
    public_key   BLOB NOT NULL,
    tree_size    INTEGER NOT NULL,
    root_hash    BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    signature    BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    UNIQUE(log_id, tree_size, root_hash, timestamp_ms, public_key, signature)
);

CREATE TABLE IF NOT EXISTS forks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id           TEXT NOT NULL REFERENCES logs(log_id),
    reason           TEXT NOT NULL,
    -- frozen/trusted head at the moment of conflict
    trusted_size     INTEGER NOT NULL,
    trusted_root     BLOB NOT NULL,
    trusted_ts       INTEGER NOT NULL,
    trusted_key      BLOB NOT NULL,
    trusted_sig      BLOB NOT NULL,
    -- equivocating verified submission
    rival_root       BLOB NOT NULL,
    rival_ts         INTEGER NOT NULL,
    rival_key        BLOB NOT NULL,
    rival_sig        BLOB NOT NULL,
    proof            BLOB NOT NULL,
    created_at       INTEGER NOT NULL,
    UNIQUE(log_id, rival_sig)
);

-- Immutable review receipts binding a caller-chosen receipt id to one leaf
-- at one already-saved checkpoint.  Rows are inserted at most once per
-- (log_id, receipt_id) and never updated: identical resubmissions return the
-- stored row, divergent resubmissions are rejected as conflicts.
CREATE TABLE IF NOT EXISTS receipts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id       TEXT NOT NULL REFERENCES logs(log_id),
    receipt_id   TEXT NOT NULL,
    -- snapshot of the saved checkpoint this receipt was anchored to
    target_size  INTEGER NOT NULL,
    target_root  BLOB NOT NULL,
    target_ts    INTEGER NOT NULL,
    leaf_index   INTEGER NOT NULL,
    leaf_hash    BLOB NOT NULL,
    leaf_data    BLOB NOT NULL,
    -- RFC 9162 inclusion path as a JSON array of lowercase hex strings
    inclusion    BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    UNIQUE(log_id, receipt_id)
);
"""


class LogState:
    def __init__(self, row: sqlite3.Row):
        self.log_id: str = row["log_id"]
        self.public_key: bytes = row["public_key"]
        self.tree_size: int = row["tree_size"]
        self.root_hash: bytes = row["root_hash"]
        self.timestamp_ms: int = row["timestamp_ms"]
        self.signature: bytes = row["signature"]
        self.status: str = row["status"]
        self.created_at: int = row["created_at"]
        self.updated_at: int = row["updated_at"]


class ReceiptState:
    __slots__ = (
        "log_id", "receipt_id", "target_size", "target_root", "target_ts",
        "leaf_index", "leaf_hash", "leaf_data", "inclusion", "created_at",
    )

    def __init__(self, row: sqlite3.Row):
        self.log_id: str = row["log_id"]
        self.receipt_id: str = row["receipt_id"]
        self.target_size: int = row["target_size"]
        self.target_root: bytes = bytes(row["target_root"])
        self.target_ts: int = row["target_ts"]
        self.leaf_index: int = row["leaf_index"]
        self.leaf_hash: bytes = bytes(row["leaf_hash"])
        self.leaf_data: bytes = bytes(row["leaf_data"])
        self.inclusion: bytes = bytes(row["inclusion"])
        self.created_at: int = row["created_at"]


class Store:
    def __init__(self, path: str):
        self._path = path
        # Re-entrant: submit() holds this across transactional helpers.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ping(self) -> None:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()

    def list_logs(self) -> list[str]:
        with self._lock:
            return [r["log_id"] for r in self._conn.execute(
                "SELECT log_id FROM logs ORDER BY log_id").fetchall()]

    @property
    def lock(self) -> threading.RLock:
        """Serialise verdict+write sections within the process."""
        return self._lock

    def get_log(self, log_id: str) -> Optional[LogState]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM logs WHERE log_id = ?", (log_id,)
            ).fetchone()
        return LogState(row) if row else None

    def first_fork(self, log_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM forks WHERE log_id = ? ORDER BY id ASC LIMIT 1",
                (log_id,),
            ).fetchone()

    def list_forks(self, log_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM forks WHERE log_id = ? ORDER BY id ASC",
                    (log_id,),
                ).fetchall()
            )

    def get_checkpoint(self, log_id: str, tree_size: int) -> Optional[sqlite3.Row]:
        """A saved checkpoint for this log at exactly ``tree_size``.

        Any historically accepted size anchors receipts, including logs
        later sealed for equivocation.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM checkpoints WHERE log_id = ? AND tree_size = ?",
                (log_id, tree_size),
            ).fetchone()

    def get_receipt(self, log_id: str, receipt_id: str) -> Optional[ReceiptState]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM receipts WHERE log_id = ? AND receipt_id = ?",
                (log_id, receipt_id),
            ).fetchone()
        return ReceiptState(row) if row else None

    def save_receipt(self, log_id: str, receipt_id: str, target: sqlite3.Row,
                     leaf_index: int, leaf_hash: bytes, leaf_data: bytes,
                     inclusion: list[bytes], now_ms: int
                     ) -> tuple[ReceiptState, bool]:
        """Atomically persist an immutable, fully-verified receipt.

        Returns ``(receipt, inserted)``: an identical-id resubmission races
        are resolved inside one ``BEGIN IMMEDIATE`` transaction -- the loser
        gets the stored row and ``inserted=False`` so the service can decide
        between idempotent replay and content conflict.
        """
        proof_blob = json.dumps([n.hex() for n in inclusion]).encode()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT * FROM receipts WHERE log_id = ? AND receipt_id = ?",
                    (log_id, receipt_id),
                ).fetchone()
                if existing is not None:
                    self._conn.execute("COMMIT")
                    return ReceiptState(existing), False
                cur = self._conn.execute(
                    "INSERT INTO receipts (log_id, receipt_id, target_size,"
                    " target_root, target_ts, leaf_index, leaf_hash, leaf_data,"
                    " inclusion, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        log_id,
                        receipt_id,
                        target["tree_size"],
                        target["root_hash"],
                        target["timestamp_ms"],
                        leaf_index,
                        leaf_hash,
                        leaf_data,
                        proof_blob,
                        now_ms,
                    ),
                )
                row = self._conn.execute(
                    "SELECT * FROM receipts WHERE id = ?",
                    (cur.lastrowid,),
                ).fetchone()
                self._conn.execute("COMMIT")
                return ReceiptState(row), True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def freeze_first(self, log_id: str, sub: "Submission", now_ms: int) -> None:
        """Atomically freeze the key and anchor the first checkpoint."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                exists = self._conn.execute(
                    "SELECT 1 FROM logs WHERE log_id = ?", (log_id,)
                ).fetchone()
                if exists:
                    # Lost a race with a concurrent first submission.
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError("log already exists")
                self._conn.execute(
                    "INSERT INTO logs (log_id, public_key, tree_size, root_hash,"
                    " timestamp_ms, signature, status, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        log_id,
                        sub.public_key,
                        sub.tree_size,
                        sub.root_hash,
                        sub.timestamp_ms,
                        sub.signature,
                        "active",
                        now_ms,
                        now_ms,
                    ),
                )
                self._conn.execute(
                    "INSERT INTO checkpoints (log_id, public_key, tree_size,"
                    " root_hash, timestamp_ms, signature, created_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (
                        log_id,
                        sub.public_key,
                        sub.tree_size,
                        sub.root_hash,
                        sub.timestamp_ms,
                        sub.signature,
                        now_ms,
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def advance(self, log_id: str, sub: "Submission", now_ms: int) -> None:
        """Atomically append a verified larger tree head."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM logs WHERE log_id = ?", (log_id,)
                ).fetchone()
                if row is None:
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError("log vanished")
                if row["tree_size"] >= sub.tree_size:
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError("no longer an extension")
                self._conn.execute(
                    "UPDATE logs SET public_key=?, tree_size=?, root_hash=?,"
                    " timestamp_ms=?, signature=?, updated_at=? WHERE log_id=?",
                    (
                        sub.public_key,
                        sub.tree_size,
                        sub.root_hash,
                        sub.timestamp_ms,
                        sub.signature,
                        now_ms,
                        log_id,
                    ),
                )
                self._conn.execute(
                    "INSERT INTO checkpoints (log_id, public_key, tree_size,"
                    " root_hash, timestamp_ms, signature, created_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (
                        log_id,
                        sub.public_key,
                        sub.tree_size,
                        sub.root_hash,
                        sub.timestamp_ms,
                        sub.signature,
                        now_ms,
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def seal_fork(self, trusted: LogState, sub: "Submission", reason: str,
                  proof_blob: bytes, now_ms: int) -> int:
        """Persist equivocation evidence without touching the trusted head.

        Returns the fork record id.  An identical rival signature is a replay
        of an already-sealed conflict and returns that record's id.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT id FROM forks WHERE log_id=? AND rival_sig=?",
                    (trusted.log_id, sub.signature),
                ).fetchone()
                if existing:
                    self._conn.execute("COMMIT")
                    return int(existing["id"])
                cur = self._conn.execute(
                    "INSERT INTO forks (log_id, reason, trusted_size, trusted_root,"
                    " trusted_ts, trusted_key, trusted_sig, rival_root, rival_ts,"
                    " rival_key, rival_sig, proof, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        trusted.log_id,
                        reason,
                        trusted.tree_size,
                        trusted.root_hash,
                        trusted.timestamp_ms,
                        trusted.public_key,
                        trusted.signature,
                        sub.root_hash,
                        sub.timestamp_ms,
                        sub.public_key,
                        sub.signature,
                        proof_blob,
                        now_ms,
                    ),
                )
                fork_id = int(cur.lastrowid)
                self._conn.execute(
                    "UPDATE logs SET status='fork_sealed' WHERE log_id=?",
                    (trusted.log_id,),
                )
                self._conn.execute("COMMIT")
                return fork_id
            except Exception:
                self._conn.execute("ROLLBACK")
                raise


def now_ms() -> int:
    return time.time_ns() // 1_000_000
