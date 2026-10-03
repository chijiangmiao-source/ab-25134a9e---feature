"""HTTP API for the seafloor checkpoint log.

Endpoints
---------
GET  /healthz                                         liveness + storage probe
GET  /logs                                            list known log ids
GET  /logs/{logId}                                    trusted head, status, first fork
POST /logs/{logId}/checkpoints                        submit a signed checkpoint
POST /logs/{logId}/receipts                           bind a sample to a saved
                                                       checkpoint via RFC 9162
                                                       inclusion proof
GET  /logs/{logId}/receipts/{receiptId}               read an immutable receipt

All validation (shape, signature, consistency/inclusion proofs) completes
before any durable write, so rejected submissions leave no partial state
behind.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from . import canonical, ed25519, merkle
from .storage import Store, now_ms

MAX_BODY_BYTES = 64 * 1024
MAX_PROOF_NODES = 64  # more than ceil(log2(u64 max size)) + 1
MAX_RECEIPT_ID_LEN = 256
MAX_RECEIPT_SAMPLE_BYTES = MAX_BODY_BYTES


class Submission:
    __slots__ = (
        "public_key", "tree_size", "timestamp_ms",
        "root_hash", "signature", "consistency",
    )

    def __init__(self, public_key, tree_size, timestamp_ms,
                 root_hash, signature, consistency):
        self.public_key = public_key
        self.tree_size = tree_size
        self.timestamp_ms = timestamp_ms
        self.root_hash = root_hash
        self.signature = signature
        self.consistency = consistency


class ReceiptRequest:
    __slots__ = ("receipt_id", "tree_size", "leaf_index",
                 "leaf_data", "leaf_hash", "proof")

    def __init__(self, receipt_id, tree_size, leaf_index,
                 leaf_data, leaf_hash, proof):
        self.receipt_id = receipt_id
        self.tree_size = tree_size
        self.leaf_index = leaf_index
        self.leaf_data = leaf_data
        self.leaf_hash = leaf_hash
        self.proof = proof


class ApiError(Exception):
    def __init__(self, http_status: int, code: str, message: str,
                 details: dict | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.details = details or {}


def _b16(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise ApiError(400, "invalid_field", f"{field} must be a hex string",
                       {"field": field})
    s = value[2:] if value.startswith("0x") else value
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        raise ApiError(400, "invalid_field",
                       f"{field} must be hexadecimal", {"field": field})
    return raw


def _valid_log_id(log_id: str) -> None:
    if not log_id:
        raise ApiError(404, "log_not_found", "unknown log", {})
    try:
        canonical.encode_message(log_id, b"\x00" * 32, 1, 0, b"\x00" * 32)
    except ValueError as exc:
        raise ApiError(400, "invalid_log_id", str(exc), {"field": "logId"})


def parse_submission(log_id: str, body: bytes) -> Submission:
    if len(body) > MAX_BODY_BYTES:
        raise ApiError(413, "body_too_large",
                       f"request body exceeds {MAX_BODY_BYTES} bytes")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(400, "invalid_json", f"request body is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        raise ApiError(400, "invalid_json", "request body must be a JSON object")

    required = ("public_key", "tree_size", "timestamp_ms",
                "root_hash", "signature", "consistency")
    missing = [f for f in required if f not in payload]
    if missing:
        raise ApiError(400, "missing_fields",
                       "missing required fields", {"fields": missing})

    public_key = _b16(payload["public_key"], "public_key")
    if len(public_key) != 32:
        raise ApiError(400, "invalid_field",
                       "public_key must decode to 32 bytes",
                       {"field": "public_key", "got_bytes": len(public_key)})
    root_hash = _b16(payload["root_hash"], "root_hash")
    if len(root_hash) != 32:
        raise ApiError(400, "invalid_field",
                       "root_hash must decode to 32 bytes",
                       {"field": "root_hash", "got_bytes": len(root_hash)})
    signature = _b16(payload["signature"], "signature")
    if len(signature) != 64:
        raise ApiError(400, "invalid_field",
                       "signature must decode to 64 bytes",
                       {"field": "signature", "got_bytes": len(signature)})

    tree_size = payload["tree_size"]
    if isinstance(tree_size, bool) or not isinstance(tree_size, int):
        raise ApiError(400, "invalid_field", "tree_size must be an integer",
                       {"field": "tree_size"})
    if tree_size <= 0:
        raise ApiError(400, "invalid_field", "tree_size must be >= 1",
                       {"field": "tree_size"})
    if tree_size > 0xFFFFFFFFFFFFFFFF:
        raise ApiError(400, "invalid_field", "tree_size out of u64 range",
                       {"field": "tree_size"})

    timestamp_ms = payload["timestamp_ms"]
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int):
        raise ApiError(400, "invalid_field",
                       "timestamp_ms must be an integer",
                       {"field": "timestamp_ms"})
    if not (0 <= timestamp_ms <= 0xFFFFFFFFFFFFFFFF):
        raise ApiError(400, "invalid_field",
                       "timestamp_ms out of u64 range",
                       {"field": "timestamp_ms"})

    proof_raw = payload["consistency"]
    if not isinstance(proof_raw, list):
        raise ApiError(400, "invalid_field",
                       "consistency must be an array of hex strings",
                       {"field": "consistency"})
    if len(proof_raw) > MAX_PROOF_NODES:
        raise ApiError(400, "proof_too_large",
                       f"consistency proof has more than {MAX_PROOF_NODES}"
                       " nodes", {"got": len(proof_raw)})
    proof = []
    for i, node in enumerate(proof_raw):
        raw = _b16(node, f"consistency[{i}]")
        if len(raw) != 32:
            raise ApiError(400, "invalid_field",
                           "consistency entries must decode to 32 bytes",
                           {"field": f"consistency[{i}]",
                            "got_bytes": len(raw)})
        proof.append(raw)

    # Signature is verified over the canonical binary message -- never over
    # the JSON body.
    message = canonical.encode_message(
        log_id, public_key, tree_size, timestamp_ms, root_hash
    )
    try:
        ed25519.verify(message, signature, public_key)
    except ed25519.PublicKeyError as exc:
        raise ApiError(400, "invalid_public_key", str(exc),
                       {"field": "public_key"})
    except ed25519.SignatureError as exc:
        raise ApiError(400, "invalid_signature",
                       f"signature does not verify over the canonical binary"
                       f" checkpoint message: {exc}",
                       {"field": "signature"})

    return Submission(public_key, tree_size, timestamp_ms,
                      root_hash, signature, proof)


def parse_receipt_request(body: bytes) -> ReceiptRequest:
    """Validate the JSON shape of a receipt submission.

    Inclusion against a *saved* checkpoint is performed later by the service
    (it needs durable state); this function only does stateless checks and
    hashes the raw sample to its RFC 9162 leaf hash.
    """
    if len(body) > MAX_BODY_BYTES:
        raise ApiError(413, "body_too_large",
                       f"request body exceeds {MAX_BODY_BYTES} bytes")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(400, "invalid_json", f"request body is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        raise ApiError(400, "invalid_json", "request body must be a JSON object")

    required = ("receipt_id", "tree_size", "leaf_index",
                "leaf_data", "inclusion_proof")
    missing = [f for f in required if f not in payload]
    if missing:
        raise ApiError(400, "missing_fields",
                       "missing required fields", {"fields": missing})

    receipt_id = payload["receipt_id"]
    if not isinstance(receipt_id, str) or not receipt_id:
        raise ApiError(400, "invalid_field",
                       "receipt_id must be a non-empty string",
                       {"field": "receipt_id"})
    try:
        rid_raw = receipt_id.encode("ascii")
    except UnicodeEncodeError:
        raise ApiError(400, "invalid_field",
                       "receipt_id must be printable ASCII (0x20-0x7E)",
                       {"field": "receipt_id"})
    if len(rid_raw) > MAX_RECEIPT_ID_LEN \
            or not all(0x20 <= b <= 0x7E for b in rid_raw):
        raise ApiError(400, "invalid_field",
                       f"receipt_id must be printable ASCII and at most"
                       f" {MAX_RECEIPT_ID_LEN} bytes",
                       {"field": "receipt_id", "got_bytes": len(rid_raw)})
    if b"/" in rid_raw:
        # A literal path separator would make /receipts/{receiptId}
        # unaddressable; percent-encoded slash (%2F) is still allowed.
        raise ApiError(400, "invalid_field",
                       "receipt_id must not contain '/'",
                       {"field": "receipt_id"})

    tree_size = payload["tree_size"]
    if isinstance(tree_size, bool) or not isinstance(tree_size, int):
        raise ApiError(400, "invalid_field", "tree_size must be an integer",
                       {"field": "tree_size"})
    if not (1 <= tree_size <= 0xFFFFFFFFFFFFFFFF):
        raise ApiError(400, "invalid_field",
                       "tree_size must be in [1, 2^64-1]",
                       {"field": "tree_size"})

    leaf_index = payload["leaf_index"]
    if isinstance(leaf_index, bool) or not isinstance(leaf_index, int):
        raise ApiError(400, "invalid_field", "leaf_index must be an integer",
                       {"field": "leaf_index"})
    if not (0 <= leaf_index < tree_size):
        raise ApiError(400, "invalid_field",
                       "leaf_index must satisfy 0 <= leaf_index < tree_size",
                       {"field": "leaf_index", "tree_size": tree_size})

    leaf_data = _b16(payload["leaf_data"], "leaf_data")
    if not leaf_data:
        raise ApiError(400, "invalid_field",
                       "leaf_data must decode to at least one byte",
                       {"field": "leaf_data"})
    if len(leaf_data) > MAX_RECEIPT_SAMPLE_BYTES:
        raise ApiError(400, "invalid_field",
                       f"leaf_data exceeds {MAX_RECEIPT_SAMPLE_BYTES} bytes",
                       {"field": "leaf_data", "got_bytes": len(leaf_data)})

    proof_raw = payload["inclusion_proof"]
    if not isinstance(proof_raw, list):
        raise ApiError(400, "invalid_field",
                       "inclusion_proof must be an array of hex strings",
                       {"field": "inclusion_proof"})
    if len(proof_raw) > MAX_PROOF_NODES:
        raise ApiError(400, "proof_too_large",
                       f"inclusion proof has more than {MAX_PROOF_NODES} nodes",
                       {"got": len(proof_raw)})
    proof = []
    for i, node in enumerate(proof_raw):
        raw = _b16(node, f"inclusion_proof[{i}]")
        if len(raw) != 32:
            raise ApiError(400, "invalid_field",
                           "inclusion_proof entries must decode to 32 bytes",
                           {"field": f"inclusion_proof[{i}]",
                            "got_bytes": len(raw)})
        proof.append(raw)

    return ReceiptRequest(receipt_id, tree_size, leaf_index,
                          leaf_data, merkle.hash_leaf(leaf_data), proof)


class Service:
    def __init__(self, store: Store):
        self.store = store

    def submit(self, log_id: str, sub: Submission) -> tuple[int, dict]:
        store = self.store
        # Serialise the read/verify/write critical section in-process; SQLite
        # BEGIN IMMEDIATE additionally protects against outside writers.
        with store.lock:
            current = store.get_log(log_id)
            if current is None:
                if sub.consistency:
                    raise ApiError(
                        409, "consistency_without_anchor",
                        "a consistency proof was supplied but no trusted"
                        " checkpoint exists for this log yet",
                        {"field": "consistency"})
                try:
                    store.freeze_first(log_id, sub, now_ms())
                    return 201, {
                        "result": "frozen",
                        "log_id": log_id,
                        "tree_size": sub.tree_size,
                        "root_hash": sub.root_hash.hex(),
                        "public_key": sub.public_key.hex(),
                    }
                except RuntimeError:
                    # A concurrent first submission won; fall through to
                    # ordinary adjudication against the now-frozen head
                    # (identical -> replay; divergent -> fork evidence).
                    current = store.get_log(log_id)
                    if current is None:  # pragma: no cover - impossible
                        raise ApiError(500, "internal_error",
                                       "log vanished after concurrent freeze")

            if sub.tree_size < current.tree_size:
                raise ApiError(
                    409, "stale_tree_size",
                    f"trusted tree is already at size {current.tree_size},"
                    f" which is larger than {sub.tree_size}",
                    {"trusted_tree_size": current.tree_size,
                     "submitted_tree_size": sub.tree_size})

            prior_fork = store.first_fork(log_id)

            if sub.tree_size == current.tree_size:
                identical = (
                    sub.root_hash == current.root_hash
                    and sub.timestamp_ms == current.timestamp_ms
                    and sub.public_key == current.public_key
                    and sub.signature == current.signature
                )
                if identical:
                    # Idempotent replay (covers concurrent duplicate
                    # extensions that arrived after the winner).
                    return 200, {
                        "result": "already_trusted",
                        "log_id": log_id,
                        "tree_size": current.tree_size,
                        "root_hash": current.root_hash.hex(),
                        "public_key": current.public_key.hex(),
                    }
                # Same size, verified signature, differing root/time/key/sig:
                # seal the FIRST fork evidence, keep the original record.
                if prior_fork is not None:
                    raise ApiError(
                        409, "fork_evidence_sealed",
                        "verified equivocation at the same tree size; fork"
                        " evidence is already sealed and the trusted head is"
                        " unchanged",
                        {"fork_id": prior_fork["id"],
                         "trusted_tree_size": current.tree_size,
                         "trusted_root_hash": current.root_hash.hex()})
                fork_id = store.seal_fork(
                    current, sub, "same_size_different_head",
                    json.dumps([n.hex() for n in sub.consistency]).encode(),
                    now_ms(),
                )
                raise ApiError(
                    409, "fork_evidence_sealed",
                    "verified equivocation at the same tree size; the first"
                    " fork evidence has been sealed and the trusted head is"
                    " unchanged",
                    {"fork_id": fork_id,
                     "trusted_tree_size": current.tree_size,
                     "trusted_root_hash": current.root_hash.hex(),
                     "rival_root_hash": sub.root_hash.hex()})

            # Larger tree from here on.
            if prior_fork is not None or current.status == "fork_sealed":
                raise ApiError(
                    409, "log_sealed",
                    "this log is sealed after equivocation evidence was"
                    " sealed; the trusted head will not advance",
                    {"trusted_tree_size": current.tree_size})

            if sub.public_key != current.public_key:
                raise ApiError(
                    409, "public_key_frozen",
                    "the public key for this log is frozen to the first"
                    " verified checkpoint; key rotation is not permitted for"
                    " tree extensions",
                    {"frozen_public_key": current.public_key.hex(),
                     "submitted_public_key": sub.public_key.hex()})

            # The proof must show the trusted tree is a prefix of the
            # submitted one.  Verify first, write after.
            try:
                merkle.verify_consistency(
                    current.tree_size, current.root_hash,
                    sub.tree_size, sub.root_hash, sub.consistency,
                )
            except ValueError as exc:
                raise ApiError(
                    400, "invalid_consistency_proof",
                    f"consistency proof failed: {exc}",
                    {"trusted_tree_size": current.tree_size,
                     "trusted_root_hash": current.root_hash.hex(),
                     "submitted_tree_size": sub.tree_size,
                     "submitted_root_hash": sub.root_hash.hex(),
                     "proof_nodes": len(sub.consistency)})

            applied = True
            try:
                store.advance(log_id, sub, now_ms())
            except RuntimeError:
                # A concurrent identical extension won; re-read and return
                # the same adjudication it got.
                applied = False
            current = store.get_log(log_id)

            if current.status == "fork_sealed":
                raise ApiError(
                    409, "log_sealed",
                    "a concurrent submission sealed fork evidence; the"
                    " trusted head will not advance",
                    {"trusted_tree_size": current.tree_size})
            if current.tree_size == sub.tree_size \
                    and current.root_hash == sub.root_hash \
                    and current.signature == sub.signature:
                return 200, {
                    "result": "trusted",
                    "applied": applied,
                    "log_id": log_id,
                    "tree_size": sub.tree_size,
                    "root_hash": sub.root_hash.hex(),
                    "public_key": current.public_key.hex(),
                }
            raise ApiError(409, "concurrent_conflict",
                           "a conflicting concurrent commit changed the"
                           " trusted head",
                           {"trusted_tree_size": current.tree_size})

    def describe_log(self, log_id: str) -> dict:
        current = self.store.get_log(log_id)
        if current is None:
            raise ApiError(404, "log_not_found",
                           f"no checkpoint has ever been accepted for"
                           f" log {log_id!r}")
        fork = self.store.first_fork(log_id)
        return {
            "log_id": current.log_id,
            "public_key": current.public_key.hex(),
            "tree_size": current.tree_size,
            "root_hash": current.root_hash.hex(),
            "timestamp_ms": current.timestamp_ms,
            "status": current.status,
            "created_at": current.created_at,
            "updated_at": current.updated_at,
            "fork": _fork_payload(fork),
        }

    # ------------------------------------------------------------ receipts

    def submit_receipt(self, log_id: str, req: ReceiptRequest) -> tuple[int, dict]:
        store = self.store
        # Receipt reads/adjudication never touch checkpoint state, so the
        # read-verify-write section only needs the same process-wide
        # serialisation as checkpoint submission.
        with store.lock:
            current = store.get_log(log_id)
            if current is None:
                raise ApiError(404, "log_not_found",
                               f"no checkpoint has ever been accepted for"
                               f" log {log_id!r}")

            # An existing receipt id is immutable: identical retries return
            # the original receipt, any other reuse is a conflict.  This is
            # adjudicated before proof verification so a malformed retry can
            # neither overwrite nor shadow the committed verdict.
            existing = store.get_receipt(log_id, req.receipt_id)
            if existing is not None:
                same, diffs = _same_receipt(existing, req)
                if same:
                    return 200, self._receipt_payload(existing, "already_sealed")
                raise ApiError(
                    409, "receipt_conflict",
                    "receipt_id was already committed with different content;"
                    " receipts are immutable and the original receipt is"
                    " unchanged",
                    {"receipt_id": req.receipt_id, "differing_fields": diffs})

            # The target size must match a checkpoint the log actually
            # published -- a historical one or the current head, on active
            # and fork-sealed logs alike.
            cp = store.get_checkpoint(log_id, req.tree_size)
            if cp is None:
                raise ApiError(
                    409, "checkpoint_not_found",
                    f"this log has no saved checkpoint at tree size"
                    f" {req.tree_size}; receipts may only bind to published"
                    f" checkpoints",
                    {"tree_size": req.tree_size,
                     "trusted_tree_size": current.tree_size})

            root = bytes(cp["root_hash"])
            try:
                merkle.verify_inclusion(
                    req.leaf_hash, req.leaf_index,
                    cp["tree_size"], root, req.proof,
                )
            except ValueError as exc:
                raise ApiError(
                    400, "invalid_inclusion_proof",
                    f"inclusion proof failed: {exc}",
                    {"tree_size": cp["tree_size"],
                     "root_hash": root.hex(),
                     "leaf_index": req.leaf_index,
                     "proof_nodes": len(req.proof)})

            try:
                store.save_receipt(log_id, req, cp, now_ms())
            except RuntimeError:
                # A concurrent request committed the same receipt id first;
                # re-read and apply the same idempotency/conflict verdict.
                winner = store.get_receipt(log_id, req.receipt_id)
                if winner is not None:
                    same, _diffs = _same_receipt(winner, req)
                    if same:
                        return 200, self._receipt_payload(
                            winner, "already_sealed")
                raise ApiError(
                    409, "receipt_conflict",
                    "a concurrent submission committed this receipt_id with"
                    " different content; the original receipt is unchanged",
                    {"receipt_id": req.receipt_id})
            saved = store.get_receipt(log_id, req.receipt_id)
            return 201, self._receipt_payload(saved, "sealed")

    def read_receipt(self, log_id: str, receipt_id: str) -> dict:
        current = self.store.get_log(log_id)
        if current is None:
            raise ApiError(404, "log_not_found",
                           f"no checkpoint has ever been accepted for"
                           f" log {log_id!r}")
        row = self.store.get_receipt(log_id, receipt_id)
        if row is None:
            raise ApiError(404, "receipt_not_found",
                           f"no receipt {receipt_id!r} has been committed for"
                           f" log {log_id!r}")
        # Receipts stay readable on fork-sealed logs.
        return self._receipt_payload(row, "sealed")

    @staticmethod
    def _receipt_payload(row, result: str) -> dict:
        try:
            proof = json.loads(row["proof"])
        except (ValueError, TypeError):
            proof = []
        return {
            "result": result,
            "log_id": row["log_id"],
            "receipt_id": row["receipt_id"],
            "created_at": row["created_at"],
            "target_checkpoint": {
                "tree_size": row["target_size"],
                "root_hash": bytes(row["root_hash"]).hex(),
                "timestamp_ms": row["timestamp_ms"],
            },
            "leaf_hash": bytes(row["leaf_hash"]).hex(),
            "leaf_index": row["leaf_index"],
            "inclusion_proof": proof,
        }


def _same_receipt(row, req: ReceiptRequest) -> tuple[bool, list[str]]:
    """Compare a committed receipt row with a new request; list diffs."""
    diffs = []
    if row["target_size"] != req.tree_size:
        diffs.append("tree_size")
    if row["leaf_index"] != req.leaf_index:
        diffs.append("leaf_index")
    if bytes(row["leaf_data"]) != req.leaf_data:
        diffs.append("leaf_data")
    if bytes(row["leaf_hash"]) != req.leaf_hash:
        diffs.append("leaf_hash")
    try:
        committed_proof = json.loads(row["proof"])
    except (ValueError, TypeError):
        committed_proof = None
    if committed_proof != [n.hex() for n in req.proof]:
        diffs.append("inclusion_proof")
    return (not diffs), diffs


def _fork_payload(row) -> dict | None:
    if row is None:
        return None
    try:
        proof = json.loads(row["proof"])
    except (ValueError, TypeError):
        proof = []
    return {
        "fork_id": row["id"],
        "reason": row["reason"],
        "created_at": row["created_at"],
        "trusted": {
            "tree_size": row["trusted_size"],
            "root_hash": bytes(row["trusted_root"]).hex(),
            "timestamp_ms": row["trusted_ts"],
            "public_key": bytes(row["trusted_key"]).hex(),
            "signature": bytes(row["trusted_sig"]).hex(),
        },
        "rival": {
            "root_hash": bytes(row["rival_root"]).hex(),
            "timestamp_ms": row["rival_ts"],
            "public_key": bytes(row["rival_key"]).hex(),
            "signature": bytes(row["rival_sig"]).hex(),
        },
        "consistency": proof,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SeafloorCheckpoint/1.0"

    def log_message(self, fmt, *args):  # route access logs to stderr
        sys.stderr.write("%s - - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, err: ApiError) -> None:
        self._send_json(err.http_status, {"error": {
            "code": err.code, "message": err.message, "details": err.details,
        }})

    def do_GET(self) -> None:
        try:
            parts = [unquote(p) for p in urlsplit(self.path).path.split("/")
                     if p]
            if parts == ["healthz"]:
                self.server.store.ping()
                self._send_json(200, {"status": "ok"})
                return
            if parts == ["logs"]:
                self._send_json(200, {
                    "logs": self.server.service.store.list_logs()})
                return
            if len(parts) == 2 and parts[0] == "logs":
                log_id = parts[1]
                _valid_log_id(log_id)
                self._send_json(200, self.server.service.describe_log(log_id))
                return
            if len(parts) == 4 and parts[0] == "logs" \
                    and parts[2] == "receipts":
                log_id, receipt_id = parts[1], parts[3]
                _valid_log_id(log_id)
                self._send_json(
                    200, self.server.service.read_receipt(log_id, receipt_id))
                return
            self._send_error(ApiError(404, "not_found", "unknown route"))
        except ApiError as err:
            self._send_error(err)
        except Exception as exc:  # pragma: no cover - defensive
            self.server.exception_hook(exc)
            self._send_error(ApiError(500, "internal_error", str(exc)))

    def do_POST(self) -> None:
        try:
            parts = [unquote(p) for p in urlsplit(self.path).path.split("/")
                     if p]
            if len(parts) != 3 or parts[0] != "logs" \
                    or parts[2] not in ("checkpoints", "receipts"):
                self._send_error(ApiError(404, "not_found",
                    "POST target must be /logs/{logId}/checkpoints"
                    " or /logs/{logId}/receipts"))
                return
            log_id = parts[1]
            _valid_log_id(log_id)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ApiError(400, "invalid_content_length",
                               "Content-Length must be a non-negative integer")
            if length <= 0:
                raise ApiError(400, "empty_body",
                               "expected a JSON request body")
            if length > MAX_BODY_BYTES:
                raise ApiError(413, "body_too_large",
                               f"request body exceeds {MAX_BODY_BYTES} bytes")
            body = self.rfile.read(length)
            if parts[2] == "receipts":
                req = parse_receipt_request(body)
                status, payload = self.server.service.submit_receipt(
                    log_id, req)
            else:
                sub = parse_submission(log_id, body)
                status, payload = self.server.service.submit(log_id, sub)
            self._send_json(status, payload)
        except ApiError as err:
            self._send_error(err)
        except Exception as exc:  # pragma: no cover - defensive
            self.server.exception_hook(exc)
            self._send_error(ApiError(500, "internal_error", str(exc)))


def build_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    store = Store(db_path)
    service = Service(store)
    server = ThreadingHTTPServer((host, port), Handler)
    server.service = service
    server.store = store

    def exception_hook(exc):
        sys.stderr.write(f"unhandled error: {exc!r}\n")

    server.exception_hook = exception_hook
    return server


def main(argv: list[str] | None = None) -> int:
    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "/data/checkpoints.db")
    server = build_server(host, port, db_path)
    sys.stderr.write(
        f"seafloor checkpoint API listening on {host}:{port}"
        f" (db={db_path})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
