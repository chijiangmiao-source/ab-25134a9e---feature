"""Service-level tests for immutable review receipts."""

import os
import tempfile
import unittest

from app import ed25519, merkle
from app.server import ApiError, ReceiptRequest, Service
from app.storage import Store


class ReceiptHarness:
    def __init__(self, store):
        self.svc = Service(store)
        self.seed, self.pub = ed25519.generate_keypair()
        self.leaves = [merkle.hash_leaf(b"sample-%02d" % i) for i in range(16)]
        self.roots = {n: merkle.tree_hash(self.leaves[:n])
                      for n in range(1, 17)}

    def sign(self, log_id, size, ts, root):
        from app import canonical
        return ed25519.sign(
            canonical.encode_message(log_id, self.pub, size, ts, root),
            self.seed)

    def checkpoint(self, log_id, size, ts, proof=None):
        from app.server import Submission
        return Submission(self.pub, size, ts, self.roots[size],
                          self.sign(log_id, size, ts, self.roots[size]),
                          proof or [])

    def receipt(self, size, index, leaf_data, proof=None):
        if proof is None:
            proof = merkle.inclusion_proof(self.leaves[:size], index)
        return ReceiptRequest(size, index, leaf_data, proof)

    # leaf bytes -> their hash equals one of the known tree leaves
    @staticmethod
    def leaf_bytes(i):
        return b"sample-%02d" % i


class ReceiptRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.h = ReceiptHarness(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _bootstrap_and_advance(self, log="R"):
        h, svc = self.h, self.h.svc
        svc.submit(log, h.checkpoint(log, 3, 100))
        svc.submit(log, h.checkpoint(
            log, 5, 200, proof=merkle.consistency_proof(3, h.leaves[:5])))
        svc.submit(log, h.checkpoint(
            log, 8, 300, proof=merkle.consistency_proof(5, h.leaves[:8])))

    def test_bind_to_historical_checkpoint_then_readback_after_advance(self):
        h, svc = self.h, self.h.svc
        log = "R"
        self._bootstrap_and_advance(log)
        # Bind to an older saved checkpoint, not the current head.
        req = h.receipt(3, 1, h.leaf_bytes(1))
        status, out = svc.submit_receipt(log, "rcpt-1", req)
        self.assertEqual((status, out["result"]), (201, "saved"))
        self.assertEqual(out["checkpoint"]["tree_size"], 3)
        self.assertEqual(out["checkpoint"]["root_hash"],
                         h.roots[3].hex())
        self.assertEqual(out["leaf_index"], 1)
        self.assertEqual(out["leaf_hash"], h.leaves[1].hex())
        self.assertEqual(out["inclusion"],
                         [n.hex() for n in req.inclusion])

        # Advance the log afterwards; the receipt still reads back anchored
        # to the historical checkpoint.
        svc.submit(log, h.checkpoint(
            log, 12, 400, proof=merkle.consistency_proof(8, h.leaves[:12])))
        got = svc.get_receipt(log, "rcpt-1")
        self.assertEqual(got["checkpoint"]["tree_size"], 3)
        self.assertEqual(got["checkpoint"]["root_hash"],
                         h.roots[3].hex())
        self.assertEqual(got["leaf_hash"], h.leaves[1].hex())
        self.assertEqual(got["leaf_index"], 1)
        self.assertEqual(got["inclusion"], [n.hex() for n in req.inclusion])

    def test_identical_resubmission_is_idempotent(self):
        h, svc = self.h, self.h.svc
        log = "R"
        self._bootstrap_and_advance(log)
        req = h.receipt(5, 4, h.leaf_bytes(4))
        s1, o1 = svc.submit_receipt(log, "dup", req)
        s2, o2 = svc.submit_receipt(log, "dup", h.receipt(5, 4, h.leaf_bytes(4)))
        self.assertEqual((s1, o1["result"]), (201, "saved"))
        self.assertEqual((s2, o2["result"]), (200, "already_saved"))
        self.assertEqual(o1["leaf_hash"], o2["leaf_hash"])
        self.assertEqual(o1["checkpoint"], o2["checkpoint"])
        n = self.store._conn.execute(
            "SELECT COUNT(*) FROM receipts WHERE log_id=? AND receipt_id=?",
            (log, "dup")).fetchone()[0]
        self.assertEqual(n, 1)

    def test_single_leaf_tree_empty_proof_verifies(self):
        h, svc = self.h, self.h.svc
        log = "ONE"
        svc.submit(log, h.checkpoint(log, 1, 10))
        status, out = svc.submit_receipt(
            log, "solo", h.receipt(1, 0, h.leaf_bytes(0), proof=[]))
        self.assertEqual((status, out["result"]), (201, "saved"))
        self.assertEqual(out["inclusion"], [])

    def test_conflict_on_changed_sample_position_target_or_proof(self):
        h, svc = self.h, self.h.svc
        log = "R"
        self._bootstrap_and_advance(log)
        good = h.receipt(5, 2, h.leaf_bytes(2))
        svc.submit_receipt(log, "c", good)
        original = svc.get_receipt(log, "c")

        cases = {
            "sample": h.receipt(5, 2, b"different-sample"),
            "position": h.receipt(5, 3, h.leaf_bytes(3)),
            "target": h.receipt(3, 2, h.leaf_bytes(2)),
        }
        for label, bad in cases.items():
            with self.assertRaises(ApiError) as ctx:
                svc.submit_receipt(log, "c", bad)
            self.assertEqual(ctx.exception.http_status, 409, label)
            self.assertEqual(ctx.exception.code, "receipt_conflict", label)
            self.assertIn({
                "sample": "leaf_data",
                "position": "leaf_index",
                "target": "target_tree_size",
            }[label], ctx.exception.details["conflicts"], label)

        # Same everything but a tampered proof node.
        tampered = h.receipt(5, 2, h.leaf_bytes(2))
        tampered.inclusion[0] = bytes(32)
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "c", tampered)
        self.assertEqual(ctx.exception.code, "receipt_conflict")
        self.assertIn("inclusion", ctx.exception.details["conflicts"])

        # Stored receipt is untouched.
        self.assertEqual(svc.get_receipt(log, "c"), original)

    def test_unsaved_target_size_rejected(self):
        h, svc = self.h, self.h.svc
        log = "R"
        self._bootstrap_and_advance(log)
        # Sizes 4, 6, 7 were never published; no receipt may anchor there.
        req = h.receipt(7, 0, h.leaf_bytes(0),
                        proof=merkle.inclusion_proof(h.leaves[:7], 0))
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "x", req)
        self.assertEqual(ctx.exception.code, "checkpoint_not_saved")
        self.assertIsNone(svc.store.get_receipt(log, "x"))

    def test_forged_proof_and_bad_index_leave_no_record(self):
        h, svc = self.h, self.h.svc
        log = "R"
        self._bootstrap_and_advance(log)

        # Truncated proof -> inclusion fails.
        bad_proof = merkle.inclusion_proof(h.leaves[:8], 2)[:-1]
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "bad1",
                               h.receipt(8, 2, h.leaf_bytes(2), bad_proof))
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # Proof nodes for a different index -> root mismatch.
        wrong = h.receipt(8, 2, h.leaf_bytes(2),
                          merkle.inclusion_proof(h.leaves[:8], 5))
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "bad2", wrong)
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # Sample bytes that are not at the claimed leaf.
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "bad3",
                               h.receipt(8, 2, b"not-in-the-tree"))
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # index out of range is a field error
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "bad4", ReceiptRequest(
                8, 8, h.leaf_bytes(0), []))
        self.assertEqual(ctx.exception.http_status, 400)

        n = self.store._conn.execute(
            "SELECT COUNT(*) FROM receipts WHERE log_id=?", (log,)).fetchone()[0]
        self.assertEqual(n, 0)

    def test_unknown_log_and_missing_receipt(self):
        svc = self.h.svc
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt("ghost", "r",
                               ReceiptRequest(1, 0, b"x", []))
        self.assertEqual(ctx.exception.http_status, 404)
        self._bootstrap_and_advance("R")
        with self.assertRaises(ApiError) as ctx:
            svc.get_receipt("R", "missing")
        self.assertEqual(ctx.exception.code, "receipt_not_found")
        self.assertEqual(ctx.exception.http_status, 404)

    def test_sealed_log_still_serves_and_accepts_historical_receipts(self):
        h, svc = self.h, self.h.svc
        log = "SEAL"
        svc.submit(log, h.checkpoint(log, 3, 100))
        # Equivocation at the same size seals the log.
        rival_root = merkle.hash_leaf(b"rival")
        from app.server import Submission
        rival = Submission(
            h.pub, 3, 101, rival_root,
            h.sign(log, 3, 101, rival_root), [])
        with self.assertRaises(ApiError):
            svc.submit(log, rival)
        self.assertEqual(svc.describe_log(log)["status"], "fork_sealed")

        # A receipt against a previously trusted checkpoint still works...
        status, out = svc.submit_receipt(
            log, "after-seal", h.receipt(3, 0, h.leaf_bytes(0)))
        self.assertEqual((status, out["result"]), (201, "saved"))
        # ...and reads back.
        got = svc.get_receipt(log, "after-seal")
        self.assertEqual(got["checkpoint"]["root_hash"],
                         h.roots[3].hex())

    def test_receipt_never_binds_to_rival_root(self):
        h, svc = self.h, self.h.svc
        log = "SEAL2"
        svc.submit(log, h.checkpoint(log, 2, 100))
        rival_root = merkle.tree_hash(
            [merkle.hash_leaf(b"a"), merkle.hash_leaf(b"b")])
        from app.server import Submission
        rival = Submission(
            h.pub, 2, 101, rival_root,
            h.sign(log, 2, 101, rival_root), [])
        with self.assertRaises(ApiError):
            svc.submit(log, rival)
        # Only saved trusted checkpoints anchor receipts; the rival subtree
        # is not one even though its size matches.
        req = ReceiptRequest(
            2, 0, b"a",
            merkle.inclusion_proof(
                [merkle.hash_leaf(b"a"), merkle.hash_leaf(b"b")], 0))
        with self.assertRaises(ApiError) as ctx:
            svc.submit_receipt(log, "r", req)
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")


if __name__ == "__main__":
    unittest.main()
