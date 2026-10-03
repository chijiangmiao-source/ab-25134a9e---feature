"""Service-level adjudication tests against a temporary SQLite database."""

import json
import os
import tempfile
import unittest

from app import canonical, ed25519, merkle
from app.server import ApiError, Service, Submission, parse_receipt_request
from app.storage import Store


def make_signer():
    seed, pub = ed25519.generate_keypair()

    def sign(log_id, size, ts, root):
        return ed25519.sign(
            canonical.encode_message(log_id, pub, size, ts, root), seed)

    return seed, pub, sign


class Harness:
    def __init__(self, store):
        self.svc = Service(store)
        self.seed, self.pub, self.sign = make_signer()
        self.leaves = [merkle.hash_leaf(os.urandom(8)) for _ in range(16)]
        self.roots = {n: merkle.tree_hash(self.leaves[:n])
                      for n in range(1, 17)}

    def sub(self, log_id, size, ts, root=None, proof=None,
            pub=None, signer=None):
        pub = pub or self.pub
        root = root or self.roots[size]
        proof = proof if proof is not None else []
        signer = signer or self.sign
        return Submission(pub, size, ts, root, signer(log_id, size, ts, root),
                          proof)


class ServiceRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.h = Harness(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_freeze_advance_replay_fork(self):
        h, svc = self.h, self.h.svc
        log = "L"
        status, out = svc.submit(log, h.sub(log, 3, 100))
        self.assertEqual((status, out["result"]), (201, "frozen"))

        # frozen key visible via describe
        desc = svc.describe_log(log)
        self.assertEqual(desc["tree_size"], 3)
        self.assertEqual(desc["public_key"], h.pub.hex())
        self.assertIsNone(desc["fork"])

        # valid extension
        proof = merkle.consistency_proof(3, h.leaves[:5])
        status, out = svc.submit(log, h.sub(log, 5, 200, proof=proof))
        self.assertEqual(out["result"], "trusted")
        self.assertTrue(out["applied"])

        # identical replay
        status, out = svc.submit(log, h.sub(log, 5, 200, proof=proof))
        self.assertEqual(out["result"], "already_trusted")

        # same-size different root signed by the frozen key -> fork
        rival_root = merkle.hash_leaf(b"rival")
        with self.assertRaises(ApiError) as ctx:
            svc.submit(log, h.sub(log, 5, 201, root=rival_root))
        self.assertEqual(ctx.exception.code, "fork_evidence_sealed")

        desc = svc.describe_log(log)
        self.assertEqual(desc["status"], "fork_sealed")
        self.assertEqual(desc["tree_size"], 5)
        self.assertEqual(desc["root_hash"], h.roots[5].hex())
        self.assertEqual(desc["fork"]["rival"]["root_hash"],
                         rival_root.hex())

        # second fork must not overwrite the first evidence
        rival2 = merkle.hash_leaf(b"rival2")
        with self.assertRaises(ApiError):
            svc.submit(log, h.sub(log, 5, 202, root=rival2))
        self.assertEqual(svc.describe_log(log)["fork"]["rival"]["root_hash"],
                         rival_root.hex())

        # extension blocked after seal
        with self.assertRaises(ApiError) as ctx:
            svc.submit(log, h.sub(
                log, 6, 300,
                proof=merkle.consistency_proof(5, h.leaves[:6])))
        self.assertEqual(ctx.exception.code, "log_sealed")

    def test_stale_and_key_freeze(self):
        h, svc = self.h, self.h.svc
        log = "K"
        svc.submit(log, h.sub(log, 4, 100))
        with self.assertRaises(ApiError) as ctx:
            svc.submit(log, h.sub(log, 3, 90))
        self.assertEqual(ctx.exception.code, "stale_tree_size")

        _, pub2, signer2 = make_signer()
        with self.assertRaises(ApiError) as ctx:
            svc.submit(log, h.sub(log, 6, 200, pub=pub2, signer=signer2,
                                  proof=merkle.consistency_proof(
                                      4, h.leaves[:6])))
        self.assertEqual(ctx.exception.code, "public_key_frozen")

    def test_invalid_signature_rejected_at_parse(self):
        import json

        from app.server import parse_submission
        h, svc = self.h, self.h.svc
        log = "V"
        svc.submit(log, h.sub(log, 2, 100))
        payload = {
            "public_key": h.pub.hex(),
            "tree_size": 3,
            "timestamp_ms": 200,
            "root_hash": h.roots[3].hex(),
            "signature": ("00" * 64),
            "consistency": [n.hex() for n in
                            merkle.consistency_proof(2, h.leaves[:3])],
        }
        with self.assertRaises(ApiError) as ctx:
            parse_submission(log, json.dumps(payload).encode())
        self.assertEqual(ctx.exception.code, "invalid_signature")
        self.assertEqual(svc.describe_log(log)["tree_size"], 2)

    def test_bad_proof_rejected_before_write(self):
        h, svc = self.h, self.h.svc
        log = "P"
        svc.submit(log, h.sub(log, 2, 100))
        proof = merkle.consistency_proof(2, h.leaves[:6])[:-1]  # truncated
        with self.assertRaises(ApiError) as ctx:
            svc.submit(log, h.sub(log, 6, 200, proof=proof))
        self.assertEqual(ctx.exception.code, "invalid_consistency_proof")
        self.assertEqual(svc.describe_log(log)["tree_size"], 2)

    def test_unknown_log(self):
        with self.assertRaises(ApiError) as ctx:
            self.h.svc.describe_log("ghost")
        self.assertEqual(ctx.exception.http_status, 404)


def receipt_body(receipt_id, size, index, sample: bytes, proof):
    return {
        "receipt_id": receipt_id,
        "tree_size": size,
        "leaf_index": index,
        "leaf_data": sample.hex(),
        "inclusion_proof": [n.hex() for n in proof],
    }


class ReceiptRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.svc = Service(self.store)
        self.seed, self.pub, self.sign = make_signer()
        # 16 published leaves; checkpoints accepted at sizes 3, 5, 8.
        self.samples = [b"sample-%02d" % i for i in range(16)]
        self.leaves = [merkle.hash_leaf(s) for s in self.samples]
        self.roots = {n: merkle.tree_hash(self.leaves[:n])
                      for n in range(1, 17)}
        self.log = "RC"
        for size, ts in ((3, 100), (5, 200), (8, 300)):
            proof = [] if size == 3 else merkle.consistency_proof(
                {3: 3, 5: 3, 8: 5}[size], self.leaves[:size])
            self.svc.submit(self.log, Submission(
                self.pub, size, ts, self.roots[size],
                self.sign(self.log, size, ts, self.roots[size]), proof))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _req(self, receipt_id, size, index, sample=None, proof=None):
        sample = self.samples[index] if sample is None else sample
        proof = merkle.inclusion_proof(self.leaves[:size], index) \
            if proof is None else proof
        return parse_receipt_request(json.dumps(receipt_body(
            receipt_id, size, index, sample, proof)).encode())

    def test_seal_read_idempotent_historical_and_after_advance(self):
        # Bind to a historical checkpoint (size 3, head is already at 8).
        req = self._req("rc-1", 3, 1)
        status, out = self.svc.submit_receipt(self.log, req)
        self.assertEqual((status, out["result"]), (201, "sealed"))
        self.assertEqual(out["target_checkpoint"]["tree_size"], 3)
        self.assertEqual(out["target_checkpoint"]["root_hash"],
                         self.roots[3].hex())
        self.assertEqual(out["leaf_index"], 1)
        self.assertEqual(out["leaf_hash"], self.leaves[1].hex())
        self.assertEqual(len(out["inclusion_proof"]),
                         len(merkle.inclusion_proof(self.leaves[:3], 1)))

        # Readback.
        got = self.svc.read_receipt(self.log, "rc-1")
        self.assertEqual(got["target_checkpoint"], out["target_checkpoint"])
        self.assertEqual(got["leaf_hash"], out["leaf_hash"])
        self.assertEqual(got["inclusion_proof"], out["inclusion_proof"])

        # Identical resubmission returns the original receipt.
        status, again = self.svc.submit_receipt(
            self.log, self._req("rc-1", 3, 1))
        self.assertEqual(status, 200)
        self.assertEqual(again["result"], "already_sealed")
        self.assertEqual(again["created_at"], out["created_at"])
        self.assertEqual(
            self.store.get_receipt(self.log, "rc-1")["id"],
            self.store.get_receipt(self.log, "rc-1")["id"])

        # Log advances afterwards; historical receipt still reads back and a
        # new receipt can target the fresh head.
        proof = merkle.consistency_proof(8, self.leaves[:10])
        self.svc.submit(self.log, Submission(
            self.pub, 10, 400, self.roots[10],
            self.sign(self.log, 10, 400, self.roots[10]), proof))
        self.assertEqual(
            self.svc.read_receipt(self.log, "rc-1")["target_checkpoint"]
            ["tree_size"], 3)
        status, out2 = self.svc.submit_receipt(
            self.log, self._req("rc-2", 10, 9))
        self.assertEqual((status, out2["result"]), (201, "sealed"))
        self.assertEqual(out2["target_checkpoint"]["tree_size"], 10)

    def test_conflict_on_reused_id(self):
        self.svc.submit_receipt(self.log, self._req("rc-x", 5, 2))

        # Same id, different sample.
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(
                self.log, self._req("rc-x", 5, 2, sample=b"other-sample"))
        self.assertEqual(ctx.exception.code, "receipt_conflict")
        self.assertIn("leaf_data", ctx.exception.details["differing_fields"])

        # Same id, different index/position.
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req("rc-x", 5, 3))
        self.assertEqual(ctx.exception.code, "receipt_conflict")
        self.assertIn("leaf_index", ctx.exception.details["differing_fields"])

        # Same id, different target checkpoint.
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req("rc-x", 8, 2))
        self.assertEqual(ctx.exception.code, "receipt_conflict")
        self.assertIn("tree_size", ctx.exception.details["differing_fields"])

        # Same id, tampered proof.
        good_proof = merkle.inclusion_proof(self.leaves[:5], 2)
        bad_proof = good_proof[:-1]
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req(
                "rc-x", 5, 2, proof=bad_proof))
        self.assertEqual(ctx.exception.code, "receipt_conflict")
        self.assertIn("inclusion_proof",
                      ctx.exception.details["differing_fields"])

        # Original receipt untouched.
        got = self.svc.read_receipt(self.log, "rc-x")
        self.assertEqual(got["leaf_index"], 2)
        self.assertEqual(got["target_checkpoint"]["tree_size"], 5)
        self.assertEqual(got["leaf_hash"], self.leaves[2].hex())

    def test_bad_index_forged_proof_and_unsaved_size_leave_no_record(self):
        # No saved checkpoint at size 7 (only 3/5/8).
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req("rc-n1", 7, 0))
        self.assertEqual(ctx.exception.code, "checkpoint_not_found")

        # Index out of range is a 400 shape error.
        with self.assertRaises(ApiError) as ctx:
            parse_receipt_request(json.dumps(receipt_body(
                "rc-n2", 5, 5, self.samples[0], [])).encode())
        self.assertEqual(ctx.exception.code, "invalid_field")

        # Index within the claimed size but inconsistent with the real tree:
        # claim index 3 against size 3 is caught above; instead forge a proof
        # for index 2 against size 5 using proof nodes from another leaf.
        forged = [bytes(32)] + merkle.inclusion_proof(
            self.leaves[:5], 2)[1:]
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req(
                "rc-n3", 5, 2, proof=forged))
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # A truncated proof also fails.
        trunc = merkle.inclusion_proof(self.leaves[:5], 2)[:-1]
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req(
                "rc-n4", 5, 2, proof=trunc))
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # Wrong leaf bytes: valid proof shape, but leaf hash mismatch.
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req(
                "rc-n5", 5, 2, sample=b"not-the-committed-sample"))
        self.assertEqual(ctx.exception.code, "invalid_inclusion_proof")

        # Nothing was persisted by any failed attempt.
        for rid in ("rc-n1", "rc-n2", "rc-n3", "rc-n4", "rc-n5"):
            self.assertIsNone(self.store.get_receipt(self.log, rid))

        with self.assertRaises(ApiError) as ctx:
            self.svc.read_receipt(self.log, "rc-n3")
        self.assertEqual(ctx.exception.http_status, 404)

    def test_receipts_on_fork_sealed_log(self):
        # Provoke a fork at size 8, sealing the log.
        rival_root = merkle.hash_leaf(b"rival")
        with self.assertRaises(ApiError):
            self.svc.submit(self.log, Submission(
                self.pub, 8, 301, rival_root,
                self.sign(self.log, 8, 301, rival_root), []))
        self.assertEqual(self.svc.describe_log(self.log)["status"],
                         "fork_sealed")

        # Existing historical checkpoint still accepts receipts.
        status, out = self.svc.submit_receipt(
            self.log, self._req("rc-sealed", 5, 4))
        self.assertEqual((status, out["result"]), (201, "sealed"))
        self.assertEqual(out["target_checkpoint"]["tree_size"], 5)
        got = self.svc.read_receipt(self.log, "rc-sealed")
        self.assertEqual(got["leaf_hash"], self.leaves[4].hex())

        # A checkpoint size never saved is unavailable even when sealed.
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt(self.log, self._req("rc-no", 6, 0))
        self.assertEqual(ctx.exception.code, "checkpoint_not_found")

    def test_unknown_log_and_unknown_receipt(self):
        with self.assertRaises(ApiError) as ctx:
            self.svc.submit_receipt("ghost", self._req("z", 3, 0))
        self.assertEqual(ctx.exception.http_status, 404)
        with self.assertRaises(ApiError) as ctx:
            self.svc.read_receipt(self.log, "missing")
        self.assertEqual(ctx.exception.http_status, 404)

    def test_receipt_id_shape_rules(self):
        for bad in ("", "a/b", "space-ok-but-too" + "x" * 256):
            with self.assertRaises(ApiError) as ctx:
                parse_receipt_request(json.dumps(receipt_body(
                    bad, 3, 0, self.samples[0], [])).encode())
            self.assertEqual(ctx.exception.code, "invalid_field", bad)
        # percent-encoded slash in the JSON string is just two characters and
        # is therefore accepted as a regular id
        req = parse_receipt_request(json.dumps(receipt_body(
            "a%2Fb", 3, 0, self.samples[0],
            merkle.inclusion_proof(self.leaves[:3], 0))).encode())
        self.assertEqual(req.receipt_id, "a%2Fb")


if __name__ == "__main__":
    unittest.main()
