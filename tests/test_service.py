"""Service-level adjudication tests against a temporary SQLite database."""

import os
import tempfile
import unittest

from app import canonical, ed25519, merkle
from app.server import ApiError, Service, Submission
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


if __name__ == "__main__":
    unittest.main()
