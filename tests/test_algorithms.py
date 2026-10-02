"""Repository-level algorithm tests (stdlib unittest).

The containerised acceptance service (acceptance/harness.py) re-runs these
interleaved with live HTTP smoke observations.
"""

import hashlib
import os
import unittest

from app import canonical, ed25519, merkle


class Ed25519Vectors(unittest.TestCase):
    SEED = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    PUB = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    SIG = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_rfc8032_test1(self):
        self.assertEqual(ed25519.public_key_from_seed(self.SEED), self.PUB)
        self.assertEqual(ed25519.sign(b"", self.SEED), self.SIG)
        ed25519.verify(b"", self.SIG, self.PUB)

    def test_wrong_message_rejected(self):
        with self.assertRaises(ed25519.SignatureError):
            ed25519.verify(b"x", self.SIG, self.PUB)

    def test_roundtrip(self):
        seed, pub = ed25519.generate_keypair()
        msg = os.urandom(128)
        sig = ed25519.sign(msg, seed)
        ed25519.verify(msg, sig, pub)
        with self.assertRaises(ed25519.SignatureError):
            ed25519.verify(msg, sig[:-1] + bytes([sig[-1] ^ 1]), pub)


class MerkleProofs(unittest.TestCase):
    def setUp(self):
        self.leaves = [merkle.hash_leaf(b"leaf-%d" % i) for i in range(40)]
        self.roots = {n: merkle.tree_hash(self.leaves[:n])
                      for n in range(1, 41)}

    def test_prefix_pairs_all_verify(self):
        for n in range(2, 41):
            for old in range(1, n):
                proof = merkle.consistency_proof(old, self.leaves[:n])
                merkle.verify_consistency(
                    old, self.roots[old], n, self.roots[n], proof)

    def test_truncation_and_forgery_rejected(self):
        proof = merkle.consistency_proof(6, self.leaves[:10])
        with self.assertRaises(ValueError):
            merkle.verify_consistency(
                6, self.roots[6], 10, self.roots[10], proof[:-1])
        forged = proof[:]
        forged[0] = bytes(32)
        with self.assertRaises(ValueError):
            merkle.verify_consistency(
                6, self.roots[6], 10, self.roots[10], forged)

    def test_empty_path_rejected(self):
        with self.assertRaises(ValueError):
            merkle.verify_consistency(
                2, self.roots[2], 4, self.roots[4], [])

    def test_rfc9162_example_inclusion(self):
        d = [merkle.hash_leaf(b"d%d" % i) for i in range(7)]
        h = hashlib.sha256
        b = h(b"\x00d1").digest()
        hh = h(b"\x01" + h(b"\x00d2").digest()
               + h(b"\x00d3").digest()).digest()
        l = h(b"\x01"
              + h(b"\x01" + h(b"\x00d4").digest()
                  + h(b"\x00d5").digest()).digest()
              + h(b"\x00d6").digest()).digest()
        self.assertEqual(merkle.inclusion_proof(d, 0), [b, hh, l])


class CanonicalMessage(unittest.TestCase):
    def test_layout_and_ascii_rules(self):
        msg = canonical.encode_message("log-1", b"\x02" * 32, 9, 42,
                                       b"\x03" * 32)
        self.assertEqual(msg[:16], canonical.MAGIC)
        self.assertEqual(len(msg), 16 + 2 + 5 + 32 + 8 + 8 + 32)
        with self.assertRaises(ValueError):
            canonical.encode_message("log-©", b"\x02" * 32, 1, 0,
                                     b"\x03" * 32)


if __name__ == "__main__":
    unittest.main()
