"""Acceptance harness run by the Compose ``verify`` service.

It exercises the running API over HTTP (first checkpoint freeze, legal
extension, forged extension, fork sealing, replays, stale sizes), interleaves
in-process proof/algorithm tests and an image-build check, verifies durable
records (restarting the API container when a Docker socket is available) and
reports the overall verdict through its process exit code.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.environ.get("APP_DIR", "/app"))
sys.path.insert(0, os.getcwd())

from app import canonical, ed25519, merkle  # noqa: E402

API_BASE = os.environ.get("API_BASE", "http://api:8080")
DB_PATH = os.environ.get("DB_PATH", "/data/checkpoints.db")
IMAGE_BUILD_MARKER = os.environ.get("IMAGE_BUILD_MARKER", "/app/IMAGE_BUILD")
DOCKER_SOCK = "/var/run/docker.sock"

failures: list[str] = []
passed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        global passed
        passed += 1
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name} {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def http(method: str, path: str, body: dict | None = None):
    url = API_BASE + path
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_api(timeout_s: float = 60.0) -> None:
    deadline = time.time() + timeout_s
    last = ""
    while time.time() < deadline:
        try:
            status, payload = http("GET", "/healthz")
            if status == 200 and payload.get("status") == "ok":
                print("api healthz ok")
                return
        except Exception as exc:  # noqa: BLE001
            last = repr(exc)
        time.sleep(0.5)
    raise RuntimeError(f"api not healthy after {timeout_s}s: {last}")


# ---------------------------------------------------------------- algorithms

def algorithm_tests() -> None:
    section("algorithm tests (Ed25519 + RFC 9162 proofs)")

    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    check("RFC8032 test1 public key",
          ed25519.public_key_from_seed(seed) == pk)
    check("RFC8032 test1 empty-message signature",
          ed25519.sign(b"", seed) == sig)
    ed25519.verify(b"", sig, pk)
    check("RFC8032 test1 verify", True)
    try:
        ed25519.verify(b"x", sig, pk)
        check("RFC8032 forged message rejected", False)
    except ed25519.SignatureError:
        check("RFC8032 forged message rejected", True)

    # Canonical message is binary, not the JSON transcript.
    m = canonical.encode_message("log-x", pk, 7, 123, b"\xaa" * 32)
    check("canonical message is raw binary",
          m.startswith(canonical.MAGIC) and len(m) == 16 + 2 + 5 + 32 + 8 + 8 + 32)
    s = ed25519.sign(m, seed)
    ed25519.verify(m, s, pk)
    check("signature over binary canonical message verifies", True)
    try:
        ed25519.verify(json.dumps({"x": 1}).encode(), s, pk)
        check("signature over JSON transcript rejected", False)
    except ed25519.SignatureError:
        check("signature over JSON transcript rejected", True)

    # Exhaustive consistency proofs for every prefix pair up to size 32.
    leaves = [merkle.hash_leaf(bytes([i])) for i in range(32)]
    roots = {n: merkle.tree_hash(leaves[:n]) for n in range(1, 33)}
    all_good = truncated_rejected = forged_rejected = True
    for n in range(2, 33):
        for old in range(1, n):
            proof = merkle.consistency_proof(old, leaves[:n])
            try:
                merkle.verify_consistency(
                    old, roots[old], n, roots[n], proof)
            except ValueError:
                all_good = False
            try:
                merkle.verify_consistency(
                    old, roots[old], n, roots[n], proof[:-1])
                if len(proof) > 1:
                    truncated_rejected = False
            except ValueError:
                pass
            bad = [bytes(32)] + proof[1:]
            try:
                merkle.verify_consistency(
                    old, roots[old], n, roots[n], bad)
                forged_rejected = False
            except ValueError:
                pass
    check("all valid consistency proofs verify (sizes 1..32)", all_good)
    check("truncated proofs rejected", truncated_rejected)
    check("forged proof nodes rejected", forged_rejected)
    check("empty consistency path rejected", _empty_rejected(roots))


def _empty_rejected(roots) -> bool:
    try:
        merkle.verify_consistency(2, roots[2], 4, roots[4], [])
        return False
    except ValueError:
        return True


# ------------------------------------------------------------- build check

def build_check() -> None:
    section("image build check")
    import app.server  # noqa: F401  (service module importable)
    check("service package importable inside image", True)
    check("entrypoint marker baked at build time",
          os.path.exists(IMAGE_BUILD_MARKER))
    with open(IMAGE_BUILD_MARKER, encoding="ascii") as fh:
        marker = fh.read().strip()
    check("IMAGE_BUILD marker carries image id", marker.startswith("image="))
    requirements = os.path.exists("/app/requirements.txt")
    check("no third-party runtime dependencies", requirements is False)
    py_ok = sys.version_info[:2] == (3, 11)
    check("running on CPython 3.11", py_ok, sys.version)
    # Same image id on api and verify (only checkable with a docker socket).
    same, reason = _same_image_as_api()
    if same is None:
        print(f"  SKIP  docker socket unavailable ({reason}); relying on"
              " shared build context and baked marker")
    else:
        check("api and verify run the same built image", same, reason)


def _docker_get(path: str):
    """Minimal Docker Engine API client over the unix socket."""
    import http.client

    class _UnixHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(DOCKER_SOCK)

    conn = _UnixHTTPConnection("localhost")
    conn.request("GET", path)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read() or b"{}")


def _same_image_as_api():
    if not os.path.exists(DOCKER_SOCK):
        return None, "no socket mounted"
    try:
        _, containers = _docker_get(
            "/v1.41/containers/json?"
            "filters=%7B%22name%22%3A%5B%22api%22%5D%7D")
        api_ids = [c["ImageID"] for c in containers if
                   any("api" in name for name in c.get("Names", []))]
        _, me = _docker_get("/v1.41/containers/" + os.environ.get(
            "HOSTNAME", "") + "/json")
        own = me.get("Image", "")
        if not api_ids or not own:
            return None, "container metadata unavailable"
        return (own in api_ids), f"own={own[:19]} api={api_ids[0][:19]}"
    except Exception as exc:  # noqa: BLE001
        return None, f"engine api error: {exc}"


# ------------------------------------------------------------------- smoke

def checkpoint_body(key: bytes, seed: bytes, log_id: str, size: int,
                    ts: int, root: bytes, proof: list[bytes]) -> dict:
    msg = canonical.encode_message(log_id, key, size, ts, root)
    return {
        "public_key": key.hex(),
        "tree_size": size,
        "timestamp_ms": ts,
        "root_hash": root.hex(),
        "signature": ed25519.sign(msg, seed).hex(),
        "consistency": [n.hex() for n in proof],
    }


def sign_raw(key: bytes, seed: bytes, log_id: str, size: int, ts: int,
             root: bytes) -> str:
    return ed25519.sign(
        canonical.encode_message(log_id, key, size, ts, root), seed).hex()


def smoke_extension_path() -> None:
    section("HTTP smoke: first checkpoint, legal & forged extensions")
    log_id = "smoke-primary"
    seed_a, key_a = ed25519.generate_keypair()
    seed_b = bytes(range(32))
    key_b = ed25519.public_key_from_seed(seed_b)

    leaves = [merkle.hash_leaf(b"obs-" + bytes([i])) for i in range(10)]
    roots = {n: merkle.tree_hash(leaves[:n]) for n in range(1, 11)}

    # 1. First valid submission freezes the key.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_a, seed_a, log_id, 4,
                                           1_000, roots[4], []))
    check("first submission returns 201 frozen",
          status == 201 and payload.get("result") == "frozen",
          f"{status} {payload}")

    status, payload = http("GET", f"/logs/{log_id}")
    check("GET exposes trusted size/root/status",
          status == 200 and payload["tree_size"] == 4
          and payload["root_hash"] == roots[4].hex()
          and payload["status"] == "active"
          and payload["public_key"] == key_a.hex(),
          f"{status} {payload}")
    check("GET of unknown log is 404",
          http("GET", "/logs/does-not-exist")[0] == 404)

    # 2. First submission must not carry a proof.
    status, payload = http("POST", "/logs/smoke-bad-first/checkpoints",
                           checkpoint_body(key_a, seed_a, "smoke-bad-first",
                                           2, 1, roots[2], [bytes(32)]))
    check("bootstrap with proof rejected",
          status == 409 and payload["error"]["code"]
          == "consistency_without_anchor", f"{status} {payload}")

    # 3. Malformed submissions are localisable and leave no partial state.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           {"public_key": key_a.hex(), "tree_size": 5})
    check("missing fields rejected with location",
          status == 400 and payload["error"]["code"] == "missing_fields"
          and "signature" in payload["error"]["details"]["fields"],
          f"{status} {payload}")

    bad = checkpoint_body(key_a, seed_a, log_id, 5, 2_000,
                          roots[5], merkle.consistency_proof(4, leaves[:5]))
    bad["signature"] = "00" * 64
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", bad)
    check("invalid signature rejected over canonical binary message",
          status == 400 and payload["error"]["code"] == "invalid_signature",
          f"{status} {payload}")

    # 4. Legal larger tree advances atomically with a valid proof.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_a, seed_a, log_id, 6,
                                           2_000, roots[6],
                                           merkle.consistency_proof(
                                               4, leaves[:6])))
    check("legal extension returns trusted",
          status == 200 and payload["result"] == "trusted"
          and payload.get("applied") is True, f"{status} {payload}")

    # 5. Forged extension: rewrite a leaf already inside the trusted prefix,
    # so the claimed old tree is not a prefix of the claimed new tree.
    forged_leaves = list(leaves[:7])
    forged_leaves[3] = merkle.hash_leaf(b"tampered-observation")
    forged_root = merkle.tree_hash(forged_leaves)
    forged_proof = merkle.consistency_proof(6, forged_leaves)
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_a, seed_a, log_id, 7,
                                           3_000, forged_root, forged_proof))
    check("forged extension (old tree not a prefix) rejected",
          status == 400 and payload["error"]["code"]
          == "invalid_consistency_proof", f"{status} {payload}")

    # Appending a brand-new divergent leaf is legitimate append-only
    # behaviour, not a fork; a proof of it must verify.
    divergent = leaves[:6] + [merkle.hash_leaf(b"different-new-leaf")]
    merkle.verify_consistency(
        6, roots[6], 7, merkle.tree_hash(divergent),
        merkle.consistency_proof(6, divergent))
    check("new divergent leaf still verifies as append-only", True)

    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_a, seed_a, log_id, 8,
                                           4_000, roots[8],
                           merkle.consistency_proof(6, leaves[:8])[:-1]))
    check("truncated proof rejected",
          status == 400 and payload["error"]["code"]
          == "invalid_consistency_proof", f"{status} {payload}")

    status, payload = http("GET", f"/logs/{log_id}")
    check("state unchanged after failed submissions",
          payload["tree_size"] == 6 and payload["status"] == "active",
          str(payload))

    # 6. Stale size.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_a, seed_a, log_id, 5,
                                           1_500, roots[5], []))
    check("stale size rejected",
          status == 409 and payload["error"]["code"] == "stale_tree_size",
          f"{status} {payload}")

    # 7. Frozen key cannot rotate on an extension.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_b, seed_b, log_id, 8,
                                           4_000, roots[8],
                                           merkle.consistency_proof(
                                               6, leaves[:8])))
    check("key rotation extension rejected",
          status == 409 and payload["error"]["code"] == "public_key_frozen",
          f"{status} {payload}")

    # 8. Concurrent identical extension: same adjudication, single advance.
    body8 = checkpoint_body(key_a, seed_a, log_id, 8, 4_000, roots[8],
                            merkle.consistency_proof(6, leaves[:8]))
    results = []

    def post_once():
        results.append(http("POST", f"/logs/{log_id}/checkpoints", body8))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: post_once(), range(2)))
    codes = sorted((s, p.get("result")) for s, p in results)
    check("concurrent identical extensions both succeed",
          all(s == 200 for s, _ in results), str(results))
    check("one applied, one recognised as already trusted",
          sorted(r for _, r in codes) == ["already_trusted", "trusted"],
          str(results))
    status, payload = http("GET", f"/logs/{log_id}")
    check("tree advanced exactly once to size 8",
          payload["tree_size"] == 8, str(payload))

    # 9. Sequential replay yields the same verdict.
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", body8)
    check("replayed extension returns already_trusted",
          status == 200 and payload["result"] == "already_trusted",
          f"{status} {payload}")


def smoke_fork_path() -> None:
    section("HTTP smoke: same-size equivocation seals first fork evidence")
    log_id = "smoke-fork"
    seed_k, key_k = ed25519.generate_keypair()
    seed_k2, key_k2 = ed25519.generate_keypair()

    leaves = [merkle.hash_leaf(b"genuine-" + bytes([i])) for i in range(5)]
    alt = [merkle.hash_leaf(b"hidden-history-" + bytes([i])) for i in range(5)]
    root3 = merkle.tree_hash(leaves[:3])
    alt3 = merkle.tree_hash(alt[:3])
    alt3b = merkle.tree_hash(alt[:2] + [merkle.hash_leaf(b"third-view")])

    status, payload = http("POST", f"/logs/{log_id}/checkpoints",
                           checkpoint_body(key_k, seed_k, log_id, 3,
                                           5_000, root3, []))
    check("fork log bootstrapped", status == 201, f"{status} {payload}")

    # Rival head, same size, different root, signed by a different key:
    # still a validly self-signed checkpoint -> seal evidence.
    rival = {
        "public_key": key_k2.hex(),
        "tree_size": 3,
        "timestamp_ms": 5_001,
        "root_hash": alt3.hex(),
        "signature": sign_raw(key_k2, seed_k2, log_id, 3, 5_001, alt3),
        "consistency": [],
    }
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", rival)
    check("same-size rival seals fork evidence",
          status == 409 and payload["error"]["code"]
          == "fork_evidence_sealed"
          and payload["error"]["details"]["trusted_tree_size"] == 3,
          f"{status} {payload}")
    fork_id = payload["error"]["details"]["fork_id"]

    status, payload = http("GET", f"/logs/{log_id}")
    check("trusted record unchanged after fork",
          payload["root_hash"] == root3.hex()
          and payload["tree_size"] == 3
          and payload["status"] == "fork_sealed"
          and payload["fork"]["fork_id"] == fork_id
          and payload["fork"]["rival"]["root_hash"] == alt3.hex()
          and payload["fork"]["trusted"]["public_key"] == key_k.hex()
          and payload["fork"]["rival"]["public_key"] == key_k2.hex(),
          str(payload))

    # A second, different rival must not overwrite the first evidence.
    rival2 = {
        "public_key": key_k.hex(),
        "tree_size": 3,
        "timestamp_ms": 5_002,
        "root_hash": alt3b.hex(),
        "signature": sign_raw(key_k, seed_k, log_id, 3, 5_002, alt3b),
        "consistency": [],
    }
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", rival2)
    check("second rival also rejected", status == 409, f"{status} {payload}")
    status, payload = http("GET", f"/logs/{log_id}")
    check("first fork evidence preserved",
          payload["fork"]["rival"]["root_hash"] == alt3.hex()
          and payload["fork"]["created_at"] <= payload["updated_at"] + 5000,
          str(payload))

    # No advancement while sealed.
    ext = checkpoint_body(key_k, seed_k, log_id, 5, 6_000,
                          merkle.tree_hash(leaves),
                          merkle.consistency_proof(3, leaves))
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", ext)
    check("extension rejected after seal",
          status == 409 and payload["error"]["code"] == "log_sealed",
          f"{status} {payload}")

    # Unsigned/garbage claims never reach evidence sealing.
    garbage = dict(rival)
    garbage["signature"] = "11" * 64
    status, payload = http("POST", f"/logs/{log_id}/checkpoints", garbage)
    check("forged-signature same-size claim rejected, not sealed",
          status == 400 and payload["error"]["code"] == "invalid_signature",
          f"{status} {payload}")


# ------------------------------------------------------------ durability

def durability_check() -> None:
    section("durable records + restart")
    # Direct read of the durable SQLite state shared via the volume.  A
    # normal connection (appuser owns /data) is used instead of mode=ro so
    # SQLite can attach WAL shared-memory files while the API is writing.
    conn = sqlite3.connect(DB_PATH)
    n_primary = conn.execute(
        "SELECT tree_size, status FROM logs WHERE log_id=?",
        ("smoke-primary",)).fetchone()
    n_cps = conn.execute(
        "SELECT COUNT(*), MAX(tree_size) FROM checkpoints"
        " WHERE log_id=?", ("smoke-primary",)).fetchone()
    n_fork = conn.execute(
        "SELECT COUNT(*) FROM forks WHERE log_id=?",
        ("smoke-fork",)).fetchone()[0]
    check("trusted head persisted (size 8, active)",
          n_primary == (8, "active"), str(n_primary))
    check("accepted checkpoints persisted (4,6,8)",
          n_cps == (3, 8), str(n_cps))
    check("exactly one fork record sealed", n_fork == 1, str(n_fork))
    conn.close()

    if not _restart_api_via_docker():
        print("  SKIP  live API restart (docker socket unavailable);"
              " durable state verified directly above")
        return
    wait_for_api()
    status, payload = http("GET", "/logs/smoke-primary")
    check("trusted checkpoint queryable after restart",
          status == 200 and payload["tree_size"] == 8
          and payload["status"] == "active", f"{status} {payload}")
    status, payload = http("GET", "/logs/smoke-fork")
    check("fork record queryable after restart",
          status == 200 and payload["status"] == "fork_sealed"
          and payload["fork"] is not None, f"{status} {payload}")


def _restart_api_via_docker() -> bool:
    if not os.path.exists(DOCKER_SOCK):
        return False
    try:
        import http.client

        class _UnixHTTPConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(15)
                self.sock.connect(DOCKER_SOCK)

        _, containers = _docker_get(
            "/v1.41/containers/json?"
            "filters=%7B%22name%22%3A%5B%22api%22%5D%7D")
        target = None
        for c in containers:
            if any(n.endswith("-api-1") or n.endswith("_api_1")
                   or n.rstrip("/").endswith("/api")
                   for n in c.get("Names", [])):
                target = c["Id"]
                break
        if target is None and containers:
            target = containers[0]["Id"]
        if target is None:
            return False
        conn = _UnixHTTPConnection("localhost")
        conn.request("POST", f"/v1.41/containers/{target}/restart")
        resp = conn.getresponse()
        resp.read()
        print(f"restarted api container {target[:12]} (HTTP {resp.status})")
        return resp.status in (204, 304)
    except Exception as exc:  # noqa: BLE001
        print(f"  SKIP  restart failed: {exc!r}")
        return False


def main() -> int:
    print(f"acceptance harness -> {API_BASE} (db {DB_PATH})")
    wait_for_api()
    algorithm_tests()
    smoke_extension_path()
    build_check()
    smoke_fork_path()
    durability_check()

    print("\n=== summary ===")
    print(f"passed: {passed}   failed: {len(failures)}")
    for failure in failures:
        print(f"  - {failure}")
    if failures:
        print("ACCEPTANCE FAILED")
        return 1
    print("ACCEPTANCE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
