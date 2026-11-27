"""Offline tests for bin/proof-verify.py (no network, throwaway Ed25519 key generated at run time).

Signing uses the repo's own pure-Python Ed25519 primitives (RFC 8032), checked against the RFC test vector.
"""
import base64
import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_spec = importlib.util.spec_from_file_location("proof_verify", os.path.join(ROOT, "bin", "proof-verify.py"))
pv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pv)

KID = "test-key-1"
DOMAIN = "example.com"
NOW = datetime(2026, 11, 25, tzinfo=timezone.utc)
TOKEN = "318926611b90a11d9392bc21"


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _compress(pt):
    x, y, z, _ = pt
    zi = pow(z, pv._ED_P - 2, pv._ED_P)
    x, y = x * zi % pv._ED_P, y * zi % pv._ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    return a, h[32:], _compress(pv._ed_point_mul(a, pv._ED_B))


def sign(seed, msg):
    a, prefix, pub = keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % pv._ED_L
    big_r = _compress(pv._ed_point_mul(r, pv._ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % pv._ED_L
    return big_r + ((r + k * a) % pv._ED_L).to_bytes(32, "little")


def new_key():
    seed = os.urandom(32)
    return seed, b64u(keypair(seed)[2])


def envelope(payload, seed, kid=KID):
    digest = hashlib.sha256(pv.canonical_json(payload).encode()).hexdigest()
    value = b64u(sign(seed, f"proof-vc-v2\n{digest}".encode()))
    return {"protocol": "proof-vc-v2", "payload": payload, "digest": digest,
            "signature": {"alg": "Ed25519", "kid": kid, "jwksUrl": "https://attacker.invalid/jwks.json", "value": value}}


def certificate(seed, payload_over=None, **top):
    payload = {"protocol": "proof-vc-v2", "domain": DOMAIN, "tier": "snapshot", "score": 92, "certified": True,
               "auditedAt": "2026-11-24T00:00:00.000Z", "expiresAt": "2026-12-01T00:00:00.000Z"}
    payload.update(payload_over or {})
    cert = {"status": "verified", "domain": payload["domain"], "score": payload["score"],
            "certified": payload["certified"], "attestation": envelope(payload, seed)}
    cert.update(top)
    return cert


def no_network(*_a, **_k):
    raise AssertionError("network must not be used")


class Ed25519Primitive(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(keypair(seed)[2], pub)
        self.assertEqual(sign(seed, b""), sig)
        self.assertTrue(pv.ed25519_verify_pure(pub, sig, b""))
        self.assertFalse(pv.ed25519_verify_pure(pub, sig, b"x"))


class Verification(unittest.TestCase):
    def run_both(self, fn):
        """Run with the cryptography package if present AND with the pure-Python fallback."""
        for force_pure in (True, False):
            with self.subTest(force_pure=force_pure):
                fn(force_pure)

    def evaluate(self, cert, pinned, force_pure=True, **kw):
        kw.setdefault("now", NOW)
        kw.setdefault("fetch", no_network)
        return pv.evaluate_certificate(cert, DOMAIN, pinned_keys=pinned, force_pure=force_pure, **kw)

    def test_pinned_list(self):
        self.assertEqual(pv.PINNED_KEYS, [{"kid": "proof-root-2026-11-24", "x": "DVEMQfdW69Z5iQxjWLO3vZTa1bTeYf7SJ6AVsiew4LA"}])

    def test_valid_signature_passes_offline(self):
        def check(fp):
            seed, x = new_key()
            r = self.evaluate(certificate(seed), [{"kid": KID, "x": x}], fp)
            self.assertEqual((r["status"], r["ok"], r["signature"]["key_source"]), ("CERTIFIED", True, "pinned"))
        self.run_both(check)

    def test_score_below_min_is_audited(self):
        seed, x = new_key()
        r = self.evaluate(certificate(seed), [{"kid": KID, "x": x}], min_score=95)
        self.assertEqual((r["status"], r["ok"]), ("AUDITED", False))

    def test_tampered_payload_fails(self):
        def check(fp):
            seed, x = new_key()
            cert = certificate(seed)
            cert["attestation"]["payload"]["score"] = 100
            cert["score"] = 100
            r = self.evaluate(cert, [{"kid": KID, "x": x}], fp)
            self.assertEqual((r["ok"], r["status"], r["reason"]), (False, "UNVERIFIED", "digest_mismatch"))
            # attacker recomputes the digest but cannot re-sign
            cert["attestation"]["digest"] = hashlib.sha256(pv.canonical_json(cert["attestation"]["payload"]).encode()).hexdigest()
            r = self.evaluate(cert, [{"kid": KID, "x": x}], fp)
            self.assertEqual((r["ok"], r["reason"]), (False, "invalid_signature"))
        self.run_both(check)

    def test_missing_or_malformed_attestation_fails(self):
        seed, x = new_key()
        pinned = [{"kid": KID, "x": x}]
        mutations = [
            lambda c: c.pop("attestation"),
            lambda c: c["attestation"].pop("signature"),
            lambda c: c["attestation"]["signature"].update(alg="HS256"),
            lambda c: c["attestation"]["signature"].pop("kid"),
            lambda c: c["attestation"]["signature"].update(value=""),
            lambda c: c.update(attestation="nope"),
        ]
        for mutate in mutations:
            cert = certificate(seed)
            mutate(cert)
            r = self.evaluate(cert, pinned)
            self.assertEqual((r["ok"], r["status"]), (False, "UNVERIFIED"))
        cert = certificate(seed)
        del cert["attestation"]
        self.assertEqual(self.evaluate(cert, pinned)["reason"], "no_ed25519_attestation")

    def test_unknown_kid_fails_without_fallback_or_network(self):
        seed, x = new_key()
        cert = certificate(seed)
        cert["attestation"]["signature"]["kid"] = "some-other-kid"
        r = self.evaluate(cert, [{"kid": KID, "x": x}])
        self.assertEqual((r["ok"], r["reason"]), (False, "unknown_kid"))

    def test_wrong_key_fails(self):
        def check(fp):
            signer, _ = new_key()
            _, other_x = new_key()
            r = self.evaluate(certificate(signer), [{"kid": KID, "x": other_x}], fp)
            self.assertEqual((r["ok"], r["reason"]), (False, "invalid_signature"))
        self.run_both(check)

    def test_opt_in_jwks_is_flagged_unpinned_and_https_only(self):
        seed, x = new_key()
        calls = []

        def fetch(url, accept):
            calls.append(url)
            return 200, {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": x}]}

        r = self.evaluate(certificate(seed), [], jwks_url="https://keys.example/jwks.json", fetch=fetch)
        self.assertEqual((r["ok"], r["signature"]["key_source"]), (True, "unpinned-jwks"))
        self.assertEqual(calls, ["https://keys.example/jwks.json"])
        r = self.evaluate(certificate(seed), [], jwks_url="http://keys.example/jwks.json", fetch=fetch)
        self.assertEqual((r["ok"], r["reason"]), (False, "jwks_url_must_be_https"))
        self.assertEqual(len(calls), 1)

    def test_jwks_url_inside_attestation_is_never_fetched(self):
        seed, x = new_key()
        cert = certificate(seed)
        cert["attestation"]["signature"]["kid"] = "unpinned"
        r = self.evaluate(cert, [{"kid": KID, "x": x}])  # fetch=no_network raises if touched
        self.assertFalse(r["ok"])

    def test_binding_to_domain_unsigned_fields_and_expiry(self):
        seed, x = new_key()
        pinned = [{"kid": KID, "x": x}]
        self.assertEqual(pv.evaluate_certificate(certificate(seed), "other.com", pinned_keys=pinned, now=NOW, fetch=no_network)["reason"], "payload_domain_mismatch")
        self.assertEqual(self.evaluate(certificate(seed, score=100), pinned)["reason"], "unsigned_score_mismatch")
        self.assertEqual(self.evaluate(certificate(seed, {"certified": False}, certified=True), pinned)["reason"], "unsigned_certified_mismatch")
        late = self.evaluate(certificate(seed), pinned, now=datetime(2026, 12, 2, tzinfo=timezone.utc))
        self.assertEqual((late["ok"], late["reason"]), (False, "certificate_expired"))
        self.assertFalse(self.evaluate(certificate(seed, {"expiresAt": "garbage"}), pinned)["ok"])


    def test_protocol_score_timestamp_and_claim_root_invariants(self):
        seed, x = new_key()
        pinned = [{"kid": KID, "x": x}]
        cases = []
        c = certificate(seed); c["attestation"]["protocol"] = "proof-v1"; cases.append(c)
        c = certificate(seed); c["attestation"]["payload"]["protocol"] = "proof-v1"; cases.append(c)
        c = certificate(seed, {"score": 101}); cases.append(c)
        c = certificate(seed, {"claimRoot": "not-a-sha256"}); cases.append(c)
        c = certificate(seed, {"auditedAt": "invalid"}); cases.append(c)
        for cert in cases:
            payload = cert["attestation"]["payload"]
            digest = hashlib.sha256(pv.canonical_json(payload).encode()).hexdigest()
            cert["attestation"]["digest"] = digest
            cert["attestation"]["signature"]["value"] = b64u(sign(seed, f"proof-vc-v2\\n{digest}".encode()))
            r = self.evaluate(cert, pinned)
            self.assertEqual(r["status"], "UNVERIFIED")


class Dns(unittest.TestCase):
    CH = {"host": f"_proof-verify.{DOMAIN}", "value": f"proof-v2=challenge:{TOKEN};jwks=https://x/j;kid=k"}

    @staticmethod
    def doh(body, status=200):
        return lambda url, accept: (status, body)

    def test_compares_token_not_prefix(self):
        ok = {"Status": 0, "Answer": [{"type": 16, "data": f'"proof-v2=challenge:{TOKEN};kid=k"'}]}
        self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, self.doh(ok))[0], "verified")
        split = {"Status": 0, "Answer": [{"type": 16, "data": f'"proof-v2=challenge:{TOKEN[:10]}" "{TOKEN[10:]};kid=k"'}]}
        self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, self.doh(split))[0], "verified")
        wrong = {"Status": 0, "Answer": [{"type": 16, "data": '"proof-v2=challenge:000000000000000000000000"'}]}
        self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, self.doh(wrong))[0], "not_verified")
        prefix = {"Status": 0, "Answer": [{"type": 16, "data": '"proof-v2="'}]}
        self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, self.doh(prefix))[0], "not_verified")
        self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, self.doh({"Status": 3}))[0], "not_verified")

    def test_not_checked_when_it_cannot_be_performed(self):
        for resp in (self.doh(None, 500), self.doh("<html>", 403), self.doh({"Status": 2})):
            self.assertEqual(pv.check_dns_challenge(DOMAIN, self.CH, resp)[0], "not_checked")
        self.assertEqual(pv.check_dns_challenge(DOMAIN, None, no_network)[0], "not_checked")
        bad_host = {"host": "_proof-verify.evil.com", "value": self.CH["value"]}
        self.assertEqual(pv.check_dns_challenge(DOMAIN, bad_host, no_network)[0], "not_checked")


class Cli(unittest.TestCase):
    script = os.path.join(ROOT, "bin", "proof-verify.py")

    def run_cli(self, *args, env=None):
        e = {**os.environ, **(env or {})}
        return subprocess.run([sys.executable, "-I", "-B", self.script, *args], capture_output=True, text=True, env=e).returncode

    def test_exit_codes_without_network(self):
        self.assertEqual(self.run_cli("--help"), 0)
        self.assertEqual(self.run_cli("not a domain"), 2)
        self.assertEqual(self.run_cli("--bogus", "example.com"), 2)
        self.assertEqual(self.run_cli("example.com", env={"PROOF_MIN_SCORE": "abc"}), 2)

    def test_parse_args(self):
        self.assertEqual(pv.parse_args(["a.com", "--jwks-url", "https://k/j"])[:2], ("a.com", "https://k/j"))
        self.assertIsNotNone(pv.parse_args(["a.com", "--jwks-url"])[2])




class AuditGuidance(unittest.TestCase):
    def test_guidance_points_to_english_audit_box_and_rerun_command(self):
        spec = importlib.util.spec_from_file_location("pv", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "proof-verify.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = "\n".join(mod.audit_guidance("mon-site.example"))
        self.assertIn("https://www.proofxray.com/en#audit-gratuit", text)
        self.assertIn("npx proof-verify mon-site.example", text)
        self.assertNotIn("proofxray.com/#audit-gratuit", text)

if __name__ == "__main__":
    unittest.main()
