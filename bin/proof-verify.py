#!/usr/bin/env python3
"""
proof-verify: Standalone Python 3 CLI verifier for the Autonomous International Enterprise (EAI) Standard & PROOF-VC v2.
Fetches https://www.proofxray.com/api/public/v1/certificate (online), then verifies the SHA-256 JCS digest and the
Ed25519 signature against a PINNED public key (no network needed for that step) with zero external dependencies
(RFC 8032 pure-Python fallback). Fails closed: a certificate without a valid signature is never accepted.
Emits GitHub Actions outputs when GITHUB_OUTPUT is set.
Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
"""

import base64
from decimal import Decimal
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request

DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


VERSION = "1.0.2"
AUDIT_URL = "https://www.proofxray.com/en#audit-gratuit"


def audit_guidance(domain):
    """What a developer sees when a domain has no certificate yet: one link and one instruction."""
    return [
        "Run a free X-Ray audit of your homepage (about 10 s, no sign-up): paste your site in the box at",
        f"  {AUDIT_URL}",
        f"Then run again: npx proof-verify {domain}",
    ]

# Trusted public keys. To trust a new key, add an entry here (and in PINNED_KEYS of lib/verify.js) and ship a
# new release. Values come from https://www.proofxray.com/.well-known/jwks.json (OKP / Ed25519, base64url `x`).
PINNED_KEYS = [
    {"kid": "proof-root-2026-11-24", "x": "DVEMQfdW69Z5iQxjWLO3vZTa1bTeYf7SJ6AVsiew4LA"},
]

SIGNATURE_FAIL = "FAIL: no valid Ed25519 signature"
UNPINNED_WARNING = (
    "UNPINNED KEY (insecure): the public key is fetched from the URL you opted into, "
    "not from the pinned list."
)


def print_help():
    print(
        "\nPROOF X-Ray — Autonomous Enterprise Standard CLI Verifier (EAI v1.0 / PROOF-VC v2)\n"
        "Usage:\n"
        "  python3 bin/proof-verify.py <domain> [--jwks-url <url>]\n\n"
        "Options:\n"
        "  --jwks-url <url>  INSECURE opt-in (key rotation only): look up a key id that is not in the pinned\n"
        "                    list in this JWKS (env: PROOF_JWKS_URL). Prints an UNPINNED KEY warning.\n"
        "  PROOF_MIN_SCORE   Minimum score to be reported CERTIFIED (default 80).\n\n"
        "Examples:\n"
        "  python3 bin/proof-verify.py proofxray.com\n"
        "  python3 bin/proof-verify.py example.com\n"
    )
    sys.exit(0)


def _jcs_number(val) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        # JSON numbers are IEEE-754 binary64 in ECMAScript. Python parses them as
        # arbitrary-precision integers; round to binary64 before JCS formatting.
        try:
            val = float(val)
        except OverflowError as exc:
            raise ValueError("non_finite_number") from exc
    if not isinstance(val, float) or not math.isfinite(val):
        raise ValueError("non_finite_number")
    if val == 0.0:
        return "0"
    sign = "-" if val < 0 else ""
    av = abs(val)
    d = Decimal(repr(av)).normalize()
    dt = d.as_tuple()
    digits = "".join(str(x) for x in dt.digits)
    exp10 = dt.exponent + len(digits) - 1
    if -6 <= exp10 < 21:
        k = len(digits)
        n = exp10 + 1
        if k <= n:
            return sign + digits + ("0" * (n - k))
        if n > 0:
            return sign + digits[:n] + "." + digits[n:]
        return sign + "0." + ("0" * (-n)) + digits
    mant = digits if len(digits) == 1 else (digits[0] + "." + digits[1:])
    es = "+" if exp10 >= 0 else "-"
    return f"{sign}{mant}e{es}{abs(exp10)}"


def canonical_json(obj) -> str:
    """RFC 8785 (JCS) deterministic JSON serializer matching ECMAScript / Node.js canonicalJson:
    - Object keys sorted lexicographically by UTF-16 code units (UTF-16BE byte order)
    - Numbers rounded to binary64 and formatted per ECMAScript 7.1.12.1
      (1.0 -> '1', -0.0 -> '0', non-finite rejected)"""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _jcs_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: str(kv[0]).encode("utf-16-be"))
        return "{" + ",".join(f"{json.dumps(str(k), ensure_ascii=False)}:{canonical_json(v)}" for k, v in items) + "}"
    raise TypeError(f"Unsupported JCS type: {type(obj).__name__}")


CLAIM_EMPTY_ROOT_LABEL = "proof-claims-empty-v2"


def compute_claim_root_from_leaves(claim_leaves):
    """Recompute the Merkle claimRoot from published claimLeaves:
    - each leaf is { canonical: str, leafHash: hex64 }, with leafHash = SHA-256(0x00 || UTF-8(canonical))
    - internal nodes are SHA-256(0x01 || leftBytes || rightBytes), odd end-of-level node paired with itself
    - empty leaf list hashes CLAIM_EMPTY_ROOT_LABEL
    Returns (True, claim_root, leaves_count) or (False, reason, 0)."""
    if not isinstance(claim_leaves, list):
        return False, "invalid_claim_leaves", 0
    if len(claim_leaves) == 0:
        empty_root = hashlib.sha256(CLAIM_EMPTY_ROOT_LABEL.encode("utf-8")).hexdigest()
        return True, empty_root, 0
    level = []
    for leaf in claim_leaves:
        if not isinstance(leaf, dict):
            return False, "invalid_claim_leaves", 0
        canonical = leaf.get("canonical")
        leaf_hash = leaf.get("leafHash")
        if not isinstance(canonical, str) or not isinstance(leaf_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", leaf_hash):
            return False, "invalid_claim_leaves", 0
        expected = hashlib.sha256(b"\x00" + canonical.encode("utf-8")).hexdigest()
        if expected != leaf_hash.lower():
            return False, "claim_leaf_hash_mismatch", 0
        level.append(expected)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest())
        level = nxt
    return True, level[0], len(claim_leaves)


def write_github_outputs(status: str, score: str, certified: bool):
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(f"status={status}\n")
        fh.write(f"score={score}\n")
        fh.write(f"certified={'true' if certified else 'false'}\n")


def fetch_json(url: str, accept: str = "application/json, text/plain", redirects: int = 3):
    req = urllib.request.Request(url, headers={"User-Agent": f"proof-verify/{VERSION}", "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            raw = res.read().decode("utf-8", errors="replace")
            try:
                return res.status, json.loads(raw)
            except Exception:
                return res.status, raw
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location") and redirects > 0:
            next_url = urllib.parse.urljoin(url, e.headers.get("Location"))
            return fetch_json(next_url, accept, redirects - 1)
        return e.code, None
    except Exception:
        return 500, None


# ── Pure-Python RFC 8032 Ed25519 verifier (zero external dependencies) ─────────
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * _ED_D * t1 * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_point_mul(s: int, pt):
    acc = (0, 1, 1, 0)
    addend = pt
    while s > 0:
        if s & 1:
            acc = _ed_point_add(acc, addend)
        addend = _ed_point_add(addend, addend)
        s >>= 1
    return acc


def _ed_point_equal(p1, p2) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def _ed_point_decompress(buf: bytes):
    if len(buf) != 32:
        return None
    y = int.from_bytes(buf, "little") & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    sign = buf[31] >> 7
    u = (y * y - 1) % _ED_P
    v = (_ED_D * y * y + 1) % _ED_P
    x2 = (u * pow(v, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        if sign == 1:
            return None
        x = 0
    else:
        x = pow(x2, (_ED_P + 3) // 8, _ED_P)
        if (x * x - x2) % _ED_P != 0:
            x = (x * _ED_I) % _ED_P
        if (x * x - x2) % _ED_P != 0:
            return None
        if (x & 1) != sign:
            x = _ED_P - x
    return (x, y, 1, (x * y) % _ED_P)


def _ed_base_point():
    by = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
    u = (by * by - 1) % _ED_P
    v = (_ED_D * by * by + 1) % _ED_P
    x2 = (u * pow(v, _ED_P - 2, _ED_P)) % _ED_P
    bx = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (bx * bx - x2) % _ED_P != 0:
        bx = (bx * _ED_I) % _ED_P
    if bx & 1:
        bx = _ED_P - bx
    return (bx, by, 1, (bx * by) % _ED_P)


_ED_B = _ed_base_point()


def ed25519_verify_pure(pub_bytes: bytes, sig_bytes: bytes, msg: bytes) -> bool:
    if len(pub_bytes) != 32 or len(sig_bytes) != 64:
        return False
    a_pt = _ed_point_decompress(pub_bytes)
    r_pt = _ed_point_decompress(sig_bytes[:32])
    if a_pt is None or r_pt is None:
        return False
    s_int = int.from_bytes(sig_bytes[32:], "little")
    if s_int >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig_bytes[:32] + pub_bytes + msg).digest(), "little") % _ED_L
    return _ed_point_equal(_ed_point_mul(s_int, _ED_B), _ed_point_add(r_pt, _ed_point_mul(k, a_pt)))


def _b64url_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        return None
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _resolve_key(kid, pinned_keys, jwks_url, fetch):
    for k in pinned_keys:
        if k.get("kid") == kid:
            return k.get("x"), "pinned", None
    if not jwks_url:
        return None, None, "unknown_kid"
    if not str(jwks_url).lower().startswith("https://"):
        return None, None, "jwks_url_must_be_https"
    st, jwks = fetch(jwks_url, "application/json")
    keys = jwks.get("keys") if st == 200 and isinstance(jwks, dict) else None
    for k in keys if isinstance(keys, list) else []:
        if isinstance(k, dict) and k.get("kid") == kid and k.get("kty") == "OKP" and k.get("crv") == "Ed25519" \
                and isinstance(k.get("x"), str):
            return k["x"], "unpinned-jwks", None
    return None, None, "jwks_key_not_found"


def verify_envelope(env, pinned_keys=None, jwks_url=None, fetch=None, force_pure=False):
    """Verify { payload, digest, signature: { alg, kid, value } }.
    Returns (valid, reason, kid, key_source). Never raises; anything unexpected is invalid.
    With a pinned key no network access happens."""
    pinned_keys = PINNED_KEYS if pinned_keys is None else pinned_keys
    fetch = fetch or fetch_json
    try:
        if not isinstance(env, dict):
            return False, "no_ed25519_attestation", None, None
        sig = env.get("signature")
        if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
            return False, "no_ed25519_attestation", None, None
        kid = sig.get("kid")
        if not isinstance(kid, str) or not kid:
            return False, "missing_kid", None, None
        if not isinstance(sig.get("value"), str) or not sig["value"]:
            return False, "missing_signature_value", kid, None
        if not isinstance(env.get("payload"), dict):
            return False, "missing_payload", kid, None
        digest = hashlib.sha256(canonical_json(env["payload"]).encode("utf-8")).hexdigest()
        if digest != env.get("digest"):
            return False, "digest_mismatch", kid, None
        x, source, err = _resolve_key(kid, pinned_keys, jwks_url, fetch)
        if err:
            return False, err, kid, None
        pub_bytes = _b64url_bytes(x)
        sig_bytes = _b64url_bytes(sig["value"])
        if pub_bytes is None or len(pub_bytes) != 32:
            return False, "bad_public_key", kid, None
        if sig_bytes is None or len(sig_bytes) != 64:
            return False, "invalid_signature", kid, None
        message = f"proof-vc-v2\n{digest}".encode("utf-8")
        ok = None
        if not force_pure:
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            except ImportError:
                Ed25519PublicKey = None
            if Ed25519PublicKey is not None:
                try:
                    Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, message)
                    ok = True
                except Exception:
                    ok = False
        if ok is None:
            ok = ed25519_verify_pure(pub_bytes, sig_bytes, message)
        return (True, "ok", kid, source) if ok else (False, "invalid_signature", kid, None)
    except Exception as e:  # fail closed
        return False, f"error: {e}", None, None


def evaluate_certificate(cert, expected_domain, min_score=80, now=None, jwks_url=None, pinned_keys=None,
                         fetch=None, force_pure=False, revoked_kids=None, revoked_scan_ids=None):
    """Decide on a certificate. Everything that decides the outcome comes from the SIGNED payload; unsigned
    top-level fields must agree with it. Returns a dict: status (CERTIFIED | AUDITED | UNVERIFIED), ok, score,
    reason, signature (valid, reason, kid, key_source), payload."""
    valid, reason, kid, source = verify_envelope(
        cert.get("attestation") if isinstance(cert, dict) else None,
        pinned_keys=pinned_keys, jwks_url=jwks_url, fetch=fetch, force_pure=force_pure,
    )
    signature = {"valid": valid, "reason": reason, "kid": kid, "key_source": source}

    def reject(why):
        return {"status": "UNVERIFIED", "ok": False, "score": None, "reason": why, "signature": signature,
                "payload": None}

    if not valid:
        return reject(reason)
    envelope = cert.get("attestation") if isinstance(cert, dict) else None
    if not isinstance(envelope, dict) or envelope.get("protocol") != "proof-vc-v2":
        return reject("invalid_attestation_protocol")
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or payload.get("protocol") != "proof-vc-v2":
        return reject("invalid_payload_protocol")
    if cert.get("status") == "revoked" or cert.get("revoked") is True or payload.get("revoked") is True:
        return reject("certificate_revoked")
    if isinstance(revoked_kids, (list, tuple, set)) and kid in revoked_kids:
        return reject("key_revoked")
    if isinstance(revoked_scan_ids, (list, tuple, set)) and isinstance(payload.get("scanId"), str) and payload.get("scanId") in revoked_scan_ids:
        return reject("certificate_revoked")
    if payload.get("domain") != expected_domain:
        return reject("payload_domain_mismatch")
    if cert.get("domain") != payload.get("domain"):
        return reject("unsigned_domain_mismatch")
    if cert.get("score") != payload.get("score"):
        return reject("unsigned_score_mismatch")
    if cert.get("certified") != payload.get("certified"):
        return reject("unsigned_certified_mismatch")
    if not isinstance(payload.get("certified"), bool):
        return reject("invalid_certified_flag")
    try:
        expires = datetime.fromisoformat(str(payload.get("expiresAt")).replace("Z", "+00:00"))
        audited = datetime.fromisoformat(str(payload.get("auditedAt")).replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if audited.tzinfo is None:
            audited = audited.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return reject("missing_or_invalid_certificate_timestamp")
    if audited > expires:
        return reject("invalid_certificate_interval")
    if (now or datetime.now(timezone.utc)) > expires:
        return reject("certificate_expired")
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not (0 <= score <= 100):
        return reject("invalid_score")
    has_claim_root = "claimRoot" in payload and payload.get("claimRoot") is not None
    has_claim_leaves_prop = "claimLeaves" in cert
    if has_claim_root:
        claim_root = payload.get("claimRoot")
        if not isinstance(claim_root, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", claim_root):
            return reject("invalid_claim_root")
        if not has_claim_leaves_prop:
            return reject("missing_claim_leaves")
        ok_leaves, computed_root_or_reason, _ = compute_claim_root_from_leaves(cert.get("claimLeaves"))
        if not ok_leaves:
            return reject(computed_root_or_reason)
        if computed_root_or_reason != claim_root.lower():
            return reject("claim_root_mismatch")
    elif has_claim_leaves_prop:
        ok_leaves, computed_root_or_reason, _ = compute_claim_root_from_leaves(cert.get("claimLeaves"))
        if not ok_leaves:
            return reject(computed_root_or_reason)
    if not (0 <= min_score <= 100):
        return reject("invalid_min_score")
    certified = payload.get("certified") is True and score >= min_score
    return {
        "status": "CERTIFIED" if certified else "AUDITED",
        "ok": certified,
        "score": score,
        "reason": "ok" if certified else ("score_below_min_score" if payload.get("certified") is True else "not_certified"),
        "signature": signature,
        "payload": payload,
    }


def parse_challenge_token(txt):
    """Token of a `proof-v2=challenge:<24-hex>;...` TXT value (DoH quoting tolerated), else None."""
    if not isinstance(txt, str):
        return None
    flat = re.sub(r'"\s+"', "", txt)
    flat = re.sub(r'^"|"$', "", flat)
    m = re.search(r"(?:^|;)\s*proof-v2=challenge:([0-9a-f]{24})(?:;|$)", flat)
    return m.group(1) if m else None


def check_dns_challenge(domain, dns_challenge, fetch=None):
    """Compare the certificate's dnsChallenge token with the TXT records at _proof-verify.<domain>.
    Returns (status, detail); status is 'verified', 'not_verified' or 'not_checked' (could not be performed)."""
    fetch = fetch or fetch_json
    host = f"_proof-verify.{domain}"
    expected = None
    if isinstance(dns_challenge, dict) and dns_challenge.get("host") == host:
        expected = parse_challenge_token(dns_challenge.get("value"))
    if not expected:
        return "not_checked", "certificate has no usable dnsChallenge for this domain"
    st, d = fetch(
        f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=TXT", "application/dns-json"
    )
    if st != 200 or not isinstance(d, dict) or not isinstance(d.get("Status"), int):
        return "not_checked", "DNS-over-HTTPS resolver unreachable or invalid response"
    if d["Status"] == 3:
        return "not_verified", "no TXT record (NXDOMAIN)"
    if d["Status"] != 0:
        return "not_checked", f"DNS resolver status {d['Status']}"
    answers = [a for a in (d.get("Answer") or []) if isinstance(a, dict) and a.get("type") == 16]
    if any(parse_challenge_token(str(a.get("data", ""))) == expected for a in answers):
        return "verified", "TXT challenge token matches the certificate dnsChallenge (resolver: Cloudflare DoH)"
    return "not_verified", "no TXT record with the expected challenge token"


def parse_args(argv):
    """Returns (domain_arg, jwks_url_or_None, error_or_None). Unknown flags are errors."""
    jwks_url = os.environ.get("PROOF_JWKS_URL") or None
    domain = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--jwks-url":
            if i + 1 >= len(argv):
                return None, None, "--jwks-url requires a URL"
            jwks_url = argv[i + 1]
            i += 1
        elif a.startswith("--jwks-url="):
            jwks_url = a.split("=", 1)[1]
        elif a.startswith("-"):
            return None, None, f"unknown option {a}"
        elif domain is None:
            domain = a
        i += 1
    return domain, jwks_url, None


def main():
    argv = sys.argv[1:]
    if not argv or "-h" in argv or "--help" in argv:
        print_help()
    domain_arg, jwks_url, err = parse_args(argv)
    if err or not domain_arg:
        print(f"Error: {err or 'missing domain'}", file=sys.stderr)
        write_github_outputs("INVALID", "", False)
        sys.exit(2)

    raw = domain_arg.strip().lower()
    raw = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0].removeprefix("www.").rstrip(".")
    if not DOMAIN_RE.match(raw):
        print(f"Error: invalid domain '{domain_arg}'", file=sys.stderr)
        write_github_outputs("INVALID", "", False)
        sys.exit(2)

    try:
        min_score = float(os.environ.get("PROOF_MIN_SCORE", "80"))
        if min_score != min_score:
            raise ValueError
    except ValueError:
        print("Error: PROOF_MIN_SCORE must be a number", file=sys.stderr)
        write_github_outputs("INVALID", "", False)
        sys.exit(2)

    print(f"\n[PROOF-VC v2] Verifying domain: {raw}")
    print("─" * 77)
    if jwks_url:
        print(UNPINNED_WARNING, file=sys.stderr)

    # 1. Live certificate (online)
    sys.stdout.write("• Querying PROOF Public Certificate API (online)... ")
    sys.stdout.flush()
    cert_status, cert = fetch_json(
        f"https://www.proofxray.com/api/public/v1/certificate?domain={urllib.parse.quote(raw)}",
        "application/json",
    )
    if cert_status != 200 or not isinstance(cert, dict) or cert.get("status") != "verified":
        print(f"✖ HTTP {cert_status}")
        print("─" * 77)
        print(f"STATUS: UNVERIFIED (No completed root-homepage audit found for {raw})")
        print("\n".join(audit_guidance(raw)) + "\n")
        write_github_outputs("UNVERIFIED", "", False)
        sys.exit(1)
    print("✔ 200 OK")

    # 2. Signature + decision (signed payload only)
    result = evaluate_certificate(cert, raw, min_score=min_score, jwks_url=jwks_url)
    sig = result["signature"]

    # 3. Informational, non-gating checks
    dns_status, dns_detail = check_dns_challenge(raw, cert.get("dnsChallenge"))
    dns_label = {"verified": "✔ VERIFIED", "not_verified": "○ NOT VERIFIED", "not_checked": "? NOT CHECKED"}[dns_status]
    print(f"• DNS-01 Ownership TXT (_proof-verify.{raw}): {dns_label} — {dns_detail}")
    llms_status, _ = fetch_json(f"https://{raw}/llms.txt", "text/markdown, text/plain")
    print(f"• LLM Routing Index (https://{raw}/llms.txt): " + ("✔ 200 OK" if llms_status == 200 else f"✖ {llms_status}"))
    agent_status, _ = fetch_json(f"https://{raw}/.well-known/agent.json", "application/json")
    print(f"• A2A Agent Card (https://{raw}/.well-known/agent.json): "
          + ("✔ 200 OK" if agent_status == 200 else f"✖ {agent_status}"))
    print("  (DNS, llms.txt and agent.json are informational and do not change the exit code)")
    print("─" * 77)

    if result["status"] == "UNVERIFIED":
        write_github_outputs("UNVERIFIED", "", False)
        if not sig["valid"]:
            print(f"{SIGNATURE_FAIL} ({sig['reason']})")
        else:
            print(f"FAIL: {result['reason']}")
        print("STATUS: UNVERIFIED\n")
        sys.exit(1)

    p = result["payload"]
    score = result["score"]
    write_github_outputs(result["status"], str(score), result["ok"])
    print(f"  • Status         : {result['status']}")
    print(f"  • Domain         : {p.get('domain')}")
    print(f"  • PROOF Score    : {score}/100 (certified: {'yes' if p.get('certified') else 'no'}, min required: {min_score:g})")
    print(f"  • Audited At     : {p.get('auditedAt')}")
    print(f"  • Expires At     : {p.get('expiresAt')} ({p.get('tier', 'snapshot')})")
    print(f"  • SHA-256 Digest : {cert['attestation'].get('digest')}")
    if p.get("claimRoot"):
        print(f"  • Merkle Claims  : {p.get('claimRoot')}")
    if sig["key_source"] == "pinned":
        print(f"  • Ed25519        : VALID — signature verified against pinned key {sig['kid']}; certificate fetched online")
    else:
        print(f"  • Ed25519        : VALID against UNPINNED KEY (insecure) — key {sig['kid']} fetched from {jwks_url}")
    print(f"  • Public Cert    : {cert.get('certificateUrl')}")
    print(f"  • Live Badge     : {cert.get('badgeUrl')}\n")
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
