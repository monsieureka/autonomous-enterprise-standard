'use strict';
/**
 * Shared, zero-dependency PROOF-VC v2 verification core (used by bin/cli.js and mcp/server.js).
 * The Python twin is bin/proof-verify.py: keep both in sync.
 *
 * Fail-closed rules:
 *  - a certificate without a valid Ed25519 attestation is never accepted;
 *  - the signature is checked against a PINNED key selected by `kid` (no fallback to "the first key");
 *  - the key URL written inside the attestation is never used;
 *  - fetching keys from a URL is possible only through the explicit opt-in (--jwks-url / PROOF_JWKS_URL).
 */

const https = require('node:https');
const crypto = require('node:crypto');

const VERSION = require('../package.json').version;

/**
 * Trusted public keys. To trust a new key, add an entry here (and in PINNED_KEYS of
 * bin/proof-verify.py) and ship a new release. The values come from
 * https://www.proofxray.com/.well-known/jwks.json (OKP / Ed25519, `x` is the base64url public key).
 */
const PINNED_KEYS = [
  { kid: 'proof-root-2026-11-24', x: 'DVEMQfdW69Z5iQxjWLO3vZTa1bTeYf7SJ6AVsiew4LA' },
];

const SIGNATURE_FAIL = 'FAIL: no valid Ed25519 signature';
const UNPINNED_WARNING =
  'UNPINNED KEY (insecure): the public key is fetched from the URL you opted into, not from the pinned list.';

function canonicalJson(value) {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('non_finite_number');
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

const CLAIM_EMPTY_ROOT_LABEL = 'proof-claims-empty-v2';

/**
 * Recompute the Merkle claimRoot from published claimLeaves:
 * - each leaf is { canonical: string, leafHash: hex64 }, with leafHash = SHA-256(0x00 || UTF-8(canonical))
 * - internal nodes are SHA-256(0x01 || leftBytes || rightBytes), odd end-of-level node paired with itself
 * - empty leaf list hashes CLAIM_EMPTY_ROOT_LABEL
 * Returns { valid: true, claimRoot, leavesCount } or { valid: false, reason }.
 */
function computeClaimRootFromLeaves(claimLeaves) {
  if (!Array.isArray(claimLeaves)) return { valid: false, reason: 'invalid_claim_leaves' };
  const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
  if (claimLeaves.length === 0) {
    return { valid: true, claimRoot: sha256Hex(Buffer.from(CLAIM_EMPTY_ROOT_LABEL, 'utf8')), leavesCount: 0 };
  }
  let level = [];
  for (const leaf of claimLeaves) {
    if (!leaf || typeof leaf !== 'object' || typeof leaf.canonical !== 'string' || typeof leaf.leafHash !== 'string' || !/^[a-f0-9]{64}$/i.test(leaf.leafHash)) {
      return { valid: false, reason: 'invalid_claim_leaves' };
    }
    const expected = sha256Hex(Buffer.concat([Buffer.from([0x00]), Buffer.from(leaf.canonical, 'utf8')]));
    if (expected !== leaf.leafHash.toLowerCase()) {
      return { valid: false, reason: 'claim_leaf_hash_mismatch' };
    }
    level.push(expected);
  }
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] || left;
      next.push(sha256Hex(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')])));
    }
    level = next;
  }
  return { valid: true, claimRoot: level[0], leavesCount: claimLeaves.length };
}

function fetchUrl(url, accept = 'application/json, text/plain', redirects = 3, userAgent = `proof-verify/${VERSION}`) {
  return new Promise((resolve) => {
    let req;
    try {
      req = https.get(
        url,
        { headers: { 'User-Agent': userAgent, Accept: accept }, timeout: 8000 },
        (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
            res.resume();
            const next = new URL(res.headers.location, url).toString();
            return resolve(fetchUrl(next, accept, redirects - 1, userAgent));
          }
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, data: JSON.parse(data) });
            } catch {
              resolve({ status: res.statusCode, data });
            }
          });
        },
      );
    } catch (e) {
      return resolve({ status: 500, error: e.message });
    }
    req.on('timeout', () => { req.destroy(); resolve({ status: 408, error: 'timeout' }); });
    req.on('error', (err) => resolve({ status: 500, error: err.message }));
  });
}

/** `--jwks-url <url>` / `--jwks-url=<url>` in argv, else env PROOF_JWKS_URL, else null. */
function resolveJwksUrl(argv = [], env = process.env) {
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--jwks-url') return argv[i + 1] || '';
    if (argv[i].startsWith('--jwks-url=')) return argv[i].slice('--jwks-url='.length);
  }
  return env.PROOF_JWKS_URL || null;
}

function b64urlBytes(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(s)) return null;
  return Buffer.from(s, 'base64url');
}

async function resolveKey(kid, { pinnedKeys, jwksUrl, fetchJson }) {
  const pinned = pinnedKeys.find((k) => k.kid === kid);
  if (pinned) return { x: pinned.x, keySource: 'pinned' };
  if (!jwksUrl) return { error: 'unknown_kid' };
  if (!/^https:\/\//i.test(jwksUrl)) return { error: 'jwks_url_must_be_https' };
  const res = await fetchJson(jwksUrl, 'application/json');
  const keys = Array.isArray(res.data && res.data.keys) ? res.data.keys : [];
  const jwk = keys.find((k) => k && k.kid === kid && k.kty === 'OKP' && k.crv === 'Ed25519');
  if (!jwk || typeof jwk.x !== 'string') return { error: 'jwks_key_not_found' };
  return { x: jwk.x, keySource: 'unpinned-jwks' };
}

/**
 * Verify an attestation envelope { payload, digest, signature: { alg, kid, value } }.
 * Returns { valid, reason, kid, keySource }. Never throws; anything unexpected is invalid.
 * With a pinned key no network access happens.
 */
async function verifyEnvelope(env, opts = {}) {
  const pinnedKeys = opts.pinnedKeys || PINNED_KEYS;
  const jwksUrl = opts.jwksUrl || null;
  const fetchJson = opts.fetchJson || fetchUrl;
  const fail = (reason, extra = {}) => ({ valid: false, reason, ...extra });
  try {
    if (!env || typeof env !== 'object') return fail('no_ed25519_attestation');
    const sig = env.signature;
    if (!sig || typeof sig !== 'object' || sig.alg !== 'Ed25519') return fail('no_ed25519_attestation');
    if (typeof sig.kid !== 'string' || !sig.kid) return fail('missing_kid');
    if (typeof sig.value !== 'string' || !sig.value) return fail('missing_signature_value');
    if (!env.payload || typeof env.payload !== 'object') return fail('missing_payload');
    const digest = crypto.createHash('sha256').update(canonicalJson(env.payload)).digest('hex');
    if (digest !== env.digest) return fail('digest_mismatch', { kid: sig.kid });
    const key = await resolveKey(sig.kid, { pinnedKeys, jwksUrl, fetchJson });
    if (key.error) return fail(key.error, { kid: sig.kid });
    const xBytes = b64urlBytes(key.x);
    const sigBytes = b64urlBytes(sig.value);
    if (!xBytes || xBytes.length !== 32) return fail('bad_public_key', { kid: sig.kid });
    if (!sigBytes || sigBytes.length !== 64) return fail('invalid_signature', { kid: sig.kid });
    const pub = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' });
    const ok = crypto.verify(null, Buffer.from(`proof-vc-v2\n${digest}`, 'utf8'), pub, sigBytes);
    return ok
      ? { valid: true, reason: 'ok', kid: sig.kid, keySource: key.keySource }
      : fail('invalid_signature', { kid: sig.kid });
  } catch (e) {
    return fail(`error: ${e.message}`);
  }
}

/**
 * Decide on a certificate returned by the public API. Everything that decides the outcome comes from the
 * SIGNED payload; top-level fields that are not signed must agree with it or the certificate is rejected.
 * Returns { status: CERTIFIED | AUDITED | UNVERIFIED, ok, score, reason, signature, payload }.
 */
async function evaluateCertificate(cert, expectedDomain, opts = {}) {
  const minScore = Number.isFinite(opts.minScore) ? opts.minScore : 80;
  const now = opts.now instanceof Date ? opts.now : new Date();
  const signature = await verifyEnvelope(cert && cert.attestation, opts);
  const reject = (reason) => ({ status: 'UNVERIFIED', ok: false, score: null, reason, signature });
  if (!signature.valid) return reject(signature.reason);

  const envelope = cert && cert.attestation;
  if (!envelope || envelope.protocol !== 'proof-vc-v2') return reject('invalid_attestation_protocol');
  const payload = envelope.payload;
  if (!payload || payload.protocol !== 'proof-vc-v2') return reject('invalid_payload_protocol');
  if (cert.status === 'revoked' || cert.revoked === true || payload.revoked === true) return reject('certificate_revoked');
  if (Array.isArray(opts.revokedKids) && opts.revokedKids.includes(signature.kid)) return reject('key_revoked');
  if (Array.isArray(opts.revokedScanIds) && typeof payload.scanId === 'string' && opts.revokedScanIds.includes(payload.scanId)) {
    return reject('certificate_revoked');
  }
  if (payload.domain !== expectedDomain) return reject('payload_domain_mismatch');
  if (cert.domain !== payload.domain) return reject('unsigned_domain_mismatch');
  if (cert.score !== payload.score) return reject('unsigned_score_mismatch');
  if (cert.certified !== payload.certified) return reject('unsigned_certified_mismatch');
  if (typeof payload.certified !== 'boolean') return reject('invalid_certified_flag');
  const expires = Date.parse(payload.expiresAt);
  const audited = Date.parse(payload.auditedAt);
  if (Number.isNaN(expires)) return reject('missing_or_invalid_expiresAt');
  if (Number.isNaN(audited)) return reject('missing_or_invalid_auditedAt');
  if (audited > expires) return reject('invalid_certificate_interval');
  if (now.getTime() > expires) return reject('certificate_expired');
  const score = payload.score;
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 100) return reject('invalid_score');
  const hasClaimRoot = payload.claimRoot !== undefined && payload.claimRoot !== null;
  const hasClaimLeavesProp = Object.prototype.hasOwnProperty.call(cert, 'claimLeaves');
  if (hasClaimRoot) {
    if (typeof payload.claimRoot !== 'string' || !/^[a-f0-9]{64}$/i.test(payload.claimRoot)) return reject('invalid_claim_root');
    if (!hasClaimLeavesProp || cert.claimLeaves === undefined) return reject('missing_claim_leaves');
    const merkle = computeClaimRootFromLeaves(cert.claimLeaves);
    if (!merkle.valid) return reject(merkle.reason);
    if (merkle.claimRoot !== payload.claimRoot.toLowerCase()) return reject('claim_root_mismatch');
  } else if (hasClaimLeavesProp && cert.claimLeaves !== undefined) {
    const merkle = computeClaimRootFromLeaves(cert.claimLeaves);
    if (!merkle.valid) return reject(merkle.reason);
  }
  if (minScore < 0 || minScore > 100) return reject('invalid_min_score');

  const certified = payload.certified === true && score >= minScore;
  return {
    status: certified ? 'CERTIFIED' : 'AUDITED',
    ok: certified,
    score,
    reason: certified ? 'ok' : (payload.certified === true ? 'score_below_min_score' : 'not_certified'),
    signature,
    payload,
  };
}

/** Extract the token of a `proof-v2=challenge:<token>;...` TXT value (DoH quoting tolerated), else null. */
function parseChallengeToken(txt) {
  if (typeof txt !== 'string') return null;
  const flat = txt.replace(/"\s+"/g, '').replace(/^"|"$/g, '');
  const m = /(?:^|;)\s*proof-v2=challenge:([0-9a-f]{24})(?:;|$)/.exec(flat);
  return m ? m[1] : null;
}

/**
 * DNS-01 ownership anchor. Compares the token of the certificate's `dnsChallenge` with the TXT records
 * published at _proof-verify.<domain>. Returns { status: 'verified' | 'not_verified' | 'not_checked', detail }.
 * "not_checked" means the check could not be performed (never reported as verified).
 */
async function checkDnsChallenge(domain, dnsChallenge, fetchJson = fetchUrl) {
  const host = `_proof-verify.${domain}`;
  const expected = dnsChallenge && dnsChallenge.host === host ? parseChallengeToken(dnsChallenge.value) : null;
  if (!expected) return { status: 'not_checked', detail: 'certificate has no usable dnsChallenge for this domain' };
  const res = await fetchJson(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=TXT`,
    'application/dns-json',
  );
  const d = res && res.data;
  if (res.status !== 200 || !d || typeof d !== 'object' || typeof d.Status !== 'number') {
    return { status: 'not_checked', detail: 'DNS-over-HTTPS resolver unreachable or invalid response' };
  }
  if (d.Status === 3) return { status: 'not_verified', detail: 'no TXT record (NXDOMAIN)' };
  if (d.Status !== 0) return { status: 'not_checked', detail: `DNS resolver status ${d.Status}` };
  const answers = Array.isArray(d.Answer) ? d.Answer.filter((a) => a && a.type === 16) : [];
  const match = answers.some((a) => parseChallengeToken(String(a.data || '')) === expected);
  return match
    ? { status: 'verified', detail: 'TXT challenge token matches the certificate dnsChallenge (resolver: Cloudflare DoH)' }
    : { status: 'not_verified', detail: 'no TXT record with the expected challenge token' };
}

const AUDIT_URL = 'https://www.proofxray.com/en#audit-gratuit';

/** What a developer sees when a domain has no certificate yet: one link and one instruction. */
function auditGuidance(domain) {
  return [
    'Run a free X-Ray audit of your homepage (about 10 s, no sign-up): paste your site in the box at',
    `  ${AUDIT_URL}`,
    `Then run again: npx proof-verify ${domain}`,
  ];
}

module.exports = {
  VERSION,
  AUDIT_URL,
  auditGuidance,
  PINNED_KEYS,
  SIGNATURE_FAIL,
  UNPINNED_WARNING,
  CLAIM_EMPTY_ROOT_LABEL,
  canonicalJson,
  computeClaimRootFromLeaves,
  fetchUrl,
  resolveJwksUrl,
  verifyEnvelope,
  evaluateCertificate,
  parseChallengeToken,
  checkDnsChallenge,
};
