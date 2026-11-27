'use strict';
// Offline tests: no network access, throwaway Ed25519 keypair generated at run time.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const lib = require('../lib/verify');

const KID = 'test-key-1';
const DOMAIN = 'example.com';
const NOW = new Date('2026-11-25T00:00:00Z');

function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, x: publicKey.export({ format: 'jwk' }).x };
}

function envelope(payload, key, kid = KID) {
  const digest = crypto.createHash('sha256').update(lib.canonicalJson(payload)).digest('hex');
  const value = crypto.sign(null, Buffer.from(`proof-vc-v2\n${digest}`), key.privateKey).toString('base64url');
  return {
    protocol: 'proof-vc-v2',
    payload,
    digest,
    signature: { alg: 'Ed25519', kid, jwksUrl: 'https://attacker.invalid/jwks.json', value },
  };
}

function certificate(key, over = {}) {
  const payload = {
    protocol: 'proof-vc-v2', domain: DOMAIN, tier: 'snapshot', score: 92, certified: true,
    auditedAt: '2026-11-24T00:00:00.000Z', expiresAt: '2026-12-01T00:00:00.000Z', ...(over.payload || {}),
  };
  return {
    status: 'verified', domain: payload.domain, score: payload.score, certified: payload.certified,
    attestation: envelope(payload, key), ...(over.top || {}),
  };
}

const ctx = (key, extra = {}) => ({ pinnedKeys: [{ kid: KID, x: key.x }], now: NOW, ...extra });
const noNetwork = () => { throw new Error('network must not be used'); };

test('pinned list holds the expected trusted key', () => {
  assert.deepEqual(lib.PINNED_KEYS, [{ kid: 'proof-root-2026-11-24', x: 'DVEMQfdW69Z5iQxjWLO3vZTa1bTeYf7SJ6AVsiew4LA' }]);
});

test('valid signature passes, without any network access', async () => {
  const key = newKey();
  const r = await lib.evaluateCertificate(certificate(key), DOMAIN, ctx(key, { fetchJson: noNetwork }));
  assert.equal(r.status, 'CERTIFIED');
  assert.equal(r.ok, true);
  assert.equal(r.signature.keySource, 'pinned');
});

test('score below min_score is AUDITED, not CERTIFIED', async () => {
  const key = newKey();
  const r = await lib.evaluateCertificate(certificate(key), DOMAIN, ctx(key, { minScore: 95 }));
  assert.equal(r.status, 'AUDITED');
  assert.equal(r.ok, false);
});

test('tampered payload fails (digest mismatch)', async () => {
  const key = newKey();
  const cert = certificate(key);
  cert.attestation.payload.score = 100;
  cert.score = 100;
  const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
  assert.equal(r.ok, false);
  assert.equal(r.status, 'UNVERIFIED');
  assert.equal(r.signature.reason, 'digest_mismatch');
});

test('tampered payload with recomputed digest fails (invalid signature)', async () => {
  const key = newKey();
  const cert = certificate(key);
  cert.attestation.payload.score = 100;
  cert.score = 100;
  cert.attestation.digest = crypto.createHash('sha256').update(lib.canonicalJson(cert.attestation.payload)).digest('hex');
  const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
  assert.equal(r.ok, false);
  assert.equal(r.signature.reason, 'invalid_signature');
});

test('missing attestation fails', async () => {
  const key = newKey();
  const cert = certificate(key);
  delete cert.attestation;
  const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
  assert.equal(r.ok, false);
  assert.equal(r.status, 'UNVERIFIED');
  assert.equal(r.signature.reason, 'no_ed25519_attestation');
});

test('attestation without Ed25519 signature or kid fails', async () => {
  const key = newKey();
  for (const mutate of [
    (c) => { delete c.attestation.signature; },
    (c) => { c.attestation.signature.alg = 'HS256'; },
    (c) => { delete c.attestation.signature.kid; },
    (c) => { c.attestation.signature.value = ''; },
  ]) {
    const cert = certificate(key);
    mutate(cert);
    const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
    assert.equal(r.ok, false);
    assert.equal(r.status, 'UNVERIFIED');
  }
});

test('unknown kid fails and never falls back to the first pinned key', async () => {
  const key = newKey();
  const cert = certificate(key);
  cert.attestation.signature.kid = 'some-other-kid';
  const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key, { fetchJson: noNetwork }));
  assert.equal(r.ok, false);
  assert.equal(r.signature.reason, 'unknown_kid');
});

test('wrong key fails (right kid, different key)', async () => {
  const signer = newKey();
  const other = newKey();
  const r = await lib.evaluateCertificate(certificate(signer), DOMAIN, ctx(other));
  assert.equal(r.ok, false);
  assert.equal(r.signature.reason, 'invalid_signature');
});

test('the jwksUrl written inside the attestation is never fetched', async () => {
  const key = newKey();
  const cert = certificate(key);
  cert.attestation.signature.kid = 'unpinned';
  const urls = [];
  const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key, { fetchJson: async (u) => { urls.push(u); return { status: 200, data: { keys: [] } }; } }));
  assert.equal(r.ok, false);
  assert.deepEqual(urls, []);
});

test('explicit --jwks-url opt-in resolves an unpinned kid and is flagged unpinned', async () => {
  const key = newKey();
  const urls = [];
  const fetchJson = async (u) => {
    urls.push(u);
    return { status: 200, data: { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: key.x }] } };
  };
  const r = await lib.evaluateCertificate(certificate(key), DOMAIN, { pinnedKeys: [], now: NOW, jwksUrl: 'https://keys.example/jwks.json', fetchJson });
  assert.equal(r.ok, true);
  assert.equal(r.signature.keySource, 'unpinned-jwks');
  assert.deepEqual(urls, ['https://keys.example/jwks.json']);
  const http = await lib.evaluateCertificate(certificate(key), DOMAIN, { pinnedKeys: [], now: NOW, jwksUrl: 'http://keys.example/jwks.json', fetchJson });
  assert.equal(http.ok, false);
  assert.equal(http.signature.reason, 'jwks_url_must_be_https');
});

test('resolveJwksUrl reads flag and env, otherwise null', () => {
  assert.equal(lib.resolveJwksUrl(['a.com', '--jwks-url', 'https://x/y'], {}), 'https://x/y');
  assert.equal(lib.resolveJwksUrl(['--jwks-url=https://x/z'], {}), 'https://x/z');
  assert.equal(lib.resolveJwksUrl([], { PROOF_JWKS_URL: 'https://e/j' }), 'https://e/j');
  assert.equal(lib.resolveJwksUrl(['a.com'], {}), null);
});

test('signed payload is bound to the requested domain, to unsigned fields, and to the expiry date', async () => {
  const key = newKey();
  assert.equal((await lib.evaluateCertificate(certificate(key), 'other.com', ctx(key))).reason, 'payload_domain_mismatch');
  const c1 = certificate(key); c1.score = 100;
  assert.equal((await lib.evaluateCertificate(c1, DOMAIN, ctx(key))).reason, 'unsigned_score_mismatch');
  const c2 = certificate(key, { payload: { certified: false } }); c2.certified = true;
  assert.equal((await lib.evaluateCertificate(c2, DOMAIN, ctx(key))).reason, 'unsigned_certified_mismatch');
  const late = await lib.evaluateCertificate(certificate(key), DOMAIN, ctx(key, { now: new Date('2026-12-02T00:00:00Z') }));
  assert.equal(late.ok, false);
  assert.equal(late.reason, 'certificate_expired');
  const noExp = await lib.evaluateCertificate(certificate(key, { payload: { expiresAt: undefined } }), DOMAIN, ctx(key));
  assert.equal(noExp.ok, false);
});

test('PROOF-VC v2 rejects protocol confusion, invalid score ranges and invalid claim roots', async () => {
  const key = newKey();
  const resign = (c) => {
    c.attestation.digest = crypto.createHash('sha256').update(lib.canonicalJson(c.attestation.payload)).digest('hex');
    c.attestation.signature.value = crypto.sign(null, Buffer.from(`proof-vc-v2\n${c.attestation.digest}`), key.privateKey).toString('base64url');
  };
  const cases = [
    ['invalid_attestation_protocol', (c) => { c.attestation.protocol = 'proof-v1'; }],
    ['invalid_payload_protocol', (c) => { c.attestation.payload.protocol = 'proof-v1'; resign(c); }],
    ['invalid_score', (c) => { c.attestation.payload.score = 101; c.score = 101; resign(c); }],
    ['invalid_claim_root', (c) => { c.attestation.payload.claimRoot = 'not-a-sha256'; resign(c); }],
    ['missing_or_invalid_auditedAt', (c) => { c.attestation.payload.auditedAt = 'invalid'; resign(c); }],
    ['invalid_certificate_interval', (c) => { c.attestation.payload.auditedAt = '2026-12-10T00:00:00Z'; resign(c); }],
  ];
  for (const [expectedReason, mutate] of cases) {
    const cert = certificate(key);
    mutate(cert);
    const r = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
    assert.equal(r.status, 'UNVERIFIED');
    assert.equal(r.reason, expectedReason);
  }
});

test('Merkle claimRoot is reconstructed from claimLeaves (0x00 leaf, 0x01 internal node) and rejects tampered leaves', async () => {
  const key = newKey();
  const sha256Hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
  const rawFacts = [
    '{"field":"name","normalized":"PROOF X-Ray","source":"jsonld","url":"https://www.proofxray.com/"}',
    '{"field":"protocol","normalized":"proof-vc-v2","source":"meta","url":"https://www.proofxray.com/proof-vc"}',
    '{"field":"siret","normalized":"50996962200067","source":"html","url":"https://www.proofxray.com/"}',
  ];
  const claimLeaves = rawFacts.map((canonical) => ({
    canonical,
    leafHash: sha256Hex(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonical, 'utf8')])),
  }));
  const computed = lib.computeClaimRootFromLeaves(claimLeaves);
  assert.equal(computed.valid, true);
  assert.equal(computed.leavesCount, 3);

  const cert = certificate(key, { payload: { claimRoot: computed.claimRoot } });
  cert.claimLeaves = claimLeaves;
  const okRes = await lib.evaluateCertificate(cert, DOMAIN, ctx(key));
  assert.equal(okRes.status, 'CERTIFIED');

  // Tamper one leaf's canonical content without updating leafHash -> claim_leaf_hash_mismatch
  const tamperedLeafCert = certificate(key, { payload: { claimRoot: computed.claimRoot } });
  tamperedLeafCert.claimLeaves = claimLeaves.map((l, idx) => (idx === 1 ? { ...l, canonical: `${l.canonical} ` } : l));
  const badLeaf = await lib.evaluateCertificate(tamperedLeafCert, DOMAIN, ctx(key));
  assert.equal(badLeaf.status, 'UNVERIFIED');
  assert.equal(badLeaf.reason, 'claim_leaf_hash_mismatch');

  // Valid leafHash but does not match signed claimRoot -> claim_root_mismatch
  const tamperedRootCert = certificate(key, { payload: { claimRoot: 'a'.repeat(64) } });
  tamperedRootCert.claimLeaves = claimLeaves;
  const badRoot = await lib.evaluateCertificate(tamperedRootCert, DOMAIN, ctx(key));
  assert.equal(badRoot.status, 'UNVERIFIED');
  assert.equal(badRoot.reason, 'claim_root_mismatch');

  // Mandatory claimLeaves when claimRoot is present -> missing_claim_leaves
  const missingLeavesCert = certificate(key, { payload: { claimRoot: computed.claimRoot } });
  const missingRes = await lib.evaluateCertificate(missingLeavesCert, DOMAIN, ctx(key));
  assert.equal(missingRes.status, 'UNVERIFIED');
  assert.equal(missingRes.reason, 'missing_claim_leaves');

  // Null claimLeaves -> invalid_claim_leaves (strict Node/Python parity)
  const nullLeavesCert = certificate(key, { payload: { claimRoot: computed.claimRoot } });
  nullLeavesCert.claimLeaves = null;
  const nullRes = await lib.evaluateCertificate(nullLeavesCert, DOMAIN, ctx(key));
  assert.equal(nullRes.status, 'UNVERIFIED');
  assert.equal(nullRes.reason, 'invalid_claim_leaves');

  const nullLeavesNoRootCert = certificate(key);
  nullLeavesNoRootCert.claimLeaves = null;
  const nullNoRootRes = await lib.evaluateCertificate(nullLeavesNoRootCert, DOMAIN, ctx(key));
  assert.equal(nullNoRootRes.status, 'UNVERIFIED');
  assert.equal(nullNoRootRes.reason, 'invalid_claim_leaves');
});

test('JCS RFC 8785 canonicalJson matches fixed cross-language vector, floats, UTF-16 key order and rejects NaN/Infinity', () => {
  const vector = {
    z: 1.0,
    negZero: -0.0,
    exp: 1e21,
    micro: 0.000001,
    frac: 333333333.3333333,
    '\ufb00': 'ff',
    '\ud83d\ude00': 'grin',
    '\u20ac': 'euro',
    a: ['x', { d: true, b: null, c: 94 }],
    m: 'proof-vc-v2',
  };
  const expectedCanonical =
    '{"a":["x",{"b":null,"c":94,"d":true}],"exp":1e+21,"frac":333333333.3333333,"m":"proof-vc-v2","micro":0.000001,"negZero":0,"z":1,"\u20ac":"euro","\ud83d\ude00":"grin","\ufb00":"ff"}';
  const expectedSha256 = '5407c528fbd9ea23c274ffac0a5c84ca7f23c39c366ef3a78422d8c267481fb9';
  assert.equal(lib.canonicalJson(vector), expectedCanonical);
  assert.equal(crypto.createHash('sha256').update(lib.canonicalJson(vector), 'utf8').digest('hex'), expectedSha256);
  assert.throws(() => lib.canonicalJson({ bad: Number.NaN }), /non_finite_number/);
  assert.throws(() => lib.canonicalJson({ bad: Number.POSITIVE_INFINITY }), /non_finite_number/);
});

test('evaluateCertificate rejects revoked certificates, revoked scanIds and revoked key IDs', async () => {
  const key = newKey();
  const c1 = certificate(key);
  c1.status = 'revoked';
  assert.equal((await lib.evaluateCertificate(c1, DOMAIN, ctx(key))).reason, 'certificate_revoked');

  const c2 = certificate(key, { payload: { revoked: true } });
  assert.equal((await lib.evaluateCertificate(c2, DOMAIN, ctx(key))).reason, 'certificate_revoked');

  const c3 = certificate(key, { payload: { scanId: 'scan-revoked-1' } });
  assert.equal((await lib.evaluateCertificate(c3, DOMAIN, ctx(key, { revokedScanIds: ['scan-revoked-1'] }))).reason, 'certificate_revoked');

  const c4 = certificate(key);
  assert.equal((await lib.evaluateCertificate(c4, DOMAIN, ctx(key, { revokedKids: [KID] }))).reason, 'key_revoked');
});

const TOKEN = '318926611b90a11d9392bc21';
const challenge = { host: `_proof-verify.${DOMAIN}`, value: `proof-v2=challenge:${TOKEN};jwks=https://x/j;kid=k` };
const doh = (body, status = 200) => async () => ({ status, data: body });

test('DNS check compares the expected token, not just the proof-v2= prefix', async () => {
  const good = { Status: 0, Answer: [{ type: 16, data: `"proof-v2=challenge:${TOKEN};jwks=https://x/j;kid=k"` }] };
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh(good))).status, 'verified');
  const split = { Status: 0, Answer: [{ type: 16, data: `"proof-v2=challenge:${TOKEN.slice(0, 10)}" "${TOKEN.slice(10)};kid=k"` }] };
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh(split))).status, 'verified');
  const wrong = { Status: 0, Answer: [{ type: 16, data: '"proof-v2=challenge:000000000000000000000000"' }] };
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh(wrong))).status, 'not_verified');
  const prefixOnly = { Status: 0, Answer: [{ type: 16, data: '"proof-v2="' }] };
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh(prefixOnly))).status, 'not_verified');
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh({ Status: 3 }))).status, 'not_verified');
});

test('DNS check reports not_checked when it cannot be performed, never verified', async () => {
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh(null, 500))).status, 'not_checked');
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh('<html>', 403))).status, 'not_checked');
  assert.equal((await lib.checkDnsChallenge(DOMAIN, challenge, doh({ Status: 2 }))).status, 'not_checked');
  assert.equal((await lib.checkDnsChallenge(DOMAIN, undefined, noNetwork)).status, 'not_checked');
  assert.equal((await lib.checkDnsChallenge(DOMAIN, { host: '_proof-verify.evil.com', value: challenge.value }, noNetwork)).status, 'not_checked');
});

test('CLI: help exits 0, invalid input exits 2 (no network used)', () => {
  const cli = path.join(__dirname, '..', 'bin', 'cli.js');
  assert.equal(spawnSync(process.execPath, [cli, '--help']).status, 0);
  assert.equal(spawnSync(process.execPath, [cli, 'not a domain']).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, 'example.com'], { env: { ...process.env, PROOF_MIN_SCORE: 'abc' } }).status, 2);
});

test('audit guidance for an unverified domain points to the English audit box and tells how to re-run', () => {
  const lines = lib.auditGuidance('mon-site.example');
  assert.equal(lib.AUDIT_URL, 'https://www.proofxray.com/en#audit-gratuit');
  assert.ok(lines.some((l) => l.includes('https://www.proofxray.com/en#audit-gratuit')));
  assert.ok(lines.some((l) => l.includes('npx proof-verify mon-site.example')));
  assert.ok(!lines.join('\n').includes('proofxray.com/#audit-gratuit'));
});
