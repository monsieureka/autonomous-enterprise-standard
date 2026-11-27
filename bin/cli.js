#!/usr/bin/env node

/**
 * proof-verify: CLI verifier for PROOF-VC v2 certificates (EAI v1.0 Standard).
 * Fetches https://www.proofxray.com/api/public/v1/certificate (online), then verifies the Ed25519 attestation
 * against a PINNED public key (no network needed for that step). Fails closed: no valid signature => exit 1.
 * Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
 */

const lib = require('../lib/verify');

const argv = process.argv.slice(2);
const jwksUrl = lib.resolveJwksUrl(argv);
const flagValueIdx = new Set();
argv.forEach((a, i) => { if (a === '--jwks-url') flagValueIdx.add(i + 1); });
const domainArg = argv.find((a, i) => !a.startsWith('-') && !flagValueIdx.has(i));

const HELP = `
\x1b[1m\x1b[36mPROOF X-Ray — Autonomous Enterprise Standard CLI Verifier (EAI v1.0 / PROOF-VC v2)\x1b[0m
Author: Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)

\x1b[1mUsage:\x1b[0m
  proof-verify <domain> [--jwks-url <url>]
  node bin/cli.js <domain> [--jwks-url <url>]

\x1b[1mOptions:\x1b[0m
  --jwks-url <url>   INSECURE opt-in (key rotation only): look up a key id that is not in the pinned list
                     in this JWKS (env: PROOF_JWKS_URL). Prints an "UNPINNED KEY" warning.
  PROOF_MIN_SCORE    Minimum score to be reported CERTIFIED (default 80).

Exit code 0 only if the certificate carries a valid Ed25519 signature (pinned key), is not expired, is
marked certified and reaches the minimum score. Otherwise 1 (2 for invalid input).
`;

if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
  console.log(HELP);
  process.exit(0);
}
if (!domainArg) {
  console.error(HELP);
  process.exit(2);
}
if (jwksUrl === '') {
  console.error('\x1b[31mError: --jwks-url requires a URL\x1b[0m');
  process.exit(2);
}

const cleanDomain = domainArg
  .trim()
  .toLowerCase()
  .replace(/^https?:\/\//i, '')
  .split('/')[0]
  .replace(/:\d+$/, '')
  .replace(/^www\./, '')
  .replace(/\.$/, '');

if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleanDomain)) {
  console.error(`\x1b[31mError: invalid domain "${domainArg}"\x1b[0m`);
  process.exit(2);
}

const minScore = Number(process.env.PROOF_MIN_SCORE === undefined ? 80 : process.env.PROOF_MIN_SCORE);
if (!Number.isFinite(minScore)) {
  console.error('\x1b[31mError: PROOF_MIN_SCORE must be a number\x1b[0m');
  process.exit(2);
}

const DNS_LABEL = {
  verified: '\x1b[32m✔ VERIFIED\x1b[0m',
  not_verified: '\x1b[33m○ NOT VERIFIED\x1b[0m',
  not_checked: '\x1b[33m? NOT CHECKED\x1b[0m',
};

async function runAudit() {
  console.log(`\n\x1b[1m\x1b[34m[PROOF-VC v2]\x1b[0m Verifying domain: \x1b[1m${cleanDomain}\x1b[0m`);
  console.log('─────────────────────────────────────────────────────────────────────────────');
  if (jwksUrl !== null) console.error(`\x1b[1m\x1b[31m${lib.UNPINNED_WARNING}\x1b[0m`);

  // 1. Live certificate (online)
  process.stdout.write('• Querying PROOF Public Certificate API (online)... ');
  const certUrl = `https://www.proofxray.com/api/public/v1/certificate?domain=${encodeURIComponent(cleanDomain)}`;
  const certRes = await lib.fetchUrl(certUrl, 'application/json');
  if (certRes.status !== 200 || !certRes.data || typeof certRes.data !== 'object' || certRes.data.status !== 'verified') {
    console.log(`\x1b[33m✖ HTTP ${certRes.status}\x1b[0m`);
    console.log('─────────────────────────────────────────────────────────────────────────────');
    console.log(`\x1b[1m\x1b[33mSTATUS: UNVERIFIED (No completed root-homepage audit found for ${cleanDomain})\x1b[0m`);
    console.log(lib.auditGuidance(cleanDomain).join('\n') + '\n');
    process.exit(1);
  }
  console.log('\x1b[32m✔ 200 OK\x1b[0m');
  const cert = certRes.data;

  // 2. Signed revocation list (online, verified against pinned key)
  const revocations = await lib.fetchAndVerifyRevocations({ jwksUrl });
  if (revocations.status === 'failed') {
    console.log(`• Signed Revocations (/.well-known/revocations.json): \x1b[31m✖ FAIL (${revocations.reason})\x1b[0m`);
    console.log('─────────────────────────────────────────────────────────────────────────────');
    console.log(`\x1b[1m\x1b[31mFAIL: ${revocations.reason}\x1b[0m`);
    console.log('\x1b[1m\x1b[31mSTATUS: UNVERIFIED\x1b[0m\n');
    process.exit(1);
  }
  if (revocations.status === 'verified') {
    console.log(`• Signed Revocations (/.well-known/revocations.json): \x1b[32m✔ VERIFIED\x1b[0m (${revocations.revokedKids.length} revoked keys, ${revocations.revokedScanIds.length} revoked scans)`);
  } else {
    console.log(`• Signed Revocations (/.well-known/revocations.json): \x1b[33m○ NOT PUBLISHED YET\x1b[0m`);
  }

  // 3. Signature + decision (signed payload only)
  const result = await lib.evaluateCertificate(cert, cleanDomain, {
    minScore,
    jwksUrl,
    revokedKids: revocations.revokedKids,
    revokedScanIds: revocations.revokedScanIds,
  });
  const sig = result.signature;

  // 3. Informational, non-gating checks
  const dns = await lib.checkDnsChallenge(cleanDomain, cert.dnsChallenge);
  console.log(`• DNS-01 Ownership TXT (_proof-verify.${cleanDomain}): ${DNS_LABEL[dns.status]} — ${dns.detail}`);
  const llmsCheck = await lib.fetchUrl(`https://${cleanDomain}/llms.txt`, 'text/markdown, text/plain');
  console.log(`• LLM Routing Index (https://${cleanDomain}/llms.txt): ${llmsCheck.status === 200 ? '\x1b[32m✔ 200 OK\x1b[0m' : `\x1b[33m✖ ${llmsCheck.status}\x1b[0m`}`);
  const agentCheck = await lib.fetchUrl(`https://${cleanDomain}/.well-known/agent.json`, 'application/json');
  console.log(`• A2A Agent Card (https://${cleanDomain}/.well-known/agent.json): ${agentCheck.status === 200 ? '\x1b[32m✔ 200 OK\x1b[0m' : `\x1b[33m✖ ${agentCheck.status}\x1b[0m`}`);
  console.log('  (DNS, llms.txt and agent.json are informational and do not change the exit code)');

  console.log('─────────────────────────────────────────────────────────────────────────────');
  if (!sig.valid) {
    console.log(`\x1b[1m\x1b[31m${lib.SIGNATURE_FAIL}\x1b[0m (${sig.reason})`);
    console.log('\x1b[1m\x1b[31mSTATUS: UNVERIFIED\x1b[0m\n');
    process.exit(1);
  }
  if (result.status === 'UNVERIFIED') {
    console.log(`\x1b[1m\x1b[31mFAIL: ${result.reason}\x1b[0m`);
    console.log('\x1b[1m\x1b[31mSTATUS: UNVERIFIED\x1b[0m\n');
    process.exit(1);
  }

  const p = result.payload;
  console.log(`  • Status         : ${result.status}`);
  console.log(`  • Domain         : ${p.domain}`);
  console.log(`  • PROOF Score    : ${result.score}/100 (certified: ${p.certified ? 'yes' : 'no'}, min required: ${minScore})`);
  console.log(`  • Audited At     : ${p.auditedAt}`);
  console.log(`  • Expires At     : ${p.expiresAt} (${p.tier || 'snapshot'})`);
  console.log(`  • SHA-256 Digest : ${cert.attestation.digest}`);
  if (p.claimRoot) console.log(`  • Merkle Claims  : ${p.claimRoot}`);
  if (sig.keySource === 'pinned') {
    console.log(`  • Ed25519        : \x1b[32mVALID\x1b[0m — signature verified against pinned key ${sig.kid}; certificate fetched online`);
  } else {
    console.log(`  • Ed25519        : \x1b[31mVALID against UNPINNED KEY (insecure)\x1b[0m — key ${sig.kid} fetched from ${jwksUrl}`);
  }
  console.log(`  • Public Cert    : ${cert.certificateUrl}`);
  console.log(`  • Live Badge     : ${cert.badgeUrl}\n`);

  process.exit(result.ok ? 0 : 1);
}

runAudit().catch((e) => {
  console.error(`\x1b[31mFAIL: unexpected error (${e && e.message})\x1b[0m`);
  process.exit(1);
});
