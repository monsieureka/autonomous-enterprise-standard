#!/usr/bin/env node
/**
 * proof-xray-mcp: Zero-dependency Model Context Protocol (MCP) stdio server for PROOF-VC v2.
 * Exposes Ed25519-verified (pinned key) domain certification, signed Merkle snapshot, and Causal GEO Benchmark
 * directly to Claude Desktop, Claude Code, Cursor, and Antigravity — zero npm install required.
 *
 * Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com) — MIT License
 */

const readline = require('node:readline');
const lib = require('../lib/verify');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'proof-xray-mcp', version: lib.VERSION };
// Optional INSECURE key-rotation opt-in (see README): `--jwks-url <url>` or env PROOF_JWKS_URL.
const JWKS_URL = lib.resolveJwksUrl(process.argv.slice(2));
const VERIFY_OPTS = { jwksUrl: JWKS_URL };
const KEY_WARNINGS = JWKS_URL ? [lib.UNPINNED_WARNING] : [];
if (JWKS_URL) process.stderr.write(`${lib.UNPINNED_WARNING}\n`);
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function normalizeDomain(raw) {
  if (typeof raw !== 'string') return null;
  const clean = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .replace(/:\d+$/, '')
    .replace(/^www\./, '')
    .replace(/\.$/, '');
  return DOMAIN_RE.test(clean) ? clean : null;
}

const MCP_USER_AGENT = `proof-xray-mcp/${lib.VERSION}`;

async function fetchJson(url, accept = 'application/json') {
  const res = await lib.fetchUrl(url, accept, 3, MCP_USER_AGENT);
  return { status: res.status, data: res.data && typeof res.data === 'object' ? res.data : null };
}

const TOOLS = [
  {
    name: 'verify_domain_proof',
    description:
      'Verify a domain against the PROOF X-Ray PROOF-VC v2 protocol: fetches the root-homepage certificate online and verifies its Ed25519 signature against a pinned public key (fails closed: no valid signature => not certified). Also reports the DNS-01 _proof-verify TXT check (verified / not_verified / not_checked; informational).',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Domain name or URL to verify (e.g. proofxray.com)' },
      },
      required: ['domain'],
    },
  },
  {
    name: 'get_transparency_log',
    description:
      'Fetch the PROOF signed Merkle snapshot (/.well-known/transparency-log.json; not an append-only log), verify its Ed25519 signature against the pinned public key (entries are returned only if the signature is valid), and optionally look up a specific certified domain.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Optional domain to inspect inside the signed Merkle snapshot' },
      },
    },
  },
  {
    name: 'get_causal_geo_benchmark',
    description:
      'Fetch the public anonymized GEO benchmark endpoint (/api/public/v1/benchmark). Experimental: collecting until the n >= 30 publication threshold.',
    inputSchema: { type: 'object', properties: {} },
  },
];

async function handleToolCall(name, args = {}) {
  if (name === 'verify_domain_proof') {
    const domain = normalizeDomain(args.domain);
    if (!domain) return { isError: true, data: { error: 'Invalid domain parameter.' } };
    const certRes = await fetchJson(`https://www.proofxray.com/api/public/v1/certificate?domain=${encodeURIComponent(domain)}`);
    if (certRes.status !== 200 || !certRes.data || certRes.data.status !== 'verified') {
      return {
        isError: false,
        data: {
          domain,
          status: 'unverified',
          certified: false,
          reason: 'no_completed_audit',
          dns: { status: 'not_checked', detail: 'no certificate to compare against' },
          auditUrl: lib.AUDIT_URL,
          auditHint: lib.auditGuidance(domain).join(' '),
          ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}),
        },
      };
    }
    const cert = certRes.data;
    const revocations = await lib.fetchAndVerifyRevocations(VERIFY_OPTS);
    if (revocations.status === 'failed') {
      return {
        isError: false,
        data: {
          domain,
          status: 'unverified',
          certified: false,
          reason: revocations.reason,
          revocations: { status: 'failed', reason: revocations.reason },
          ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}),
        },
      };
    }
    const result = await lib.evaluateCertificate(cert, domain, {
      ...VERIFY_OPTS,
      revokedKids: revocations.revokedKids,
      revokedScanIds: revocations.revokedScanIds,
    });
    const dns = await lib.checkDnsChallenge(domain, cert.dnsChallenge);
    const signature = {
      valid: result.signature.valid,
      reason: result.signature.reason,
      ...(result.signature.kid ? { kid: result.signature.kid } : {}),
      ...(result.signature.keySource ? { keySource: result.signature.keySource } : {}),
      note: result.signature.valid && result.signature.keySource === 'pinned'
        ? `signature verified against pinned key ${result.signature.kid}; certificate fetched online`
        : (result.signature.valid ? 'UNPINNED KEY (insecure)' : lib.SIGNATURE_FAIL),
    };
    if (result.status === 'UNVERIFIED') {
      return {
        isError: false,
        data: {
          domain,
          status: 'unverified',
          certified: false,
          reason: result.reason,
          ed25519: signature,
          dns,
          ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}),
        },
      };
    }
    const p = result.payload;
    return {
      isError: false,
      data: {
        domain: p.domain,
        status: result.ok ? 'certified' : 'audited',
        certified: result.ok,
        score: result.score,
        tier: p.tier,
        auditedAt: p.auditedAt,
        expiresAt: p.expiresAt,
        injectionFree: p.injectionFree,
        ...(cert.dualViewVerified !== undefined ? { dualViewVerified: cert.dualViewVerified } : {}),
        dnsAnchored: dns.status === 'verified',
        dns,
        claimRoot: p.claimRoot,
        revocations: {
          status: revocations.status,
          revokedKidsCount: revocations.revokedKids.length,
          revokedScanIdsCount: revocations.revokedScanIds.length,
        },
        ed25519: signature,
        certificateUrl: cert.certificateUrl,
        badgeUrl: cert.badgeUrl,
        ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}),
      },
    };
  }

  if (name === 'get_transparency_log') {
    const res = await fetchJson('https://www.proofxray.com/.well-known/transparency-log.json');
    if (res.status !== 200 || !res.data) {
      return { isError: true, data: { error: `Transparency log HTTP ${res.status}` } };
    }
    const log = res.data;
    const sth = await lib.verifyEnvelope(log.signedTreeHead, VERIFY_OPTS);
    if (!sth.valid) {
      return { isError: true, data: { error: lib.SIGNATURE_FAIL, reason: sth.reason, ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}) } };
    }
    const filter = args.domain ? normalizeDomain(args.domain) : null;
    const entry = filter && Array.isArray(log.entries) ? log.entries.find((e) => e.domain === filter) || null : undefined;
    return {
      isError: false,
      data: {
        protocol: log.protocol,
        date: log.date,
        entryCount: log.entryCount,
        merkleRoot: log.merkleRoot,
        signedTreeHead: { valid: true, kid: sth.kid, keySource: sth.keySource },
        ...(KEY_WARNINGS.length ? { warnings: KEY_WARNINGS } : {}),
        ...(filter ? { lookupDomain: filter, entry } : { sampleDomains: (log.entries || []).slice(0, 10).map((e) => ({ domain: e.domain, score: e.score })) }),
      },
    };
  }

  if (name === 'get_causal_geo_benchmark') {
    const res = await fetchJson('https://www.proofxray.com/api/public/v1/benchmark');
    if (res.status !== 200 || !res.data) {
      return { isError: true, data: { error: `Benchmark HTTP ${res.status}` } };
    }
    return { isError: false, data: res.data };
  }

  return { isError: true, data: { error: `Unknown tool: ${name}` } };
}

function send(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

async function handleRequest(req) {
  if (!req || typeof req !== 'object') return;
  const { id, method, params } = req;
  if (method === 'notifications/initialized') return;
  if (method === 'initialize') {
    return send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      },
    });
  }
  if (method === 'ping') {
    return send({ jsonrpc: '2.0', id, result: {} });
  }
  if (method === 'tools/list') {
    return send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  }
  if (method === 'tools/call') {
    const out = await handleToolCall(params?.name, params?.arguments);
    return send({
      jsonrpc: '2.0',
      id,
      result: {
        content: [{ type: 'text', text: JSON.stringify(out.data, null, 2) }],
        isError: out.isError,
      },
    });
  }
  if (id !== undefined) {
    send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    void handleRequest(JSON.parse(trimmed));
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
});
