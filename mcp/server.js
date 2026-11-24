#!/usr/bin/env node
/**
 * proof-xray-mcp: Zero-dependency Model Context Protocol (MCP) stdio server for PROOF-VC v2.
 * Exposes offline-verifiable Ed25519 domain certification, signed Merkle snapshot, and Causal GEO Benchmark
 * directly to Claude Desktop, Claude Code, Cursor, and Antigravity — zero npm install required.
 *
 * Copyright (c) 2026 Arthur Mellin / PROOF X-Ray (https://www.proofxray.com) — MIT License
 */

const https = require('node:https');
const crypto = require('node:crypto');
const readline = require('node:readline');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'proof-xray-mcp', version: '2.0.0' };
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

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

function fetchJson(url, accept = 'application/json', redirects = 3) {
  return new Promise((resolve) => {
    const req = https.get(
      url,
      { headers: { 'User-Agent': 'proof-xray-mcp/2.0.0', Accept: accept }, timeout: 8000 },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
          res.resume();
          return resolve(fetchJson(new URL(res.headers.location, url).toString(), accept, redirects - 1));
        }
        let raw = '';
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(raw) });
          } catch {
            resolve({ status: res.statusCode, data: null });
          }
        });
      },
    );
    req.on('timeout', () => { req.destroy(); resolve({ status: 408, data: null }); });
    req.on('error', () => resolve({ status: 500, data: null }));
  });
}

async function verifyEnvelopeOffline(envelope) {
  if (!envelope || !envelope.signature || envelope.signature.alg !== 'Ed25519') {
    return { checked: false, valid: false, reason: 'no_ed25519_attestation' };
  }
  const expectedDigest = crypto.createHash('sha256').update(canonicalJson(envelope.payload)).digest('hex');
  if (expectedDigest !== envelope.digest) {
    return { checked: true, valid: false, reason: 'digest_mismatch' };
  }
  const jwksRes = await fetchJson(envelope.signature.jwksUrl || 'https://www.proofxray.com/.well-known/jwks.json');
  const keys = Array.isArray(jwksRes.data?.keys) ? jwksRes.data.keys : [];
  const jwk = keys.find((k) => k.kid === envelope.signature.kid) || keys[0];
  if (!jwk) return { checked: true, valid: false, reason: 'jwks_key_not_found' };
  try {
    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const ok = crypto.verify(
      null,
      Buffer.from(`proof-vc-v2\n${expectedDigest}`, 'utf8'),
      pub,
      Buffer.from(envelope.signature.value, 'base64url'),
    );
    return { checked: true, valid: ok, reason: ok ? 'verified_offline' : 'invalid_signature', kid: jwk.kid };
  } catch (e) {
    return { checked: true, valid: false, reason: e.message };
  }
}

const TOOLS = [
  {
    name: 'verify_domain_proof',
    description:
      'Verify a domain against the live PROOF X-Ray PROOF-VC v2 protocol: fetches the root-homepage certificate, checks DNS-01 _proof-verify TXT ownership anchor, and verifies the Ed25519 signature offline against /.well-known/jwks.json.',
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
      'Fetch the PROOF signed Merkle snapshot (/.well-known/transparency-log.json; not an append-only log), verify its Ed25519 signature offline, and optionally look up a specific certified domain.',
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
      'Fetch the public anonymized Causal GEO Citation Benchmark (/api/public/v1/benchmark) measuring real ChatGPT & Perplexity citation lift with exact Wilson 95% confidence intervals.',
    inputSchema: { type: 'object', properties: {} },
  },
];

async function handleToolCall(name, args = {}) {
  if (name === 'verify_domain_proof') {
    const domain = normalizeDomain(args.domain);
    if (!domain) return { isError: true, data: { error: 'Invalid domain parameter.' } };
    const [certRes, dohRes] = await Promise.all([
      fetchJson(`https://www.proofxray.com/api/public/v1/certificate?domain=${encodeURIComponent(domain)}`),
      fetchJson(`https://cloudflare-dns.com/dns-query?name=_proof-verify.${encodeURIComponent(domain)}&type=TXT`, 'application/dns-json'),
    ]);
    const answers = Array.isArray(dohRes.data?.Answer) ? dohRes.data.Answer : [];
    const dnsAnchored = answers.some((a) => String(a.data || '').includes('proof-v2='));
    if (certRes.status !== 200 || !certRes.data || certRes.data.status !== 'verified') {
      return {
        isError: false,
        data: {
          domain,
          status: 'unverified',
          dnsAnchored,
          auditUrl: 'https://www.proofxray.com/#audit-gratuit',
        },
      };
    }
    const cert = certRes.data;
    const ed25519 = cert.attestation ? await verifyEnvelopeOffline(cert.attestation) : { checked: false, valid: false };
    return {
      isError: false,
      data: {
        domain: cert.domain,
        status: cert.certified && (!ed25519.checked || ed25519.valid) ? 'certified' : 'audited',
        certified: Boolean(cert.certified && (!ed25519.checked || ed25519.valid)),
        score: cert.score,
        tier: cert.tier,
        auditedAt: cert.auditedAt,
        expiresAt: cert.expiresAt,
        expired: cert.expired,
        injectionFree: cert.injectionFree,
        ...(cert.dualViewVerified !== undefined ? { dualViewVerified: cert.dualViewVerified } : {}),
        dnsAnchored,
        claimRoot: cert.claimRoot,
        ed25519Offline: ed25519,
        certificateUrl: cert.certificateUrl,
        badgeUrl: cert.badgeUrl,
      },
    };
  }

  if (name === 'get_transparency_log') {
    const res = await fetchJson('https://www.proofxray.com/.well-known/transparency-log.json');
    if (res.status !== 200 || !res.data) {
      return { isError: true, data: { error: `Transparency log HTTP ${res.status}` } };
    }
    const log = res.data;
    const sth = log.signedTreeHead ? await verifyEnvelopeOffline(log.signedTreeHead) : { checked: false, valid: false };
    const filter = args.domain ? normalizeDomain(args.domain) : null;
    const entry = filter && Array.isArray(log.entries) ? log.entries.find((e) => e.domain === filter) || null : undefined;
    return {
      isError: false,
      data: {
        protocol: log.protocol,
        date: log.date,
        entryCount: log.entryCount,
        merkleRoot: log.merkleRoot,
        signedTreeHeadOffline: sth,
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
