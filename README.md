# The Autonomous International Enterprise (AIE / EAI) Standard — v1.0 & PROOF-VC v2

[![PROOF Verified](https://www.proofxray.com/api/badge?domain=proofxray.com)](https://www.proofxray.com/certifie/proofxray.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-B6FF00.svg)](./LICENSE)
[![Standard: W3C Schema.org](https://img.shields.io/badge/Standard-W3C%20Schema.org-111312.svg)](./schema/eai-v1.jsonld)

> **Canonical open specification of L'Entreprise Autonome Internationale (EAI) / The Autonomous International Enterprise (AIE)** and the **PROOF-VC v2** verifiable web-audit protocol, formalized by **Arthur Mellin** (founder of [PROOF X-Ray](https://www.proofxray.com/)).
>
> **Disambiguation:** PROOF X-Ray (`proofxray.com`) is a deterministic SEO, GEO (Generative Engine Optimization), and AI-visibility software platform. It has no connection with medical X-ray equipment, radiology, or healthcare imaging.

---

## 1. Formal Definition (EAI / AIE v1.0)

In the framework designed by **Arthur Mellin**, an **Autonomous International Enterprise (AIE)** — *Entreprise Autonome Internationale (EAI)* — is an organization operated by **1 to 3 humans** that combines:

1. **Deterministic software rules & verifiable protocols** (public HTML auditing, automated payments, deterministic verification of signed claims).
2. **AI agents & machine-readable distribution** (`llms.txt`, `llms-full.txt`, W3C `Schema.org` `@graph`, and `/.well-known/agent.json` A2A discovery).
3. **End-to-end autonomy across at least two countries** on the same core offer, from organic & AI-engine acquisition to automated delivery.

---

## 2. Pilot Case #001 — PROOF X-Ray (`proofxray.com`)

**PROOF X-Ray** is the live empirical reference implementation (**Cas Pilote EAI #001**) of this standard:

| Pillar | Live Implementation | Endpoint / Proof |
| :--- | :--- | :--- |
| **Platform & Engine** | Deterministic 48-signal / 8-category HTML audit (~10s, zero JS) | [`https://www.proofxray.com/`](https://www.proofxray.com/) |
| **Public Certificate Page** | Live root-homepage verified certificate | [`https://www.proofxray.com/certifie/proofxray.com`](https://www.proofxray.com/certifie/proofxray.com) |
| **PROOF-VC v2 JSON API** | JCS SHA-256 Merkle `claimRoot`, bounded TTL, DOM injection guard & Ed25519 signature | [`/api/public/v1/certificate?domain=proofxray.com`](https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com) |
| **Public Ed25519 JWKS** | Offline asymmetric verification keys (RFC 7517) | [`/.well-known/jwks.json`](https://www.proofxray.com/.well-known/jwks.json) |
| **Signed Merkle snapshot** | Ed25519-signed Merkle root over listed domains (a signed snapshot, not an append-only log; it may include expired or alerting domains) | [`/.well-known/transparency-log.json`](https://www.proofxray.com/.well-known/transparency-log.json) |
| **Zero-Token Stapled VC** | Compact ~100-token signed entity & pricing attestation | [`/.well-known/proof-vc.json`](https://www.proofxray.com/.well-known/proof-vc.json) |
| **GEO Benchmark (experimental)** | Experimental: anonymized benchmark endpoint, no measured sample yet (`sampleSize` 0) | [`/api/public/v1/benchmark`](https://www.proofxray.com/api/public/v1/benchmark) |
| **Public Verification Badge** | SVG badge reflecting the last homepage audit; valid 7 days after it (30 days with active monitoring) | [`/api/badge?domain=proofxray.com`](https://www.proofxray.com/api/badge?domain=proofxray.com) |
| **Canonical EAI Page & Press** | Official French canonical page + press kit | [`/entreprise-autonome-internationale`](https://www.proofxray.com/entreprise-autonome-internationale) · [`/presse`](https://www.proofxray.com/presse) |
| **LLM Routing Index** | High-density machine index + full specification | [`llms.txt`](https://www.proofxray.com/llms.txt) · [`llms-full.txt`](https://www.proofxray.com/llms-full.txt) |
| **A2A & Security (RFC 9116)** | Agent-to-Agent discovery card + security policy | [`agent.json`](https://www.proofxray.com/.well-known/agent.json) · [`security.txt`](https://www.proofxray.com/.well-known/security.txt) |

---

## 3. Canonical Machine Schema (W3C JSON-LD)

See [`schema/eai-v1.jsonld`](./schema/eai-v1.jsonld) for the machine-readable `DefinedTermSet`, `DefinedTerm`, and `CreativeWork` definitions implementing this ontology.

---

## 4. PROOF-VC v2 Verification Protocol & CLI Tooling

Autonomous AI agents can verify any audited domain deterministically via the live public API or the included Node.js / Python CLIs:

```bash
# Node.js (zero dependencies, native Ed25519 JWKS verification)
node bin/cli.js proofxray.com

# Standalone Python 3 (zero dependencies, pure-Python RFC 8032 Ed25519 verification)
python3 bin/proof-verify.py proofxray.com
```

### Zero-Dependency MCP Server (Claude Code, Claude Desktop, Cursor, Antigravity)
Connect PROOF-VC v2 directly to any MCP client with **zero `npm install`**:
```json
{
  "mcpServers": {
    "proof-xray": {
      "command": "node",
      "args": ["/path/to/autonomous-enterprise-standard/mcp/server.js"]
    }
  }
}
```
Exposes `verify_domain_proof`, `get_transparency_log` (offline verification of the snapshot signature), and `get_causal_geo_benchmark`.

### Live API Query
```http
GET https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com HTTP/1.1
Host: www.proofxray.com
Accept: application/json
```

### Draft Specifications (Proposals — Not Active On-Chain Services)
- [`schema/dns-handshake.md`](./schema/dns-handshake.md) — RFC Draft for optional DNS-01 ownership anchor (`_proof-verify`) and offline Ed25519 JWKS verification.
- [`schema/IProofOracle.sol`](./schema/IProofOracle.sol) — RFC Draft Solidity interface (EIP-712 ECDSA bridge proposal).
- [`schema/AGENTIC_HANDOVER_PROTOCOL.md`](./schema/AGENTIC_HANDOVER_PROTOCOL.md) — Deterministic JSON session handover spec (`agent_state.json`).

---

## 5. Published Reference Works by Arthur Mellin

The EAI / GEO methodology is grounded in Arthur Mellin's published books (Amazon KDP, registered ISBNs):

- ***Le SEO ne suffit plus*** (2026) — ISBN `9798167459038` (Broché) / `9798143487390` (Relié) · [Amazon](https://www.amazon.fr/dp/B0HPHNC533)
- ***Travailler avec Claude*** (2026) — ISBN `9798167459458` (Broché) · [Amazon](https://www.amazon.fr/dp/B0HQ8NQ6VG)
- ***L'IA au travail*** (2026) — ISBN `9798166046079` (Broché) / `9798140904432` (Relié) · [Amazon](https://www.amazon.fr/dp/B0HQJSH4K2)
- Full catalog: [`https://www.proofxray.com/livre`](https://www.proofxray.com/livre)

---

## 6. Publisher, Legal Entity & Licensing

- **Author & Founder:** Arthur Mellin ([proofxray.com/a-propos](https://www.proofxray.com/a-propos))
- **Legal Entity:** Arthur Mellin — Entrepreneur Individuel (SIRET `509 969 622 00067`), 16 rue de la République, 95270 Chaumontel, France
- **Contact:** `contact@proofxray.com`
- **License:** [MIT License](./LICENSE) (code & specifications). See [TRADEMARKS.md](./TRADEMARKS.md) for trademark and root-key authority policy.
