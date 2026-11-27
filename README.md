# The Autonomous International Enterprise (EAI) Standard v1.0

**The Open Cryptographic Standard for AI Agent Trust, Deterministic GEO, and Sovereign Solo-Scale Operations.**

[![PROOF Verified](https://www.proofxray.com/api/badge?domain=proofxray.com)](https://www.proofxray.com/certifie/proofxray.com)
[![npm version](https://img.shields.io/npm/v/proof-verify)](https://www.npmjs.com/package/proof-verify)
[![License: MIT](https://img.shields.io/badge/License-MIT-B6FF00.svg)](./LICENSE)
[![RFC 7517](https://img.shields.io/badge/RFC-7517%20(JWK)-111312)](https://www.rfc-editor.org/rfc/rfc7517)

**Disambiguation:** PROOF X-Ray (`proofxray.com`) is deterministic SEO, GEO (Generative Engine Optimization) and AI-visibility website-audit software. It has no connection with medical X-ray equipment, radiology, healthcare imaging, or CERN ROOT/PROOF.

## Quick start: verify a domain in 2 seconds

No account, no API key, no configuration.

```bash
npx proof-verify proofxray.com
```

The command fetches the public certificate, checks its Ed25519 signature against a key pinned in the package, and exits with `0` only if the certificate is valid, unexpired, certified and at or above the minimum score. The score changes with each audit; the result is a dated snapshot.

A domain that has not been audited exits with code `1` and a link to the free audit. Prefer Python with no npm? `git clone` this repo, then `python3 bin/proof-verify.py proofxray.com` (pure-Python RFC 8032 Ed25519 fallback, no dependency).

## The official book (physical reference)

***The Autonomous International Enterprise*** by **Arthur Mellin**, founder of PROOF X-Ray. The book sets out the EAI standard in English.

- **Hardcover:** [amazon.com/dp/B0HSXSVJGV](https://www.amazon.com/dp/B0HSXSVJGV) · ASIN `B0HSXSVJGV` · ISBN-13 `9798145890198`
- **Kindle:** [amazon.com/dp/B0HJM4F6G3](https://www.amazon.com/dp/B0HJM4F6G3) · ASIN `B0HJM4F6G3`

## AI agent integration (official MCP server)

Three lines are enough to give Claude Desktop, Cursor or any MCP client the verifier as tools (`verify_domain_proof`, `get_transparency_log`, `get_causal_geo_benchmark`):

```bash
claude mcp add proof-verify -- npx -y -p proof-verify proof-mcp
```

For Claude Desktop or Cursor, add to the client configuration:

```json
{
  "mcpServers": {
    "proof-verify": { "command": "npx", "args": ["-y", "-p", "proof-verify", "proof-mcp"] }
  }
}
```

The server is published in the [official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.monsieureka/proof-verify) and listed on [Glama](https://glama.ai/mcp/servers/monsieureka/autonomous-enterprise-standard).

## Philosophy and architecture

**The proof before the promise.** Every measurement is deterministic: eight signal categories, read from the public HTML, without executing JavaScript. The same input gives the same result, and the method is published.

- **Offline verification.** Certificates are signed with Ed25519. The public keys are published at [`/.well-known/jwks.json`](https://www.proofxray.com/.well-known/jwks.json) (RFC 7517) and pinned in the CLI, so a signature can be checked without trusting the vendor or the network.
- **Transparency log.** Issued certificates are recorded in a signed transparency log.
- **CI integration.** The official GitHub Action, [proof-autonomous-enterprise-verifier](https://github.com/marketplace/actions/proof-autonomous-enterprise-verifier), verifies a certificate in a workflow.

No measurement promises a ranking, a citation by an AI assistant, or a commercial result.

---

## Reference

## Use it in CI in 10 seconds

```yaml
- uses: monsieureka/autonomous-enterprise-standard@v1.0.1
  with:
    domain: example.com
    min_score: '80'
```
The step fails unless the domain's certificate has a valid pinned-key Ed25519 signature, is not expired, is certified and reaches `min_score`. It needs `python3` on the runner (present on GitHub-hosted Ubuntu runners).

## Security model & current limits

- **Single issuer today.** PROOF is the only signer. A certificate means "engine version X observed these signals on this public homepage at time T", signed by us. It is not a third-party attestation. The engine output, the Merkle root over the extracted facts (leaves are published, so you can recompute it) and both verifiers are public so that anyone can check a certificate or catch us out.
- **Offline-checkable signature, online fetch.** The certificate JSON is fetched over HTTPS; the signature is checked locally against a key pinned in the verifier. Rotating the key requires a new release of this package.
- **The transparency endpoint is a signed snapshot,** recomputed on request: no inclusion or consistency proofs, not an append-only log. It lists only certificates whose badge is still valid.
- **No ownership proof by default.** The DNS-01 anchor is optional and informational.
- **No promise about rankings or AI answers.** The score measures observable signals in public HTML. It is not a search ranking, a probability of being cited, or a revenue forecast.
- **Public by design.** A domain's certificate page shows its score, audit date and homepage findings. Ask `contact@proofxray.com` to have a page taken down.

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
| **Platform & Engine** | Deterministic raw-HTML SEO/GEO audit (~10s, zero JS) | [`proofxray.com/en`](https://www.proofxray.com/en) · [`Example Report`](https://www.proofxray.com/en/report) |
| **Public Certificate Page** | Live root-homepage verified certificate (FR & EN) | [`/en/certified/proofxray.com`](https://www.proofxray.com/en/certified/proofxray.com) · [`/certifie/proofxray.com`](https://www.proofxray.com/certifie/proofxray.com) |
| **PROOF-VC v2 JSON API** | JCS SHA-256 Merkle `claimRoot`, bounded TTL, DOM injection guard & Ed25519 signature | [`/api/public/v1/certificate?domain=proofxray.com`](https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com) |
| **Public Ed25519 JWKS** | Asymmetric verification keys (RFC 7517); the CLIs ship the current key pinned | [`/.well-known/jwks.json`](https://www.proofxray.com/.well-known/jwks.json) |
| **Signed Merkle snapshot** | Ed25519-signed Merkle root over active certified domains (recomputed snapshot, not an append-only log) | [`/.well-known/transparency-log.json`](https://www.proofxray.com/.well-known/transparency-log.json) |
| **Zero-Token Stapled VC** | Compact ~100-token signed entity & pricing attestation | [`/.well-known/proof-vc.json`](https://www.proofxray.com/.well-known/proof-vc.json) |
| **GEO Benchmark (experimental)** | Anonymized benchmark endpoint (`collecting` until `n >= 30` observations) | [`/api/public/v1/benchmark`](https://www.proofxray.com/api/public/v1/benchmark) |
| **Public Verification Badge** | SVG badge reflecting the last homepage audit; valid 7 days after it (30 days with active monitoring) | [`/api/badge?domain=proofxray.com`](https://www.proofxray.com/api/badge?domain=proofxray.com) |
| **Canonical EAI Page & Press** | Official canonical pages + press kits (EN & FR) | [`/en/autonomous-international-enterprise`](https://www.proofxray.com/en/autonomous-international-enterprise) · [`/en/press`](https://www.proofxray.com/en/press) · [`/entreprise-autonome-internationale`](https://www.proofxray.com/entreprise-autonome-internationale) |
| **LLM Routing Index** | High-density machine index + full specification | [`llms.txt`](https://www.proofxray.com/llms.txt) · [`llms-full.txt`](https://www.proofxray.com/llms-full.txt) |
| **A2A & Security (RFC 9116)** | Agent-to-Agent discovery card + security policy | [`agent.json`](https://www.proofxray.com/.well-known/agent.json) · [`security.txt`](https://www.proofxray.com/.well-known/security.txt) |
| **Technical Write-ups (`Dev.to`)** | Part 1: Ed25519 + DNS-01 + MCP · Part 2: Raw-HTML `57–66 → 79–85/100` benchmark | [`Part 1 (Architecture)`](https://dev.to/proofxray/how-i-built-a-cryptographically-verifiable-seo-ai-readiness-geo-standard-with-ed25519-dns-01-412c) · [`Part 2 (Raw HTML vs JS)`](https://dev.to/proofxray/why-js-rendered-smb-hotel-sites-score-57-66100-in-raw-html-and-how-we-reached-79-85-with-zero-3ci9) |

---

## 3. Canonical Machine Schema (W3C JSON-LD)

See [`schema/eai-v1.jsonld`](./schema/eai-v1.jsonld) for the machine-readable `DefinedTermSet`, `DefinedTerm`, and `CreativeWork` definitions implementing this ontology.

---

## 4. PROOF-VC v2 Verification Protocol & CLI Tooling

Autonomous AI agents can verify any audited domain deterministically via the live public API or the included Node.js / Python CLIs:

```bash
# Node.js (zero dependencies, native Ed25519)
node bin/cli.js proofxray.com

# Standalone Python 3 (zero dependencies, pure-Python RFC 8032 Ed25519 fallback)
python3 bin/proof-verify.py proofxray.com

# Or directly via npm:
npx proof-verify proofxray.com
```

### What the verifiers check, and how they fail

The certificate JSON is **fetched online**. Its Ed25519 attestation is then checked against a public key **pinned in the verifier** (matched by `kid`), so that step needs no network. The tools **fail closed**: exit code `1` (and `FAIL: no valid Ed25519 signature`) when the attestation is missing, malformed, has an unknown `kid`, a digest mismatch or an invalid signature. The score, `certified` flag, domain and expiry are read from the **signed payload**; unsigned top-level fields that disagree with it are rejected. Exit `0` only if the signature is valid, the certificate is not expired, `certified` is true and the score reaches `PROOF_MIN_SCORE` (default 80).

- The key URL written inside the attestation (`jwksUrl`) is **never** used. A missing `kid` is a failure (no fallback to "the first key").
- DNS-01 (`_proof-verify.<domain>`), `llms.txt` and `agent.json` are reported for information and **do not change the exit code**. The DNS check compares the token of the certificate's `dnsChallenge`; it prints `VERIFIED`, `NOT VERIFIED` or `NOT CHECKED` (resolver unreachable, or no usable challenge) and never claims verification it did not perform.
- Trusted keys live in the `PINNED_KEYS` array of `lib/verify.js` and `bin/proof-verify.py`. Currently: `proof-root-2026-11-24` (same key as the published JWKS at the time of writing).

**Key rotation.** To trust a new key, a maintainer adds `{ kid, x }` to both `PINNED_KEYS` arrays (values from `/.well-known/jwks.json`), bumps the version and publishes a new release. Old and new `kid` can be pinned side by side. Until users upgrade, they can opt in explicitly with `--jwks-url <url>` (or `PROOF_JWKS_URL`) to look up an unknown `kid` in that HTTPS JWKS; this prints a visible `UNPINNED KEY (insecure)` warning and the result is labelled as such. Never enable it in CI by default.

### Tests

```bash
npm test                                   # node --test  +  python3 -m unittest (no network needed)
node --test                                # JavaScript only
python3 -m unittest discover -s test -p "test_*.py" -v   # Python only
```

The tests generate a throwaway Ed25519 key and a signed fixture certificate; they cover valid, tampered, missing-attestation, unknown-kid and wrong-key cases. See also [`ci/README.md`](./ci/README.md).

### MCP server and CI
See the quick-start sections at the top of this file (Claude Desktop, Claude Code, Cursor; GitHub Action).

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

The EAI / GEO methodology is grounded in Arthur Mellin's published books (Amazon KDP):

- ***The Autonomous International Enterprise: The PROOF X-Ray Standard for Cryptographic Trust, AI Search (GEO/AEO), and Sovereign Solo-Scale Operations*** (2026, English) — Paperback ASIN `B0HSXSVJGV` ([Amazon.com](https://www.amazon.com/dp/B0HSXSVJGV)) · Kindle ASIN `B0HJM4F6G3` ([Amazon.com](https://www.amazon.com/dp/B0HJM4F6G3))
- ***Le SEO ne suffit plus*** (2026, French) — ISBN `9798167459038` (Broché) / `9798143487390` (Relié) · [Amazon.fr](https://www.amazon.fr/dp/B0HPHNC533)
- ***Travailler avec Claude*** (2026, French) — ISBN `9798167459458` (Broché) · [Amazon.fr](https://www.amazon.fr/dp/B0HQ8NQ6VG)
- ***L'IA au travail*** (2026, French) — ISBN `9798166046079` (Broché) / `9798140904432` (Relié) · [Amazon.fr](https://www.amazon.fr/dp/B0HQJSH4K2)
- Full catalog: [`https://www.proofxray.com/livre`](https://www.proofxray.com/livre)

---

## 6. Publisher, Legal Entity & Licensing

- **Author & Founder:** Arthur Mellin ([proofxray.com/a-propos](https://www.proofxray.com/a-propos))
- **Legal Entity:** Arthur Mellin — Entrepreneur Individuel (SIRET `509 969 622 00067`), 16 rue de la République, 95270 Chaumontel, France
- **Contact:** `contact@proofxray.com`
- **License:** [MIT License](./LICENSE) (code & specifications). See [TRADEMARKS.md](./TRADEMARKS.md) for trademark and root-key authority policy.
