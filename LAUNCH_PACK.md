# Kit de Lancement Vérifié : PROOF X-Ray & Standard EAI / PROOF-VC v2

> **Règle de vérité stricte :** Tous les liens, endpoints et snippets ci-dessous correspondent à du code déployé ; les liens et endpoints sont à revérifier avant publication.

---

## 1. Show HN (Hacker News — format texte brut prêt à coller, sans Markdown cassé)

**Optimal window:** Tuesday–Thursday, 14:30–16:30 Paris time (8:30–10:30 AM US East Coast).

**Title:**
Show HN: PROOF-VC v2 – Offline-verifiable Ed25519 web-audit & anti-cloaking spec for AI agents

**Text (plain text for HN — paste directly as-is):**
Hi HN,

I built PROOF X-Ray (https://www.proofxray.com) to audit how websites are actually read by search engines and AI crawlers (raw HTML without JS execution, 48 deterministic signals, rule-based scoring — unmeasured signals are explicitly marked unmeasured).

Today I'm open-sourcing the EAI v1.0 / PROOF-VC v2 specification, zero-dependency CLI verifiers (Node.js and pure-Python RFC 8032 Ed25519), and a zero-dependency MCP server under MIT:
https://github.com/monsieureka/autonomous-enterprise-standard

What is actually live right now:
- Free 10-second raw-HTML audit (international FR/EN/DE/ES, multi-currency, E.164 phones) + deterministic DOM prompt-injection & Unicode steganography guard + parallel Dual-View Anti-Cloaking check (bot vs Chrome UA)
- Public multi-domain certificate API: https://www.proofxray.com/api/public/v1/certificate?domain=proofxray.com
- Deterministic SHA-256 Merkle root over extracted entity facts (claimRoot), bounded TTL (7d free snapshot vs 30d continuous monitoring), DNS-01 ownership anchor (_proof-verify TXT), and Ed25519 signatures verifiable offline via https://www.proofxray.com/.well-known/jwks.json
- Ed25519-signed Merkle snapshot of listed domains (not an append-only log): https://www.proofxray.com/.well-known/transparency-log.json
- SVG badge reflecting the last homepage audit, with a 7-day expiry (30 days with active monitoring) (https://www.proofxray.com/api/badge?domain=proofxray.com)

Try it locally with zero dependencies (Node or Python 3):

  git clone https://github.com/monsieureka/autonomous-enterprise-standard
  node autonomous-enterprise-standard/bin/cli.js proofxray.com
  python3 autonomous-enterprise-standard/bin/proof-verify.py proofxray.com

Or connect the zero-dep MCP server directly in Claude Code / Cursor (`node mcp/server.js`).

Would love brutal technical feedback on the scoring invariants, Dual-View anti-cloaking guard, and Ed25519 / signed-snapshot schema.

---

## 2. Hacker News Profile Bio (`about` — texte brut HN)

```text
Founder of PROOF X-Ray (https://www.proofxray.com) — deterministic 48-signal HTML/GEO audits, Dual-View anti-cloaking & DOM prompt-injection guard, and offline-verifiable Ed25519 certificates (PROOF-VC v2).

Open-source MIT spec, zero-dep Node/Python verifiers & MCP server: https://github.com/monsieureka/autonomous-enterprise-standard
```

---

## 3. Thread X / Twitter

### Tweet 1
> AI agents reading raw web HTML face three silent failure modes:
> 1. Blindly trusting self-asserted `llms.txt` / JSON-LD
> 2. Indirect prompt injection hidden in DOM / Unicode tags
> 3. Bot-vs-human cloaking (fake prices/info shown to AI crawlers)
>
> Today we're open-sourcing **PROOF-VC v2** (MIT): deterministic HTML/GEO audits, Dual-View anti-cloaking, Ed25519-signed Merkle snapshot (not an append-only log) & zero-dep CLI/MCP verifiers.

### Tweet 2
> Every audited root homepage gets:
> - Live public certificate page (`/certifie/<domain>`)
> - Offline-verifiable Ed25519 attestation (`/.well-known/jwks.json`)
> - Signed Merkle snapshot (not an append-only log) (`/.well-known/transparency-log.json`)
> - SVG badge reflecting the last homepage audit, 7-day expiry (`/api/badge?domain=...`)
> - Zero-dep Node CLI, pure-Python RFC 8032 verifier & MCP server
>
> MIT repo: https://github.com/monsieureka/autonomous-enterprise-standard

---

## 4. Post LinkedIn (B2B & Presse)

> Les moteurs de réponse IA (ChatGPT Search, Perplexity, Claude, Gemini) lisent le HTML brut de votre site, sans exécuter JavaScript.
>
> Nous publions aujourd'hui en open-source (licence MIT) le protocole **EAI v1.0 / PROOF-VC v2**, ses vérificateurs CLI (Node + Python pur RFC 8032 sans dépendance) et son serveur **MCP** pour Claude / Cursor :
> - Audit déterministe en ~10 secondes sur 48 signaux SEO & GEO (ce qui n'est pas mesuré reste indiqué « non mesuré ») ;
> - Double pare-feu déterministe anti-injection de prompt DOM, anti-stéganographie Unicode et anti-cloaking Dual-View (robot vs navigateur) ;
> - Certificat public `/certifie/<domaine>` + racine Merkle des faits d'entité + signature asymétrique Ed25519 vérifiable hors-ligne (`/.well-known/jwks.json`) + instantané Merkle signé (pas un journal append-only) (`/.well-known/transparency-log.json`).
>
> Dépôt open-source : https://github.com/monsieureka/autonomous-enterprise-standard
> Diagnostic gratuit (10 s, sans inscription) : https://www.proofxray.com/
