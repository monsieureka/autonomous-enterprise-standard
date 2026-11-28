# Trademark & Certification Authority Policy

The code, schemas, and specifications in this repository are licensed under the standard OSI-approved [MIT License](./LICENSE).

Separately from the MIT copyright license on the Software:

1. **Trademarks:** The names **"PROOF X-Ray"**, **"PROOF X-Ray Verified"**, and the official PROOF X-Ray visual seal remain trademarks / trade names of **Arthur Mellin (EI — SIRET 509 969 622 00067, France)**. The MIT License does not grant trademark rights beyond fair, accurate attribution.
2. **Root Signing Authority:** Anyone is free to fork, study, or implement compatible verifiers and clients under the MIT License. However, only attestations signed by the official Ed25519 root key published at `https://www.proofxray.com/.well-known/jwks.json` represent an official **PROOF X-Ray Verified** certification. Third-party forks must publish their own JWKS endpoint and must not impersonate PROOF X-Ray.
3. **Disambiguation:** **PROOF X-Ray** (`proofxray.com`) is a server-side website-attestation and deterministic GEO standard (`/.well-known/agent.json`). It is unrelated to **Proof** (formerly Notarize, `proof.com`, creator of the `x401` user-identity protocol) or the `x402` payment protocol (Coinbase & Cloudflare).
