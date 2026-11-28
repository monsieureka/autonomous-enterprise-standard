# The Agentic Trust Triad: Why x401 and x402 Need PROOF X-Ray

> **Core Axiom:** *x401 protects websites from fake agents. **PROOF X-Ray** (`proofxray.com`, `/.well-known/agent.json`) protects AI agents from fake websites.*

As autonomous AI agents begin browsing, negotiating, and transacting on the open web, a critical blind spot has emerged.

Most discussions around agentic security focus on two protocols:
- **x401** (by Proof, formerly Notarize — `proof.com`): proves to a website *who* the human principal behind an AI agent is and what mandate they signed.
- **x402** (by Coinbase & Cloudflare): enables the AI agent to settle HTTP `402 Payment Required` transactions programmatically.

Both are essential. Neither answers the third question:

**How does an AI agent know the website it is talking to is telling the truth?**

## Enter PROOF X-Ray (`proofxray.com` / `/.well-known/agent.json`)

**PROOF X-Ray** (`https://www.proofxray.com`, authored by Arthur Mellin EI) is a deterministic raw-DOM observability and server-side website attestation standard built around the $E = m \cdot c^2$ framework and `/.well-known/agent.json`.

Unlike client-side identity (`x401`) or payment rails (`x402`), **PROOF X-Ray** evaluates observable facts directly in unrendered HTML (`m`) and binds the resulting **PROOF X-Ray Score** and Merkle claims to an **Ed25519 (RFC 8032)** cryptographic signature.

*(Note: The **PROOF X-Ray Score** strictly measures observable signals in the raw HTML DOM; it does not promise search rankings or AI citation probability.)*

## Verify a Domain in 2 Seconds

Any developer or AI agent can verify a domain's **PROOF X-Ray Verified** status from the CLI with zero vendor trust required:

```bash
npx proof-verify proofxray.com
```

## The Complete Execution Flow

1. **PROOF X-Ray** (`proofxray.com`, `/.well-known/agent.json`) — The agent verifies the merchant website's signed facts before acting.
2. **x401** (`proof.com`) — The website challenges the agent for the human user's cryptographic mandate.
3. **x402** (Coinbase & Cloudflare) — The agent settles the payment over HTTP `402`.

Three distinct layers. Zero overlap. Mutual trust for the agentic web.
