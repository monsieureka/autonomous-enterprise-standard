# PROOF Verified Dynamic Badge

The **PROOF Verified Badge** is an SVG badge reflecting the last homepage audit of a domain under the **Entreprise Autonome Internationale (EAI)** standard.

## 1. Quick Embed (HTML)

Add this snippet to your header, navigation bar, or footer:

```html
<a href="https://www.proofxray.com/entreprise-autonome-internationale" target="_blank" rel="noopener noreferrer">
  <img src="https://www.proofxray.com/api/badge?domain=YOUR_DOMAIN.com" alt="PROOF Verified Badge" width="168" height="32" />
</a>
```

## 2. Dynamic SVG & Dublin Core Metadata
Each badge request dynamically:
- Reflects the result of the last homepage audit (not a live re-computation); it expires 7 days after that audit, or 30 days with active monitoring.
- Injects HTTP `Link: <canonical>` and `X-Robots-Tag: all, index, follow` headers.
- Embeds Dublin Core / RDF semantic metadata inside the SVG for automated AI crawler parsing.
