# ScamShield

**Pause. Check. Stay safer.**

ScamShield is an explainable phishing and scam detector built for the TLN Cybersecurity Challenge 2026. It helps people move from “this feels suspicious” to a clear, safer next step.

## What it does

- Inspects suspicious messages and URLs for common scam patterns.
- Explains every warning with plain-English evidence.
- Gives a prioritized next-step checklist instead of only showing a score.
- Includes sample scenarios for a fast demo: bank alert, delivery text, and suspicious link.
- Keeps this prototype local-first: the scan runs in the browser and does not require an account or API key.

## Demo flow

1. Open the app.
2. Choose **Bank alert** under “Try a sample.”
3. Select **Analyze for red flags**.
4. Walk through the risk score, evidence chips, and safer-action checklist.
5. Try **Delivery text** or **Suspicious link** to show the same workflow on another threat.

## Tech stack

- React 19
- TypeScript
- Vite
- Tailwind CSS 4
- Lucide icons
- Browser-side deterministic heuristics for the MVP

## Run locally

```bash
pnpm install
pnpm dev
```

For a production build:

```bash
pnpm check
pnpm build
```

## Simple structure

```text
client/
  index.html              # page metadata and fonts
  src/
    pages/Home.tsx        # main product screen and scan logic
    index.css             # design system and responsive styling
    App.tsx               # app shell and routing
    components/ui/        # reusable scaffold components
server/
  index.ts                # static production server from the scaffold
README.md
package.json
```

The product MVP intentionally keeps its core logic in one readable page so a judge can understand the demo quickly. The scaffold’s reusable UI components remain available if the project grows into a multi-page product.

## Important limitation

This is a prototype signal system, not a guarantee of safety. A low-risk result does not prove a message is legitimate. Users should always verify unexpected requests through a trusted channel.

## AI and external tools disclosure

AI-assisted development was used for ideation, interface refinement, and code drafting. The runtime prototype does **not** send user content to an AI API. Its visible scan result is produced by readable browser-side heuristics for urgency, credential requests, payment language, shortened links, lookalike domains, and reply-to actions. No external images or proprietary datasets are required.

## License

MIT
