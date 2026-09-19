# ScamShield — Hackathon Submission Kit

## One-line pitch

**ScamShield turns suspicious messages into explainable evidence and safer next steps—without sending private text to an AI service.**

## The 90-second demo script

### 0:00–0:12 — The problem

“Scams do not win because people are careless. They win because the message creates pressure before the person has time to verify it. Today, most tools only say ‘scam’ or ‘not scam.’ That leaves the user anxious and unsure what to do next.”

### 0:12–0:25 — The product

“This is ScamShield. It is a local-first security coach: paste a suspicious message, and it shows the evidence behind the risk—not a mysterious black-box verdict.”

Click **Run judge demo**. This loads the bank-alert scenario and brings the analysis workspace into view.

### 0:25–0:52 — The analysis

“Here is a fake bank message. ScamShield identifies four signals: artificial urgency, a credential request, a lookalike domain, and a reply-to action. The risk score is high, but the important part is the explanation: each flag quotes the evidence a person can recognize for themselves.”

Point to the evidence chips: “URGENT,” “Verify your identity,” “secure-firstnational,” and “Reply YES.”

### 0:52–1:12 — The action

“Detection is only half the job. ScamShield gives the user a safe sequence: do not click or reply, open the organization’s official app directly, then block and report the sender. The product teaches a reusable habit: don’t use their link—use your own.”

### 1:12–1:27 — The technical decision

“For this MVP, we chose readable browser-side heuristics instead of pretending to have perfect AI detection. The rules are transparent, fast, and private. The architecture is ready to grow into OCR, reputation APIs, and a more advanced classifier without changing the user flow.”

### 1:27–1:35 — The close

“ScamShield does not just label a threat. It gives people back the few seconds they need to make a safer decision.”

## Devpost project description

### What we built

ScamShield is an explainable phishing and scam detector for everyday users. It analyzes suspicious messages and URLs for common social-engineering signals, shows the evidence in plain English, and recommends a safe next action.

### Why it matters

Phishing and scam messages are designed to create urgency, uncertainty, and fear. A binary warning is not enough: people need to understand why something is suspicious and what to do next. ScamShield makes that decision process visible and approachable.

### What makes it different

ScamShield is **explainable by design** and **private by default**. The MVP runs its signal scan in the browser with readable heuristics for urgency, credential requests, payment language, shortened links, lookalike domains, and reply-to actions. It does not require an account or send message content to an AI API.

### Technologies used

React, TypeScript, Vite, Tailwind CSS, Lucide icons, and browser-side deterministic heuristics. The project is structured as a small static frontend that can be cloned and run with `pnpm install` and `pnpm dev`.

### Future direction

The next layer would add OCR for screenshots, domain reputation and certificate checks, and a privacy-preserving classifier that can support the same explainable signal model. The core product principle remains unchanged: show the evidence, then show the safest move.

## Judging criteria mapping

| Criterion | What to emphasize |
| --- | --- |
| Impact & relevance | Everyone receives suspicious messages; the product targets phishing, online safety, and digital security directly. |
| Technical implementation | Functional React prototype, deterministic scan engine, reusable UI, responsive layout, and no API-key dependency. |
| Innovation & creativity | Moves beyond “scam / not scam” into explainable evidence plus an action plan; uses local-first privacy as a product feature. |
| User experience & design | Calm editorial security-desk interface, readable language, sample scenarios, privacy note, and one-click judge demo. |
| Presentation & demo | The strongest scenario is preloaded in one click and can be explained in under 90 seconds. |

## Honest limitations to disclose

ScamShield is a prototype signal system, not a guarantee of safety. A low-risk result does not prove a message is legitimate. Users should verify unexpected requests through an independent trusted channel. The screenshot tab is currently a guided placeholder for the next OCR iteration.

## AI and external tools disclosure

AI-assisted development was used for ideation, interface refinement, and code drafting. The runtime prototype does not send user content to an AI API. Its visible scan result is produced by readable browser-side heuristics. No external images or proprietary datasets are required.
