# Second Look

**Paste a suspicious text, email, or link. Get a plain-language answer in one second: is this a scam, why, and what to do next.**
Built for older adults and the people who look out for them. Runs 100% on your device. Nothing you paste is ever uploaded.

🔗 **Live app:** https://venkatagaddam247.github.io/second-look/
🎥 **Demo video:** _coming soon_

GenHacks 2026 · Track: **AI, Agentic Systems, Cybersecurity, and Dev Tools**

---

## The problem

In 2025 the FBI's Internet Crime Complaint Center received **1,008,597 complaints** with **$20.877 billion** in reported losses, up 26% from 2024. People aged 60 and over reported about **$7.7 billion** of that, the most of any age group, with an average loss around $38,500 per complaint.
(Source: FBI IC3 *2025 Internet Crime Report*, released April 7, 2026.)

Most of these scams start the same way: one text, email, or call. The single moment that matters is *before* the person clicks, calls back, or pays. Existing tools are either built into one app, require an account, send your messages to a server, or give a bare "spam / not spam" answer with no explanation.

## What Second Look does

1. **Explainable verdict.** A 0–100 risk score and one of three plain answers: *Very likely a scam*, *Be careful*, or *No strong warning signs*. Every point of the score comes from a named reason the user can read.
2. **Highlights the exact words.** The message is shown with the suspicious phrases marked like a highlighter on a letter (yellow = warning sign, red = strong warning sign).
3. **Look-alike link detector.** Shows where each link *really* goes and catches:
   - typo domains (`paypa1.com`, `arnazon.com`, `netfllx-billing.com`)
   - foreign look-alike letters / homoglyphs (`аpple.com` with a Cyrillic "а"), decoded from punycode
   - brand names stuffed into other domains (`usps-redelivery-help.top`)
   - brand names used as subdomains (`paypal.com.security-check.net`)
   - `@` tricks (`paypal.com@evil.net`), bare IP addresses, shortened links, risky endings like `.top` `.click` `.xyz`
4. **Names the scam.** Toll/delivery, government impersonation, tech support, fake renewal "call us for a refund", grandparent/family emergency, prize, investment/crypto, fake job, overpayment, account phishing.
5. **Tells you what to do next**, tailored to the scam type, plus an "Already paid or shared a code?" section with real recovery steps (bank, ReportFraud.ftc.gov, IC3.gov, 7726, AARP Fraud Watch Helpline 877-908-3360).
6. **"Ask someone you trust."** Scammers rely on isolation ("don't tell anyone"). One tap writes a message to a family member with the verdict, the top reasons, and the original text, ready to copy or send by text.
7. **Accessible by design.** Atkinson Hyperlegible font (designed by the Braille Institute for low-vision readers), a "Larger text" switch, "Read result aloud" (text-to-speech), 44px+ tap targets, light and dark mode, keyboard focus states.
8. **Practice mode.** "Scam or real?" quiz with realistic messages. After each answer, the engine shows exactly what gave it away, so people learn the patterns themselves.
9. **Private and offline.** No server, no account, no tracking. Installable as an app (PWA) and works with no internet after the first visit.

## How it works

```
message ──► text signal rules (30 weighted patterns, each with a plain-English reason)
        ──► link extractor ──► URL parse ─► punycode decode ─► "skeleton" normalize
                                 (Cyrillic а→a, 0→o, 1→l, rn→m…) ─► compare to 50+ brands
                                 (exact skeleton match, Damerau-Levenshtein distance,
                                  brand-in-domain, brand-as-subdomain) + structural checks
        ──► scam-recipe combos (e.g. "account problem + deadline + bad link")
        ──► safety signals that LOWER the score ("Don't share this code with anyone")
        ──► score = 100 · (1 − e^(−Σweights/55)), with hard floors for
            never-legit asks (gift cards, Bitcoin ATM, remote access, reading back a code)
        ──► verdict + scam type + highlights + tailored advice
```

Design choices:
- **Explainable rules, not a black box.** For a safety tool used by non-technical people, "here is why" matters as much as the answer. Every finding has a title and a reason written at a plain-reading level.
- **Diminishing-returns scoring** so a single harmless word ("urgent") can't flag a message, but a few strong signals together do.
- **Look-alike detection on a normalized "skeleton"** so the same check catches digit swaps, foreign letters, and `rn`→`m` tricks in one pass.
- **Precision first.** A tool that cries wolf gets ignored. Real 2FA codes, bank purchase alerts, delivery updates, and personal texts score low.

## Results

`node tests/run.js` runs link unit tests plus two labeled message sets:

| Set | Scams flagged "Very likely" | Scams flagged at least "Be careful" | Real messages wrongly called "Very likely" | Real messages marked "Be careful" |
|---|---|---|---|---|
| Development (28 scam / 14 real), used while writing rules | 28/28 | 28/28 | 0/14 | 0/14 |
| **Held-out (12 scam / 8 real), never tuned on** | **11/12** | **12/12** | **0/8** | **0/8** |

Link unit tests: 14/14 (including `purchase.com` and `stream.com`, which must *not* be flagged as Chase or Steam).

These are small, hand-written test sets, so treat the numbers as a sanity check, not a benchmark. The one held-out miss (a fake PayPal "invoice" with a callback number) scored 57, just under the "Very likely" line, and still showed as "Be careful".

## Run it

No build step, no dependencies.

```bash
git clone https://github.com/Venkatagaddam247/second-look.git
cd second-look
# open index.html in a browser, or serve it:
python3 -m http.server 8000      # then visit http://localhost:8000
node tests/run.js                # run the tests (Node 18+)
```

## Files

| File | What it is |
|---|---|
| `index.html` | The app: UI, highlighting, trusted-contact message, practice mode, accessibility controls |
| `engine.js` | Detection engine (works in the browser and in Node) |
| `tests/run.js` | Test runner: link unit tests + accuracy on both message sets |
| `tests/corpus.json` | Development set of labeled messages |
| `tests/holdout.json` | Held-out set, not used for tuning |
| `sw.js`, `manifest.json`, `icon.svg` | Offline support and "install as app" |

## Built with

HTML, CSS, vanilla JavaScript, Web Speech API (read aloud), Service Worker + Web App Manifest (offline PWA), Node.js (tests), Google Fonts (Atkinson Hyperlegible, Bricolage Grotesque). Built with help from Claude (AI assistant).

## What's next

- Read text from a **screenshot** (on-device OCR) since many people get scams as images or can't copy text
- Browser extension that checks links on hover in webmail
- Spanish and other languages
- Larger, real-world test set from public phishing archives
- Optional "family circle" so a trusted person gets alerted when a "Very likely" result happens (opt-in)

## Disclaimer

Second Look gives a second opinion, not a guarantee. Scammers change tactics constantly. When in doubt, contact the organization using a number or website you already trust.

## License

MIT
