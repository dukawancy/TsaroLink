# 🛡️ Phishing URL Detector

[![Netlify Status](https://api.netlify.com/api/v1/badges/YOUR-NETLIFY-BADGE-ID/deploy-status)](https://app.netlify.com/sites/YOUR-SITE-NAME/deploys)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Languages](https://img.shields.io/badge/languages-English%20%7C%20Hausa-green.svg)
![Made in Nigeria](https://img.shields.io/badge/made%20in-Nigeria%20🇳🇬-008751.svg)
![Powered by Claude](https://img.shields.io/badge/AI-Claude%20by%20Anthropic-blueviolet.svg)

> A bilingual (English/Hausa) cybersecurity tool that detects phishing URLs using pattern analysis, real-time threat databases (Google Safe Browsing + VirusTotal), and AI-powered explanations — built for general public awareness in Nigeria and Northern Africa.

---

## ✨ Features

- 🔍 **6-signal pattern analysis** — HTTPS check, suspicious TLDs, brand impersonation, URL shorteners, high-risk keywords, subdomain depth
- 🌐 **Live threat database scan** — checks against Google Safe Browsing (10k/day free) and VirusTotal (70+ security engines)
- 🤖 **AI explanation** — Claude (Anthropic) explains results in plain English anyone can understand
- 🌍 **Bilingual UI** — full English/Hausa toggle including AI responses, verdicts, flags, and tips
- 📤 **Share to X** — one-click pre-filled tweet with verdict and score in the active language
- 🕒 **Scan history** — last 10 URLs checked this session, click to re-run any
- 🔒 **Privacy-first** — no data stored or sent to any server except the threat APIs; all pattern checks run in the browser
- ⚡ **No install needed** — single HTML file, works in any modern browser

---

## 🖥️ Demo

🔗 **Live site:** [your-site-name.netlify.app](https://your-site-name.netlify.app)

<!-- Replace the image below with a real screenshot after deployment -->
<!-- ![Screenshot of Phishing URL Detector](./screenshot.png) -->

---

## 🏗️ How it works

```
Browser (index.html)
    │
    ├── Pattern engine (client-side, instant)
    │     └── TLD check, brand lookalike, keywords, subdomains...
    │
    └── Deep scan button → Netlify Function (check-url.js)
          ├── Google Safe Browsing API  (known threat blocklist)
          └── VirusTotal API            (70+ AV engines)
```

The Netlify serverless function acts as a secure proxy — your API keys stay on the server and are never exposed to the browser.

---

## 🚀 Deploy your own

### 1. Clone the repo

```bash
git clone https://github.com/dukwancy/phishing-url-detector.git
cd phishing-url-detector
```

### 2. Get free API keys

| Service | Free Tier | Where to get it |
|---|---|---|
| Google Safe Browsing | 10,000 req/day | [console.cloud.google.com](https://console.cloud.google.com) → Enable Safe Browsing API → Credentials |
| VirusTotal | 500 req/day | [virustotal.com](https://www.virustotal.com) → Profile → API Key |
| Anthropic (optional) | Pay-as-you-go | [console.anthropic.com](https://console.anthropic.com) — users supply their own key in-browser |

### 3. Deploy to Netlify

**Option A — Drag and drop:**
1. Go to [app.netlify.com/drop](https://app.netlify.com/drop)
2. Drag the project folder onto the page

**Option B — Connect GitHub (recommended):**
1. Netlify dashboard → **Add new site** → **Import an existing project**
2. Connect this GitHub repo — `netlify.toml` handles the rest automatically

### 4. Add environment variables

In your Netlify site dashboard:
**Site configuration → Environment variables → Add a variable**

| Key | Value |
|---|---|
| `GOOGLE_SAFE_BROWSING_KEY` | your Google API key |
| `VIRUSTOTAL_API_KEY` | your VirusTotal API key |

Then trigger a redeploy: **Deploys → Trigger deploy → Deploy site**

---

## 📁 Project structure

```
.
├── index.html                    # Full frontend — UI, pattern engine, i18n
├── netlify.toml                  # Netlify build + functions config
├── package.json
├── LICENSE
├── README.md
└── netlify/
    └── functions/
        └── check-url.js          # Serverless backend — Safe Browsing + VirusTotal proxy
```

---

## 🌍 Bilingual support (English / Hausa)

This tool is designed with Nigerian and Northern African users in mind. Every visible string in the UI — verdicts, flag descriptions, tips, AI responses, share tweets — switches fully between English and Hausa with the toggle in the header.

If you spot a translation that could be improved, pull requests are welcome.

---

## 🔐 Security notes

- **API keys** are stored as Netlify environment variables — never in code or exposed to the browser
- **No user data** is logged or stored anywhere
- **Anthropic key** for AI explanations is entered by the user in their own browser session only — never sent to this project's backend
- Pattern matching runs entirely client-side — no network request is made unless the user clicks "Run deep scan"

---

## 🛠️ Local development

```bash
npm install -g netlify-cli
cp .env.example .env         # fill in your keys
netlify dev                  # runs site + functions at localhost:8888
```

`.env` example:
```
GOOGLE_SAFE_BROWSING_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

> ⚠️ Never commit your `.env` file — it's already in `.gitignore`

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

---

## 👤 Author

**Adam** ([@dukwancy](https://x.com/dukwancy)) — Cybersecurity graduate, NYSC corps member, Web3 & cybersecurity educator creating content in English and Hausa for Nigerian audiences.

---

## 📄 License

[MIT](./LICENSE) © 2025 Adam Dukwancy
