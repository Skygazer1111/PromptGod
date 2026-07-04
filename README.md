# 🛡️ PromptGod

**AI Prompt Sanitizer** — A Chrome Extension that automatically masks API keys, passwords, and secrets when you paste text into AI chatbots.

**Current version:** 1.0.1

## The Problem

Developers paste code, `.env` files, logs, and infrastructure configs into ChatGPT, Gemini, Copilot, etc. — often with secrets still in them. PromptGod catches those secrets and replaces them with partial redaction (`sk_live_51N***************`) before they ever leave your browser.

> All processing happens locally. No data is sent anywhere.

## Features

- **Auto-mask on paste** — Intercepts paste events in chat inputs and masks secrets before they reach the AI
- **50+ built-in rules** — AWS, OpenAI, GitHub, Stripe, Slack, JWT, PEM private keys, connection strings, credit cards, and more
- **Smart Entropy Engine** — Detects unknown secrets via Shannon entropy analysis, even without a matching regex
- **Context-aware detection** — Lowers the entropy threshold on lines with `_SECRET`, `_KEY`, `_TOKEN`, etc.; catches custom-prefixed keys like `cmp_sec_live_...`
- **Inline credential parsing** — Masks passwords in `user:pass@host` and `proxy_auth=...` strings, including special characters (`@`, `#`, `%`, `!`) inside passwords
- **Partial redaction** — Shows the first 1/4 of each secret, stars the rest, preserving exact string length so JSON/YAML structure stays intact
- **Structure-safe processing** — Line-isolated regex pipeline prevents cross-line “chomp” bugs; PEM/RSA multiline keys are still handled correctly
- **Operational ID preservation** — Does not mask git commit hashes, UUIDs, transaction IDs, K8s API groups (`networking.k8s.io/v1`), or repo URLs
- **The Vault** — Click the extension icon to review redacted secrets (saved via the background service worker)
- **Manual Sanitize** — Floating 🛡️ button to scan typed text on demand
- **Custom Rules** — Add your own regex patterns or keywords via Settings
- **Performance-tuned** — Fast-path rejection for plain prose; per-line sanitization; deferred vault writes

## Supported Sites

ChatGPT · Gemini · Claude · Grok · Microsoft Copilot · Bing Chat · Perplexity · DeepSeek · Poe · HuggingFace Chat · Mistral

## Installation

1. Clone the repo
   ```bash
   git clone https://github.com/Skygazer1111/PromptGod.git
   ```
2. Go to `chrome://extensions` → enable **Developer mode**
3. Click **Load unpacked** → select the `PromptGod` folder
4. Visit any supported site and paste text containing API keys to try it.

**After updating the extension:** click **Reload** on `chrome://extensions`, then **hard-refresh** any open chat tabs (Ctrl+Shift+R). Content scripts from the previous version stay attached until the tab is refreshed.

## How the Sanitizer Works

PromptGod uses a two-phase pipeline in `sanitizer.js`:

1. **Multiline phase** — PEM / RSA private key blocks (the only rules allowed to span lines)
2. **Line-isolated phase** — All other regex rules and entropy detection run per line, so structural characters (quotes, braces, newlines) are never consumed across boundaries

Detection layers, in order:

| Layer | What it catches |
|-------|-----------------|
| Regex rules | Known vendor keys, env assignments, DB URIs, Sentry DSNs, etc. |
| Inline credentials | `://user:password@host` and `proxy_auth=user:pass@host` (passwords may contain `@`, `#`, `%`) |
| Custom prefixes | Vendor-specific patterns like `cmp_sec_live_...` |
| Entropy engine | High-entropy unknown strings in config-like text |
| False-positive filter | UUIDs, git SHAs, infra domains, JSON keys, repo URLs |

## Project Structure

```
PromptGod/
├── manifest.json       # Extension config (Manifest V3)
├── sanitizer.js        # Regex + entropy detection engine (v2)
├── test-runner.js      # CLI test runner (116 tests)
├── test-sanitizer.html # Browser-based test suite UI
├── content.js          # Paste interceptor + sanitize button
├── background.js       # Service worker (vault storage, messaging)
├── popup/              # The Vault UI
├── options/            # Custom rules settings page
└── icons/              # Extension icons
```

## Testing

The sanitizer ships with **116 automated tests** covering:

- Hardcoded vendor key patterns (OpenAI, AWS, Stripe, etc.)
- Partial masking and length preservation
- Custom-named env/JSON/YAML keys
- Entropy detection and false-positive resistance
- Operational content (git commits, UUIDs, markdown repo links)
- Infrastructure preservation (K8s manifests, JSON structure)
- Heavy nested config (multi-block JSON, proxy strings, custom secrets)

Run the suite:

```bash
node test-runner.js
```

For a visual dashboard, open `test-sanitizer.html` in your browser (served locally).

## Tech

Manifest V3 · Vanilla JS · Zero dependencies · No build step

## License

MIT
