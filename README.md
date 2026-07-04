# 🛡️ PromptGod

**AI Prompt Sanitizer** — A Chrome Extension that automatically masks API keys, passwords, and secrets when you paste text into AI chatbots.

## The Problem

Developers paste code, `.env` files, and logs into ChatGPT, Gemini, Copilot, etc. — often with secrets still in them. PromptGod catches those secrets and replaces them with `********` before they ever leave your browser.

> All processing happens locally. No data is sent anywhere.

## Features

- **Auto-mask on paste** — Intercepts paste events and masks secrets automatically
- **Smart Entropy Engine** — Automatically detects unknown secrets and API keys using Shannon entropy analysis, even without matching regexes
- **Partial Redaction** — Masks the last 3/4ths of a secret while leaving the prefix visible, so you know which key was redacted
- **The Vault** — Click the extension icon to see all redacted secrets with copy buttons
- **Manual Sanitize** — Floating 🛡️ button to scan typed text on-demand
- **Custom Rules** — Add your own regex patterns or keywords via Settings
- **50+ built-in rules** — AWS, OpenAI, GitHub, Stripe, Slack, JWT, private keys, credit cards, and more

## Supported Sites

ChatGPT · Gemini · Claude · Grok · Microsoft Copilot · Bing Chat · Perplexity · DeepSeek · Poe · HuggingFace Chat · Mistral

## Installation

1. Clone the repo
   ```bash
   git clone https://github.com/Skygazer1111/PromptGod.git
   ```
2. Go to `chrome://extensions` → enable **Developer mode**
3. Click **Load unpacked** → select the `PromptGod` folder
4. Done! Visit any supported site and try pasting text with API keys.

## Project Structure

```
PromptGod/
├── manifest.json       # Extension config (Manifest V3)
├── sanitizer.js        # Regex & Entropy detection engine
├── test-runner.js      # CLI test runner for sanitizer validation
├── test-sanitizer.html # Browser-based test suite UI
├── content.js          # Paste interceptor + sanitize button
├── background.js       # Service worker
├── popup/              # The Vault UI
├── options/            # Custom rules settings page
└── icons/              # Extension icons
```

## Testing

PromptGod's detection engine comes with a comprehensive test suite covering 70+ test cases including false positives, custom keys, partial masking, and multi-line parsing.

To run the test suite via Node.js:
```bash
node test-runner.js
```
Alternatively, you can open `test-sanitizer.html` in your browser (served locally) for a visual testing dashboard.

## Tech

Manifest V3 · Vanilla JS · Zero dependencies · No build step

## License

MIT
