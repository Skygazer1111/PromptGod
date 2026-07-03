# PromptGod - Build Roadmap

## Build Phase 1: Project Setup & Basic Engine
- [x] Initialize the project folder and files.
- [x] Setup `manifest.json` (Manifest V3) with necessary permissions (`storage`, `activeTab`, `scripting`).
- [x] Create `sanitizer.js`: Write the core regular expression logic to detect and replace dummy API keys/secrets with `********`.

## Build Phase 2: The MVP Interceptor
- [x] Create `content.js` and configure the manifest to inject it into specific URLs (e.g., `*://chatgpt.com/*`).
- [x] Implement the `paste` event listener in `content.js` attached to the main chat input (`textarea` or `contenteditable`).
- [x] Connect the `paste` event to `sanitizer.js`: Intercept pasted text, mask it, and insert the masked text into the input field instead of the original text.
- [x] Verify auto-masking works seamlessly in the actual ChatGPT/Gemini interface.

## Build Phase 3: The Vault & Local Storage
- [x] Implement `chrome.storage.local` inside `content.js` to save the original, unmasked values that `sanitizer.js` extracted during a paste event.
- [x] Create the extension popup (`popup.html` and `popup.js`).
- [x] Design "The Vault" UI inside the popup: Fetch data from `chrome.storage.local` and display a clean list of recently masked items.
- [x] Add a "Clear Vault" button in the popup to wipe the saved data from local storage.

## Build Phase 4: Manual Controls & Settings
- [ ] Inject a manual "Sanitize" button into the DOM near the chat input (for users who type sensitive data instead of pasting).
- [ ] Create the Options page (`options.html` and `options.js`).
- [ ] Build a UI in the Options page allowing users to define custom Regex rules or specific keywords to mask.
- [ ] Update `sanitizer.js` to merge user-defined custom rules with the default rulesets before running the detection.

## Build Phase 5: Hardening & Release
- [ ] Expand the default Regex rulesets to cover standard patterns comprehensively (AWS, OpenAI, GitHub, generic Hex/Base64, emails).
- [ ] Cross-browser/Cross-site testing: Ensure the interceptor works on Gemini, Grok, Claude, and standard web forms, handling different DOM structures gracefully.
- [ ] Optimize performance to ensure large text pastes don't freeze the browser.
- [ ] Design the extension icon and prepare promotional assets (screenshots, descriptions).
- [ ] Publish PromptGod to the Chrome Web Store.
