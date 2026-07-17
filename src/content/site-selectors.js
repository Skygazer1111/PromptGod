/**
 * PromptGod — Site Selectors
 * Site-specific CSS selectors for identifying chat input elements
 * on supported AI chatbot websites.
 */

const PromptGodSelectors = (() => {
  "use strict";

  /**
   * Site-specific selectors for the main chat input.
   * These target the contenteditable div or textarea where users type.
   * We use multiple selectors per site as fallbacks since sites update often.
   */
  const SITE_SELECTORS = {
    // --- OpenAI ---
    "chatgpt.com": [
      "#prompt-textarea",
      'div[contenteditable="true"][id="prompt-textarea"]',
      'div[contenteditable="true"]',
      "textarea",
    ],
    "chat.openai.com": [
      "#prompt-textarea",
      'div[contenteditable="true"]',
      "textarea",
    ],
    // --- Google ---
    "gemini.google.com": [
      ".ql-editor",
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- xAI ---
    "grok.com": [
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- Anthropic ---
    "claude.ai": [
      'div[contenteditable="true"].ProseMirror',
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- Microsoft Copilot ---
    "copilot.microsoft.com": [
      "#userInput",
      'textarea[id="userInput"]',
      'div[contenteditable="true"]',
      'textarea[placeholder]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- Bing Chat ---
    "www.bing.com": [
      "#searchbox",
      'textarea[id="searchbox"]',
      'div[contenteditable="true"]',
      "textarea",
    ],
    // --- HuggingFace Chat ---
    "huggingface.co": [
      'textarea[placeholder]',
      'div[contenteditable="true"]',
      "textarea",
    ],
    // --- Poe ---
    "poe.com": [
      'div[contenteditable="true"]',
      'textarea[class*="Chat"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- Perplexity ---
    "perplexity.ai": [
      'textarea[placeholder]',
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- DeepSeek ---
    "deepseek.com": [
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    "chat.deepseek.com": [
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    // --- Mistral ---
    "chat.mistral.ai": [
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
  };

  /**
   * Get the matching selectors for the current site.
   */
  function getSelectorsForCurrentSite() {
    const hostname = window.location.hostname;
    for (const [domain, selectors] of Object.entries(SITE_SELECTORS)) {
      if (hostname.includes(domain)) {
        return selectors;
      }
    }
    // Fallback: generic selectors
    return ['div[contenteditable="true"]', 'div[role="textbox"]', "textarea"];
  }

  // Resolved once per page load — avoids repeated hostname scans
  const cachedSelectors = getSelectorsForCurrentSite();
  const cachedSelectorString = cachedSelectors.join(", ");

  // Editable elements only — fast reject before compound selector walk
  const EDITABLE_SELECTOR =
    'textarea, input[type="text"], input:not([type]), [contenteditable="true"], [role="textbox"]';

  return {
    SITE_SELECTORS,
    cachedSelectors,
    cachedSelectorString,
    EDITABLE_SELECTOR,
  };
})();
