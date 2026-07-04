/**
 * PromptGod - Content Script
 * Intercepts paste events on AI chatbot websites and automatically
 * masks sensitive data (API keys, passwords, tokens, etc.) before
 * the text enters the chat input.
 *
 * Supports: ChatGPT, Gemini, Grok, Claude (contenteditable + textarea)
 */

(() => {
  "use strict";

  const LOG_PREFIX = "[PromptGod]";
  let isEnabled = true;
  let cachedCustomRules = []; // Compiled custom rules from storage

  /**
   * Check if the extension context is still valid.
   * After an extension reload/update, old content scripts remain on the page
   * but chrome.runtime becomes disconnected — calling any chrome.* API throws
   * "Extension context invalidated". This guard prevents that.
   */
  function isExtensionContextValid() {
    try {
      return !!(
        typeof chrome !== "undefined" &&
        chrome.runtime &&
        chrome.runtime.id
      );
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------
  // 1. Check if the extension is enabled & load custom rules
  // ---------------------------------------------------------------
  function checkEnabled() {
    if (!isExtensionContextValid()) return;
    try {
      chrome.storage.local.get(["enabled", "customRules"], (data) => {
        if (chrome.runtime.lastError) return;
        isEnabled = data.enabled !== false; // default to true
        cachedCustomRules = PromptGodSanitizer.buildCustomRules(data.customRules || []);
        console.log(`${LOG_PREFIX} Loaded ${cachedCustomRules.length} custom rule(s).`);
      });
    } catch (e) {
      console.warn(`${LOG_PREFIX} Extension context lost, skipping checkEnabled.`);
    }
  }
  checkEnabled();

  // Listen for toggle changes and custom rule updates from popup / options
  if (isExtensionContextValid()) {
    try {
      chrome.storage.onChanged.addListener((changes) => {
        if (!isExtensionContextValid()) return;
        if (changes.enabled) {
          isEnabled = changes.enabled.newValue;
          console.log(`${LOG_PREFIX} Extension ${isEnabled ? "enabled" : "disabled"}.`);
        }
        if (changes.customRules) {
          cachedCustomRules = PromptGodSanitizer.buildCustomRules(changes.customRules.newValue || []);
          console.log(`${LOG_PREFIX} Custom rules updated (${cachedCustomRules.length} rules).`);
        }
      });
    } catch (e) {
      console.warn(`${LOG_PREFIX} Extension context lost, skipping storage listener.`);
    }
  }

  // ---------------------------------------------------------------
  // 2. Identify the chat input element on the page
  // ---------------------------------------------------------------

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
      "#userInput",                                   // Copilot main input
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
      'textarea',
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

  // ---------------------------------------------------------------
  // 3. Paste Interception
  // ---------------------------------------------------------------

  /**
   * The main paste handler. Attached to the document so it catches
   * paste events on dynamically created inputs (SPAs swap DOM often).
   */
  function handlePaste(event) {
    if (!isEnabled) return;

    // Only act if the paste target is (or is inside) a chat input
    const target = event.target;
    if (!isChatInput(target)) return;

    // Get the plain text from the clipboard
    const clipboardData = event.clipboardData || window.clipboardData;
    if (!clipboardData) return;

    const pastedText = clipboardData.getData("text/plain");
    if (!pastedText || pastedText.trim().length === 0) return;

    // Run sanitizer with custom rules
    const result = PromptGodSanitizer.sanitize(pastedText, cachedCustomRules);

    // If nothing was found, let the normal paste go through
    if (result.extracted.length === 0) {
      console.log(`${LOG_PREFIX} Paste scanned — no secrets found. Passing through.`);
      return;
    }

    // Secrets found! Prevent the original paste.
    event.preventDefault();
    event.stopImmediatePropagation();

    console.log(
      `${LOG_PREFIX} 🛡️ Intercepted paste! Masked ${result.extracted.length} secret(s).`
    );

    // Insert the masked text into the input
    insertTextIntoInput(target, result.maskedText);

    // Save the extracted secrets to local storage for the Vault
    saveToVault(result.extracted);

    // Show a brief notification on the page
    showNotification(result.extracted.length);
  }

  /**
   * Check if an element is (or is inside) a known chat input.
   */
  function isChatInput(element) {
    if (!element) return false;
    const selectors = getSelectorsForCurrentSite();
    for (const selector of selectors) {
      // The element itself matches
      if (element.matches && element.matches(selector)) return true;
      // The element is inside a matching container
      if (element.closest && element.closest(selector)) return true;
    }
    return false;
  }

  // ---------------------------------------------------------------
  // 4. Text Insertion (handles both contenteditable & textarea)
  // ---------------------------------------------------------------

  /**
   * Insert masked text into the target input element.
   * Works with both <textarea> and contenteditable divs.
   */
  function insertTextIntoInput(target, text) {
    const editableEl = findEditableElement(target);

    if (!editableEl) {
      // Last resort: try document.execCommand
      document.execCommand("insertText", false, text);
      return;
    }

    if (editableEl.tagName === "TEXTAREA" || editableEl.tagName === "INPUT") {
      // Standard textarea/input
      insertIntoTextarea(editableEl, text);
    } else {
      // Contenteditable div (ChatGPT, Claude, Gemini, Grok)
      insertIntoContentEditable(editableEl, text);
    }
  }

  /**
   * Walk up from the target to find the actual editable element.
   */
  function findEditableElement(el) {
    let current = el;
    while (current) {
      if (
        current.tagName === "TEXTAREA" ||
        current.tagName === "INPUT" ||
        current.contentEditable === "true" ||
        current.getAttribute?.("contenteditable") === "true"
      ) {
        return current;
      }
      current = current.parentElement;
    }
    return null;
  }

  /**
   * Insert text into a <textarea> or <input>.
   */
  function insertIntoTextarea(textarea, text) {
    const start = textarea.selectionStart || 0;
    const end = textarea.selectionEnd || 0;
    const before = textarea.value.substring(0, start);
    const after = textarea.value.substring(end);

    // Set value using native setter to trigger React/framework updates
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      "value"
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(textarea, before + text + after);
    } else {
      textarea.value = before + text + after;
    }

    // Fire input event to notify frameworks
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    textarea.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /**
   * Insert text into a contenteditable div.
   * Uses a combination of approaches for maximum compatibility with
   * ProseMirror (ChatGPT, Claude) and Quill (Gemini).
   */
  function insertIntoContentEditable(el, text) {
    // Focus the element first
    el.focus();

    // Approach 1: Use the InputEvent API (best for modern editors)
    // This simulates a real user input which ProseMirror and Quill respond to.
    try {
      const inputEvent = new InputEvent("beforeinput", {
        inputType: "insertFromPaste",
        data: text,
        bubbles: true,
        cancelable: true,
        composed: true,
      });

      // Some editors need DataTransfer on the event
      if (typeof DataTransfer !== "undefined") {
        const dt = new DataTransfer();
        dt.setData("text/plain", text);
        Object.defineProperty(inputEvent, "dataTransfer", {
          value: dt,
        });
      }

      const wasHandled = !el.dispatchEvent(inputEvent);

      if (wasHandled) {
        // The editor handled it via beforeinput — we're done
        el.dispatchEvent(
          new InputEvent("input", {
            inputType: "insertFromPaste",
            data: text,
            bubbles: true,
          })
        );
        return;
      }
    } catch (e) {
      // Fall through to next approach
    }

    // Approach 2: execCommand (deprecated but still widely effective)
    try {
      const success = document.execCommand("insertText", false, text);
      if (success) return;
    } catch (e) {
      // Fall through
    }

    // Approach 3: Direct DOM manipulation (last resort)
    const selection = window.getSelection();
    if (selection && selection.rangeCount > 0) {
      const range = selection.getRangeAt(0);
      range.deleteContents();
      const textNode = document.createTextNode(text);
      range.insertNode(textNode);
      // Move cursor to end of inserted text
      range.setStartAfter(textNode);
      range.setEndAfter(textNode);
      selection.removeAllRanges();
      selection.addRange(range);
    } else {
      // Absolute last resort: set textContent
      el.textContent = text;
    }

    // Fire input event
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }

  // ---------------------------------------------------------------
  // 5. Vault Storage (save extracted secrets for the popup)
  // ---------------------------------------------------------------

  /**
   * Save extracted secrets to chrome.storage.local so the popup
   * (The Vault) can display them.
   */
  function saveToVault(extractedItems) {
    if (!isExtensionContextValid()) {
      console.warn(`${LOG_PREFIX} Extension context invalidated, skipping vault save.`);
      return;
    }

    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).substring(2, 7),
      timestamp: new Date().toISOString(),
      site: window.location.hostname,
      items: extractedItems.map((item) => ({
        rule: item.rule,
        original: item.original,
        description: item.description,
      })),
    };

    try {
      chrome.storage.local.get("vault", (data) => {
        if (chrome.runtime.lastError) return;
        const vault = data.vault || [];
        vault.unshift(entry); // newest first

        // Keep only the last 100 entries to avoid storage bloat
        if (vault.length > 100) vault.length = 100;

        chrome.storage.local.set({ vault }, () => {
          if (chrome.runtime.lastError) return;
          console.log(`${LOG_PREFIX} Saved ${entry.items.length} item(s) to the Vault.`);
        });
      });
    } catch (e) {
      console.warn(`${LOG_PREFIX} Extension context lost, vault save skipped.`);
    }
  }

  // ---------------------------------------------------------------
  // 6. On-page notification (subtle toast)
  // ---------------------------------------------------------------

  /**
   * Show a small, non-intrusive notification on the page when
   * secrets are masked.
   */
  function showNotification(count) {
    // Remove any existing notification
    const existing = document.getElementById("promptgod-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "promptgod-toast";
    toast.innerHTML = `
      <span style="font-size: 18px; line-height: 1;">🛡️</span>
      <span><strong>PromptGod</strong> masked ${count} secret${count > 1 ? "s" : ""} in your paste.</span>
    `;

    Object.assign(toast.style, {
      position: "fixed",
      bottom: "24px",
      right: "24px",
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      gap: "10px",
      padding: "12px 20px",
      background: "linear-gradient(135deg, #1a1a2e, #16213e)",
      border: "1px solid #7c3aed",
      borderRadius: "12px",
      color: "#e0e0e8",
      fontFamily: "'Segoe UI', system-ui, sans-serif",
      fontSize: "13px",
      boxShadow: "0 8px 32px rgba(124, 58, 237, 0.3)",
      opacity: "0",
      transform: "translateY(16px)",
      transition: "opacity 0.3s ease, transform 0.3s ease",
    });

    document.body.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
      toast.style.opacity = "1";
      toast.style.transform = "translateY(0)";
    });

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px)";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // ---------------------------------------------------------------
  // 7. Sanitize Button Injection
  // ---------------------------------------------------------------

  /**
   * Inject a floating "Sanitize" button near the chat input.
   * Allows users to manually sanitize text they've typed (not pasted).
   */
  function injectSanitizeButton() {
    // Don't inject twice
    if (document.getElementById("promptgod-sanitize-btn")) return;

    const btn = document.createElement("button");
    btn.id = "promptgod-sanitize-btn";
    btn.innerHTML = `🛡️`;
    btn.title = "PromptGod: Sanitize current text";

    Object.assign(btn.style, {
      position: "fixed",
      bottom: "80px",
      right: "24px",
      zIndex: "2147483646",
      width: "44px",
      height: "44px",
      borderRadius: "50%",
      border: "1px solid #7c3aed",
      background: "linear-gradient(135deg, #1a1a2e, #16213e)",
      color: "#e0e0e8",
      fontSize: "20px",
      cursor: "pointer",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      boxShadow: "0 4px 20px rgba(124, 58, 237, 0.35)",
      transition: "transform 0.2s ease, box-shadow 0.2s ease",
      lineHeight: "1",
    });

    btn.addEventListener("mouseenter", () => {
      btn.style.transform = "scale(1.1)";
      btn.style.boxShadow = "0 6px 28px rgba(124, 58, 237, 0.5)";
    });
    btn.addEventListener("mouseleave", () => {
      btn.style.transform = "scale(1)";
      btn.style.boxShadow = "0 4px 20px rgba(124, 58, 237, 0.35)";
    });

    btn.addEventListener("click", () => {
      if (!isEnabled) {
        showNotificationMessage("PromptGod is disabled. Enable it from the popup.");
        return;
      }
      sanitizeCurrentInput();
    });

    document.body.appendChild(btn);
  }

  /**
   * Find the active chat input and sanitize its current text content.
   */
  function sanitizeCurrentInput() {
    const selectors = getSelectorsForCurrentSite();
    let inputEl = null;

    for (const selector of selectors) {
      inputEl = document.querySelector(selector);
      if (inputEl) break;
    }

    if (!inputEl) {
      showNotificationMessage("Could not find the chat input on this page.");
      return;
    }

    // Get the current text
    let currentText;
    if (inputEl.tagName === "TEXTAREA" || inputEl.tagName === "INPUT") {
      currentText = inputEl.value;
    } else {
      currentText = inputEl.innerText || inputEl.textContent;
    }

    if (!currentText || currentText.trim().length === 0) {
      showNotificationMessage("The chat input is empty — nothing to sanitize.");
      return;
    }

    const result = PromptGodSanitizer.sanitize(currentText, cachedCustomRules);

    if (result.extracted.length === 0) {
      showNotificationMessage("No secrets detected in the current text. ✅");
      return;
    }

    // Replace the content with masked text
    if (inputEl.tagName === "TEXTAREA" || inputEl.tagName === "INPUT") {
      insertIntoTextarea(inputEl, result.maskedText);
    } else {
      // For contenteditable, replace all content
      inputEl.focus();
      // Select all text
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(inputEl);
      selection.removeAllRanges();
      selection.addRange(range);
      // Insert masked text
      document.execCommand("insertText", false, result.maskedText);
    }

    saveToVault(result.extracted);
    showNotification(result.extracted.length);
  }

  /**
   * Show a simple text message as a toast (for non-masking notifications).
   */
  function showNotificationMessage(message) {
    const existing = document.getElementById("promptgod-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "promptgod-toast";
    toast.innerHTML = `
      <span style="font-size: 18px; line-height: 1;">🛡️</span>
      <span>${message}</span>
    `;

    Object.assign(toast.style, {
      position: "fixed",
      bottom: "24px",
      right: "24px",
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      gap: "10px",
      padding: "12px 20px",
      background: "linear-gradient(135deg, #1a1a2e, #16213e)",
      border: "1px solid #7c3aed",
      borderRadius: "12px",
      color: "#e0e0e8",
      fontFamily: "'Segoe UI', system-ui, sans-serif",
      fontSize: "13px",
      boxShadow: "0 8px 32px rgba(124, 58, 237, 0.3)",
      opacity: "0",
      transform: "translateY(16px)",
      transition: "opacity 0.3s ease, transform 0.3s ease",
    });

    document.body.appendChild(toast);
    requestAnimationFrame(() => {
      toast.style.opacity = "1";
      toast.style.transform = "translateY(0)";
    });
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px)";
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  // ---------------------------------------------------------------
  // 8. Attach the listener & inject button
  // ---------------------------------------------------------------

  // Use capture phase so we get the paste event before the editor does
  document.addEventListener("paste", handlePaste, true);

  // Inject the Sanitize button once the page is ready
  if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(injectSanitizeButton, 1500);
  } else {
    window.addEventListener("load", () => setTimeout(injectSanitizeButton, 1500));
  }

  console.log(
    `${LOG_PREFIX} ✅ Content script active on ${window.location.hostname}. Paste interception is ON.`
  );
})();
