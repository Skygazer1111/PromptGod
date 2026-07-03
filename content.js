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

  // ---------------------------------------------------------------
  // 1. Check if the extension is enabled
  // ---------------------------------------------------------------
  function checkEnabled() {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.local.get("enabled", (data) => {
        isEnabled = data.enabled !== false; // default to true
      });
    }
  }
  checkEnabled();

  // Listen for toggle changes from the popup / background
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.enabled) {
        isEnabled = changes.enabled.newValue;
        console.log(`${LOG_PREFIX} Extension ${isEnabled ? "enabled" : "disabled"}.`);
      }
    });
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
    "chatgpt.com": [
      "#prompt-textarea",                           // main chat textarea (ProseMirror)
      'div[contenteditable="true"][id="prompt-textarea"]',
      'div[contenteditable="true"]',
      "textarea",
    ],
    "chat.openai.com": [
      "#prompt-textarea",
      'div[contenteditable="true"]',
      "textarea",
    ],
    "gemini.google.com": [
      ".ql-editor",                                 // Quill editor used by Gemini
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    "grok.com": [
      'div[contenteditable="true"]',
      'div[role="textbox"]',
      "textarea",
    ],
    "claude.ai": [
      'div[contenteditable="true"].ProseMirror',    // Claude uses ProseMirror
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

    // Run sanitizer
    const result = PromptGodSanitizer.sanitize(pastedText);

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
    if (typeof chrome === "undefined" || !chrome.storage) {
      console.log(`${LOG_PREFIX} Storage not available, skipping vault save.`);
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

    chrome.storage.local.get("vault", (data) => {
      const vault = data.vault || [];
      vault.unshift(entry); // newest first

      // Keep only the last 100 entries to avoid storage bloat
      if (vault.length > 100) vault.length = 100;

      chrome.storage.local.set({ vault }, () => {
        console.log(`${LOG_PREFIX} Saved ${entry.items.length} item(s) to the Vault.`);
      });
    });
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
  // 7. Attach the listener
  // ---------------------------------------------------------------

  // Use capture phase so we get the paste event before the editor does
  document.addEventListener("paste", handlePaste, true);

  console.log(
    `${LOG_PREFIX} ✅ Content script active on ${window.location.hostname}. Paste interception is ON.`
  );
})();
