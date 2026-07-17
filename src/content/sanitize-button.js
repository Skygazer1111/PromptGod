/**
 * PromptGod — Sanitize Button
 * Floating "Sanitize" button injected near the chat input.
 * Allows manual sanitization of typed (not pasted) text.
 *
 * Depends on: PromptGodSelectors, PromptGodInserter, PromptGodVault, PromptGodToast
 */

const PromptGodSanitizeButton = (() => {
  "use strict";

  const { cachedSelectors } = PromptGodSelectors;

  /**
   * Inject a floating "Sanitize" button near the chat input.
   *
   * @param {function} getIsEnabled - Returns current isEnabled state
   * @param {function} getCachedCustomRules - Returns current custom rules
   */
  function injectSanitizeButton(getIsEnabled, getCachedCustomRules) {
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
      if (!getIsEnabled()) {
        PromptGodToast.showNotificationMessage("PromptGod is disabled. Enable it from the popup.");
        return;
      }
      sanitizeCurrentInput(getCachedCustomRules());
    });

    document.body.appendChild(btn);
  }

  /**
   * Find the active chat input and sanitize its current text content.
   */
  function sanitizeCurrentInput(cachedCustomRules) {
    let inputEl = null;

    for (const selector of cachedSelectors) {
      inputEl = document.querySelector(selector);
      if (inputEl) break;
    }

    if (!inputEl) {
      PromptGodToast.showNotificationMessage("Could not find the chat input on this page.");
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
      PromptGodToast.showNotificationMessage("The chat input is empty — nothing to sanitize.");
      return;
    }

    const result = PromptGodSanitizer.sanitize(currentText, cachedCustomRules);

    if (result.extracted.length === 0) {
      PromptGodToast.showNotificationMessage("No secrets detected in the current text. ✅");
      return;
    }

    // Replace the content with masked text
    if (inputEl.tagName === "TEXTAREA" || inputEl.tagName === "INPUT") {
      PromptGodInserter.insertIntoTextarea(inputEl, result.maskedText);
    } else {
      // For contenteditable, replace all content
      inputEl.focus();
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(inputEl);
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand("insertText", false, result.maskedText);
    }

    PromptGodVault.saveToVault(result.extracted);
    PromptGodToast.showNotification(result.extracted.length);
  }

  return {
    injectSanitizeButton,
  };
})();
