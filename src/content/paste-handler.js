/**
 * PromptGod — Paste Handler
 * Intercepts paste events on AI chatbot input fields and sanitizes
 * the pasted text before it enters the editor.
 *
 * Depends on: PromptGodSelectors, PromptGodInserter, PromptGodVault, PromptGodToast
 */

const PromptGodPasteHandler = (() => {
  "use strict";

  const LOG_PREFIX = "[PromptGod]";
  const DEBUG = false;

  const { cachedSelectorString, EDITABLE_SELECTOR } = PromptGodSelectors;

  /**
   * The main paste handler. Attached to the document so it catches
   * paste events on dynamically created inputs (SPAs swap DOM often).
   *
   * @param {ClipboardEvent} event
   * @param {boolean} isEnabled - Current extension enabled state
   * @param {Array} cachedCustomRules - Compiled custom rules
   */
  function handlePaste(event, isEnabled, cachedCustomRules) {
    if (!isEnabled) return;

    const target = event.target;
    if (!target || target.nodeType !== Node.ELEMENT_NODE) return;

    // Fast reject: most pastes on the page are not in chat inputs
    if (!target.closest(EDITABLE_SELECTOR)) return;
    if (!target.closest(cachedSelectorString)) return;

    const clipboardData = event.clipboardData || window.clipboardData;
    if (!clipboardData) return;

    const pastedText = clipboardData.getData("text/plain");
    if (!pastedText || pastedText.trim().length === 0) return;

    const result = PromptGodSanitizer.sanitize(pastedText, cachedCustomRules);

    if (result.extracted.length === 0) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    if (DEBUG) {
      console.log(
        `${LOG_PREFIX} 🛡️ Intercepted paste! Masked ${result.extracted.length} secret(s).`
      );
    }

    PromptGodInserter.insertTextIntoInput(target, result.maskedText);
    PromptGodVault.saveToVault(result.extracted);
    PromptGodToast.showNotification(result.extracted.length);
  }

  return {
    handlePaste,
  };
})();
