/**
 * PromptGod — Content Script Orchestrator
 * Extension state management, storage listeners, event registration,
 * and sanitize button scheduling.
 *
 * Depends on: PromptGodSanitizer, PromptGodPasteHandler, PromptGodSanitizeButton,
 *             PromptGodVault
 */

(() => {
  "use strict";

  const LOG_PREFIX = "[PromptGod]";
  const DEBUG = false;
  let isEnabled = true;
  let cachedCustomRules = [];

  const { isExtensionContextValid } = PromptGodVault;

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
        if (DEBUG) console.log(`${LOG_PREFIX} Loaded ${cachedCustomRules.length} custom rule(s).`);
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
          if (DEBUG) console.log(`${LOG_PREFIX} Extension ${isEnabled ? "enabled" : "disabled"}.`);
        }
        if (changes.customRules) {
          cachedCustomRules = PromptGodSanitizer.buildCustomRules(changes.customRules.newValue || []);
          if (DEBUG) console.log(`${LOG_PREFIX} Custom rules updated (${cachedCustomRules.length} rules).`);
        }
      });
    } catch (e) {
      console.warn(`${LOG_PREFIX} Extension context lost, skipping storage listener.`);
    }
  }

  // ---------------------------------------------------------------
  // 2. Attach paste listener & inject sanitize button
  // ---------------------------------------------------------------

  // Use capture phase so we get the paste event before the editor does
  document.addEventListener("paste", (event) => {
    PromptGodPasteHandler.handlePaste(event, isEnabled, cachedCustomRules);
  }, true);

  // Inject the Sanitize button when the browser is idle (non-blocking)
  function scheduleSanitizeButton() {
    const inject = () => PromptGodSanitizeButton.injectSanitizeButton(
      () => isEnabled,
      () => cachedCustomRules
    );
    if (typeof requestIdleCallback === "function") {
      requestIdleCallback(inject, { timeout: 3000 });
    } else {
      setTimeout(inject, 1500);
    }
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    scheduleSanitizeButton();
  } else {
    window.addEventListener("load", scheduleSanitizeButton, { once: true });
  }

  if (DEBUG) {
    console.log(
      `${LOG_PREFIX} ✅ Content script active on ${window.location.hostname}. Paste interception is ON.`
    );
  }
})();
