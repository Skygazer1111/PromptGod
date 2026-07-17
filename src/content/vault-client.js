/**
 * PromptGod — Vault Client
 * Saves extracted secrets to chrome.storage via the background worker.
 *
 * Depends on: PromptGodToast (for unavailability notification)
 */

const PromptGodVault = (() => {
  "use strict";

  const LOG_PREFIX = "[PromptGod]";
  const DEBUG = false;

  let vaultSaveUnavailableNotified = false;

  /**
   * Check if the extension context is still valid.
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

  /**
   * Save extracted secrets to the Vault via the background worker.
   */
  function saveToVault(extractedItems) {
    if (!extractedItems?.length) return;

    if (!isExtensionContextValid()) {
      notifyVaultUnavailable();
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
      chrome.runtime.sendMessage({ type: "SAVE_VAULT", entry }, (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          notifyVaultUnavailable();
          return;
        }
        if (DEBUG) {
          console.log(`${LOG_PREFIX} Saved ${entry.items.length} item(s) to the Vault.`);
        }
      });
    } catch {
      notifyVaultUnavailable();
    }
  }

  /**
   * Shown once per page when masking works but Vault sync cannot run.
   */
  function notifyVaultUnavailable() {
    if (vaultSaveUnavailableNotified) return;
    vaultSaveUnavailableNotified = true;
    if (DEBUG) {
      console.warn(`${LOG_PREFIX} Vault save unavailable — extension context invalidated. Refresh the page.`);
    }
    PromptGodToast.showNotificationMessage(
      "Secrets were masked. Refresh this page to sync with the Vault."
    );
  }

  return {
    saveToVault,
    isExtensionContextValid,
  };
})();
