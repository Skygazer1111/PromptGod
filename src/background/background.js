/**
 * PromptGod - Background Service Worker
 * Handles extension lifecycle and messaging between content scripts and popup.
 */

// Listen for installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    console.log("[PromptGod] Extension installed successfully.");
    // Initialize default settings
    chrome.storage.local.set({
      enabled: true,
      customRules: [],
      vault: [],
    });
  } else if (details.reason === "update") {
    console.log(`[PromptGod] Extension updated to version ${chrome.runtime.getManifest().version}`);
  }
});

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_STATUS") {
    chrome.storage.local.get("enabled", (data) => {
      sendResponse({ enabled: data.enabled !== false });
    });
    return true; // keep channel open for async response
  }

  if (message.type === "TOGGLE_STATUS") {
    chrome.storage.local.get("enabled", (data) => {
      const newStatus = !data.enabled;
      chrome.storage.local.set({ enabled: newStatus }, () => {
        sendResponse({ enabled: newStatus });
      });
    });
    return true;
  }

  if (message.type === "SAVE_VAULT") {
    const entry = message.entry;
    if (!entry || !Array.isArray(entry.items) || entry.items.length === 0) {
      sendResponse({ ok: false });
      return false;
    }

    chrome.storage.local.get("vault", (data) => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false });
        return;
      }
      const vault = data.vault || [];
      vault.unshift(entry);
      if (vault.length > 100) vault.length = 100;
      chrome.storage.local.set({ vault }, () => {
        sendResponse({ ok: !chrome.runtime.lastError });
      });
    });
    return true;
  }
});
