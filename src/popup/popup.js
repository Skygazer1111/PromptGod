/**
 * PromptGod — Popup Script (The Vault)
 * Reads masked secrets from chrome.storage.local and renders them
 * in a collapsible, grouped list. Provides toggle and clear controls.
 */

document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggle-btn");
  const statusDot = document.getElementById("status-dot");
  const statusText = document.getElementById("status-text");
  const statsBadge = document.getElementById("stats-badge");
  const vaultList = document.getElementById("vault-list");
  const emptyState = document.getElementById("empty-state");
  const clearBtn = document.getElementById("clear-btn");
  const vaultSection = document.querySelector(".vault");

  // ---------------------------------------------------------------
  // 1. Load extension status
  // ---------------------------------------------------------------
  function loadStatus() {
    chrome.storage.local.get("enabled", (data) => {
      const enabled = data.enabled !== false;
      updateToggleUI(enabled);
    });
  }

  function updateToggleUI(enabled) {
    if (enabled) {
      toggleBtn.classList.add("active");
      statusDot.classList.remove("disabled");
      statusText.textContent = "Active";
    } else {
      toggleBtn.classList.remove("active");
      statusDot.classList.add("disabled");
      statusText.textContent = "Disabled";
    }
  }

  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get("enabled", (data) => {
      const newState = data.enabled === false; // toggle
      chrome.storage.local.set({ enabled: newState }, () => {
        updateToggleUI(newState);
      });
    });
  });

  // ---------------------------------------------------------------
  // 2. Load & render vault entries
  // ---------------------------------------------------------------
  function loadVault() {
    chrome.storage.local.get("vault", (data) => {
      const vault = data.vault || [];
      renderVault(vault);
    });
  }

  function renderVault(vault) {
    vaultList.innerHTML = "";

    if (vault.length === 0) {
      vaultSection.style.display = "none";
      emptyState.style.display = "block";
      statsBadge.textContent = "";
      return;
    }

    vaultSection.style.display = "block";
    emptyState.style.display = "none";

    // Count total secrets across all entries
    const totalSecrets = vault.reduce((sum, entry) => sum + entry.items.length, 0);
    statsBadge.textContent = `${totalSecrets} secret${totalSecrets !== 1 ? "s" : ""} caught`;

    vault.forEach((entry, index) => {
      const entryEl = createEntryElement(entry, index);
      vaultList.appendChild(entryEl);
    });
  }

  function createEntryElement(entry, index) {
    const el = document.createElement("div");
    el.className = "vault-entry";
    el.style.animationDelay = `${index * 0.04}s`;

    const timeAgo = getTimeAgo(entry.timestamp);
    const count = entry.items.length;

    el.innerHTML = `
      <div class="vault-entry-header">
        <div class="vault-entry-meta">
          <span class="vault-site">${escapeHtml(entry.site)}</span>
          <span class="vault-time">${timeAgo}</span>
        </div>
        <span class="vault-count">${count} masked</span>
        <span class="vault-chevron">▶</span>
      </div>
      <div class="vault-items">
        ${entry.items.map((item, i) => createItemHTML(item, entry.id, i)).join("")}
      </div>
    `;

    // Toggle expand/collapse
    const header = el.querySelector(".vault-entry-header");
    header.addEventListener("click", () => {
      el.classList.toggle("expanded");
    });

    // Copy buttons
    el.querySelectorAll(".copy-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const value = btn.dataset.value;
        navigator.clipboard.writeText(value).then(() => {
          btn.classList.add("copied");
          btn.textContent = "✓";
          setTimeout(() => {
            btn.classList.remove("copied");
            btn.textContent = "📋";
          }, 1500);
        });
      });
    });

    return el;
  }

  function createItemHTML(item, entryId, itemIndex) {
    return `
      <div class="vault-item">
        <div class="vault-item-rule">${escapeHtml(item.rule)}</div>
        <div class="vault-item-value">
          ${escapeHtml(item.original)}
          <button class="copy-btn" data-value="${escapeAttr(item.original)}" title="Copy to clipboard">📋</button>
        </div>
      </div>
    `;
  }

  // ---------------------------------------------------------------
  // 3. Clear Vault (with confirmation dialog)
  // ---------------------------------------------------------------
  clearBtn.addEventListener("click", () => {
    showConfirmDialog(
      "Clear Vault?",
      "This will permanently delete all stored secrets. This cannot be undone.",
      () => {
        chrome.storage.local.set({ vault: [] }, () => {
          loadVault();
        });
      }
    );
  });

  function showConfirmDialog(title, message, onConfirm) {
    // Remove existing overlay if any
    const existing = document.querySelector(".confirm-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.className = "confirm-overlay";
    overlay.innerHTML = `
      <div class="confirm-dialog">
        <h3>${title}</h3>
        <p>${message}</p>
        <div class="confirm-actions">
          <button class="btn-cancel">Cancel</button>
          <button class="btn-danger">Clear All</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector(".btn-cancel").addEventListener("click", () => {
      overlay.remove();
    });

    overlay.querySelector(".btn-danger").addEventListener("click", () => {
      onConfirm();
      overlay.remove();
    });

    // Close on clicking outside the dialog
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });
  }

  // ---------------------------------------------------------------
  // 4. Utilities
  // ---------------------------------------------------------------
  function getTimeAgo(isoString) {
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffMs = now - then;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 30) return "Just now";
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    return new Date(isoString).toLocaleDateString();
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ---------------------------------------------------------------
  // 5. Settings link
  // ---------------------------------------------------------------
  const optionsLink = document.getElementById("options-link");
  if (optionsLink) {
    optionsLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      }
    });
  }

  // ---------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------
  loadStatus();
  loadVault();
});
