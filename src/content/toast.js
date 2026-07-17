/**
 * PromptGod — Toast Notifications
 * On-page toast notifications for masking feedback and status messages.
 */

const PromptGodToast = (() => {
  "use strict";

  const TOAST_STYLES = {
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
  };

  /**
   * Show a small, non-intrusive notification when secrets are masked.
   */
  function showNotification(count) {
    const existing = document.getElementById("promptgod-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "promptgod-toast";
    toast.innerHTML = `
      <span style="font-size: 18px; line-height: 1;">🛡️</span>
      <span><strong>PromptGod</strong> masked ${count} secret${count > 1 ? "s" : ""} in your paste.</span>
    `;

    Object.assign(toast.style, TOAST_STYLES);
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

    Object.assign(toast.style, TOAST_STYLES);
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

  return {
    showNotification,
    showNotificationMessage,
  };
})();
