/**
 * PromptGod — Options Page Script
 * Manages built-in rule display and custom rule CRUD operations.
 * Custom rules are stored in chrome.storage.local under "customRules".
 */

document.addEventListener("DOMContentLoaded", () => {
  const builtinRulesEl = document.getElementById("builtin-rules");
  const builtinCountEl = document.getElementById("builtin-count");
  const customCountEl = document.getElementById("custom-count");
  const customListEl = document.getElementById("custom-rules-list");
  const emptyCustomEl = document.getElementById("empty-custom");
  const addRuleBtn = document.getElementById("add-rule-btn");
  const testRuleBtn = document.getElementById("test-rule-btn");
  const testArea = document.getElementById("test-area");
  const testInput = document.getElementById("test-input");
  const testResult = document.getElementById("test-result");
  const ruleNameInput = document.getElementById("rule-name");
  const ruleTypeSelect = document.getElementById("rule-type");
  const rulePatternInput = document.getElementById("rule-pattern");
  const ruleDescInput = document.getElementById("rule-desc");
  const patternHint = document.getElementById("pattern-hint");
  const saveToast = document.getElementById("save-toast");

  // ---------------------------------------------------------------
  // 1. Display built-in rules
  // ---------------------------------------------------------------
  function renderBuiltinRules() {
    const rules = PromptGodSanitizer.getRuleNames();
    builtinCountEl.textContent = rules.length;

    builtinRulesEl.innerHTML = rules
      .map(
        (rule) => `
      <div class="rule-chip" title="${escapeHtml(rule.description)}">
        <span class="dot"></span>
        <span class="name">${escapeHtml(rule.name)}</span>
      </div>
    `
      )
      .join("");
  }

  // ---------------------------------------------------------------
  // 2. Load & render custom rules
  // ---------------------------------------------------------------
  function loadCustomRules() {
    chrome.storage.local.get("customRules", (data) => {
      const rules = data.customRules || [];
      renderCustomRules(rules);
    });
  }

  function renderCustomRules(rules) {
    customCountEl.textContent = rules.length;

    if (rules.length === 0) {
      customListEl.style.display = "none";
      emptyCustomEl.style.display = "block";
      return;
    }

    customListEl.style.display = "flex";
    emptyCustomEl.style.display = "none";

    customListEl.innerHTML = rules
      .map(
        (rule, index) => `
      <div class="custom-rule-item" style="animation-delay: ${index * 0.03}s">
        <div class="custom-rule-info">
          <div class="custom-rule-name">${escapeHtml(rule.name)}</div>
          <div class="custom-rule-pattern">${escapeHtml(rule.pattern)}</div>
          ${rule.description ? `<div class="custom-rule-desc">${escapeHtml(rule.description)}</div>` : ""}
        </div>
        <span class="custom-rule-type ${rule.type}">${rule.type}</span>
        <button class="delete-rule-btn" data-index="${index}" title="Delete rule">✕</button>
      </div>
    `
      )
      .join("");

    // Attach delete handlers
    customListEl.querySelectorAll(".delete-rule-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const index = parseInt(btn.dataset.index, 10);
        deleteCustomRule(index);
      });
    });
  }

  // ---------------------------------------------------------------
  // 3. Add a custom rule
  // ---------------------------------------------------------------
  addRuleBtn.addEventListener("click", () => {
    const name = ruleNameInput.value.trim();
    const type = ruleTypeSelect.value;
    const pattern = rulePatternInput.value.trim();
    const description = ruleDescInput.value.trim();

    // Validate
    let valid = true;
    if (!name) {
      ruleNameInput.classList.add("error", "shake");
      valid = false;
    }
    if (!pattern) {
      rulePatternInput.classList.add("error", "shake");
      valid = false;
    }

    if (!valid) {
      setTimeout(() => {
        ruleNameInput.classList.remove("shake");
        rulePatternInput.classList.remove("shake");
      }, 400);
      return;
    }

    // Validate regex if type is regex
    if (type === "regex") {
      try {
        new RegExp(pattern, "g");
      } catch (e) {
        rulePatternInput.classList.add("error", "shake");
        patternHint.textContent = `Invalid regex: ${e.message}`;
        patternHint.style.color = "#f87171";
        setTimeout(() => rulePatternInput.classList.remove("shake"), 400);
        return;
      }
    }

    const newRule = { name, type, pattern, description };

    chrome.storage.local.get("customRules", (data) => {
      const rules = data.customRules || [];
      rules.push(newRule);
      chrome.storage.local.set({ customRules: rules }, () => {
        renderCustomRules(rules);
        showSaveToast();
        // Clear form
        ruleNameInput.value = "";
        rulePatternInput.value = "";
        ruleDescInput.value = "";
        ruleNameInput.classList.remove("error");
        rulePatternInput.classList.remove("error");
        patternHint.textContent = "Enter a JavaScript-compatible regular expression (without delimiters).";
        patternHint.style.color = "";
      });
    });
  });

  // Remove error styles on input
  ruleNameInput.addEventListener("input", () => ruleNameInput.classList.remove("error"));
  rulePatternInput.addEventListener("input", () => {
    rulePatternInput.classList.remove("error");
    patternHint.textContent =
      ruleTypeSelect.value === "regex"
        ? "Enter a JavaScript-compatible regular expression (without delimiters)."
        : "Enter the exact text string to mask.";
    patternHint.style.color = "";
  });

  // Update hint when type changes
  ruleTypeSelect.addEventListener("change", () => {
    patternHint.textContent =
      ruleTypeSelect.value === "regex"
        ? "Enter a JavaScript-compatible regular expression (without delimiters)."
        : "Enter the exact text string to mask.";
  });

  // ---------------------------------------------------------------
  // 4. Delete a custom rule
  // ---------------------------------------------------------------
  function deleteCustomRule(index) {
    chrome.storage.local.get("customRules", (data) => {
      const rules = data.customRules || [];
      rules.splice(index, 1);
      chrome.storage.local.set({ customRules: rules }, () => {
        renderCustomRules(rules);
        showSaveToast();
      });
    });
  }

  // ---------------------------------------------------------------
  // 5. Test pattern
  // ---------------------------------------------------------------
  testRuleBtn.addEventListener("click", () => {
    const isVisible = testArea.style.display !== "none";
    testArea.style.display = isVisible ? "none" : "block";
    if (!isVisible) testInput.focus();
  });

  testInput.addEventListener("input", () => {
    const pattern = rulePatternInput.value.trim();
    const type = ruleTypeSelect.value;
    const text = testInput.value;

    if (!pattern || !text) {
      testResult.innerHTML = "";
      return;
    }

    try {
      let regex;
      if (type === "keyword") {
        regex = new RegExp(escapeRegex(pattern), "gi");
      } else {
        regex = new RegExp(pattern, "gi");
      }

      const matches = text.match(regex);
      if (matches && matches.length > 0) {
        testResult.innerHTML = `<span class="test-match">✅ Found ${matches.length} match${matches.length > 1 ? "es" : ""}: ${matches.map((m) => `<code>${escapeHtml(m)}</code>`).join(", ")}</span>`;
      } else {
        testResult.innerHTML = `<span class="test-no-match">No matches found.</span>`;
      }
    } catch (e) {
      testResult.innerHTML = `<span style="color: var(--red);">❌ Regex error: ${escapeHtml(e.message)}</span>`;
    }
  });

  // ---------------------------------------------------------------
  // 6. Utilities
  // ---------------------------------------------------------------
  function showSaveToast() {
    saveToast.classList.add("show");
    setTimeout(() => saveToast.classList.remove("show"), 2000);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // ---------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------
  renderBuiltinRules();
  loadCustomRules();
});
