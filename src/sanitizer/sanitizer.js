/**
 * PromptGod — Sanitizer Engine v2.0
 * Main orchestrator: sanitize() pipeline, heuristics, and public API.
 * Composes: Rules, FalsePositives, Entropy, Candidates, RuleEngine.
 *
 * Depends on: PromptGodRules, PromptGodFalsePositives, PromptGodEntropy,
 *             PromptGodCandidates, PromptGodRuleEngine
 */

const PromptGodSanitizer = (() => {
  "use strict";

  const {
    DEFAULT_RULES, MULTILINE_RULES, LINE_RULES_NON_CONTEXT, LINE_RULES_CONTEXT,
    SECRET_HINT_RE, LONG_TOKEN_RE, SECURITY_KEYWORD_RE, MAX_ENTROPY_CHARS,
  } = PromptGodRules;

  const { applyRules } = PromptGodRuleEngine;
  const { applyEntropyDetection, calculateEntropy, isLikelySecret, getEntropyThreshold } = PromptGodEntropy;
  const { isFalsePositive } = PromptGodFalsePositives;

  // =====================================================================
  // HEURISTICS
  // =====================================================================

  /**
   * Heuristic: does the text look like code or configuration?
   */
  function looksLikeCodeOrConfig(text) {
    const codeIndicators = [
      /^[\s]*(?:export\s+)?[A-Z_]+=.+/m,
      /\bimport\s+/,
      /\brequire\s*\(/,
      /\bconst\s+/,
      /\blet\s+/,
      /\bvar\s+/,
      /\bdef\s+/,
      /\bclass\s+/,
      /[{}();]/,
      /^\s*#/m,
      /^\s*\/\//m,
      /\bprocess\.env\b/,
      /\bos\.environ\b/,
      /\bdotenv\b/,
      /\.env\b/,
    ];
    return codeIndicators.some((re) => re.test(text));
  }

  // =====================================================================
  // SANITIZE — Main detection + masking function
  // =====================================================================

  /**
   * Quick check: does the text likely contain secrets?
   */
  function mightContainSecrets(text) {
    if (!text || text.length < 8) return false;
    if (SECRET_HINT_RE.test(text)) return true;
    if (text.length >= 16 && LONG_TOKEN_RE.test(text)) return true;
    return false;
  }

  /**
   * Sanitize a string by detecting and masking sensitive data.
   * Optimized: deduplicates matches and limits regex execution time.
   * @param {string} text - The input text to sanitize.
   * @param {Array} customRules - Optional array of additional rules.
   * @returns {{ maskedText: string, extracted: Array }}
   */
  function sanitize(text, customRules = []) {
    // Performance guard: skip very short strings
    if (!text || text.length < 8) return { maskedText: text, extracted: [] };

    // Fast exit for plain prose / UI text with no secret-like patterns
    if (customRules.length === 0 && !mightContainSecrets(text)) {
      return { maskedText: text, extracted: [] };
    }

    const extracted = [];
    let maskedText = text;
    const seen = new Set();
    const isCodeOrConfig = looksLikeCodeOrConfig(text);

    // ── Phase 1: Multiline rules on full text (PEM/RSA blocks only) ──
    // These are the ONLY rules allowed to match across line boundaries.
    if (MULTILINE_RULES.length > 0) {
      maskedText = applyRules(MULTILINE_RULES, maskedText, extracted, seen);
    }

    // ── Phase 2: Line-isolated processing ──
    // Every other rule runs per-line. This prevents any regex from
    // consuming structural characters (quotes, braces, newlines) across
    // line boundaries — the root cause of JSON/YAML structure corruption.
    const lineRules = customRules.length > 0
      ? [...LINE_RULES_NON_CONTEXT, ...customRules]
      : LINE_RULES_NON_CONTEXT;
    const contextRules = isCodeOrConfig ? LINE_RULES_CONTEXT : [];
    const runEntropy =
      text.length <= MAX_ENTROPY_CHARS &&
      (isCodeOrConfig || LONG_TOKEN_RE.test(text));

    const lines = maskedText.split("\n");
    maskedText = lines.map((line) => {
      if (line.length < 6) return line;
      let processed = applyRules(lineRules, line, extracted, seen);
      if (contextRules.length > 0) {
        processed = applyRules(contextRules, processed, extracted, seen);
      }
      const lineNeedsEntropy =
        runEntropy ||
        extracted.length > 0 ||
        SECURITY_KEYWORD_RE.test(line) ||
        /proxy_auth\s*=/i.test(line);
      if (lineNeedsEntropy) {
        processed = applyEntropyDetection(processed, extracted, seen, line);
      }
      return processed;
    }).join("\n");

    return { maskedText, extracted };
  }

  // =====================================================================
  // PUBLIC API
  // =====================================================================

  /**
   * Get list of default rule names (for display in UI).
   */
  function getRuleNames() {
    return DEFAULT_RULES.map((r) => ({ name: r.name, description: r.description }));
  }

  /**
   * Build regex rule objects from user-defined custom rules stored in chrome.storage.
   * @param {Array} storedRules - Array of {name, type, pattern, description} from storage.
   * @returns {Array} Array of rule objects compatible with the sanitize() customRules param.
   */
  function buildCustomRules(storedRules) {
    if (!Array.isArray(storedRules)) return [];

    return storedRules
      .map((rule) => {
        try {
          let regexSource;
          if (rule.type === "keyword") {
            regexSource = rule.pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          } else {
            regexSource = rule.pattern;
          }
          return {
            name: rule.name || "Custom Rule",
            regex: new RegExp(`(${regexSource})`, "g"),
            description: rule.description || "User-defined custom rule",
          };
        } catch (e) {
          console.warn(`[PromptGod] Invalid custom rule "${rule.name}":`, e.message);
          return null;
        }
      })
      .filter(Boolean);
  }

  return {
    sanitize,
    getRuleNames,
    buildCustomRules,
    // Exposed for testing
    calculateEntropy,
    detectUnknownSecrets: PromptGodCandidates.detectUnknownSecrets,
    isLikelySecret,
    isFalsePositive,
    getEntropyThreshold,
  };
})();

// Make available for both content scripts and test pages
if (typeof module !== "undefined" && module.exports) {
  module.exports = PromptGodSanitizer;
}
