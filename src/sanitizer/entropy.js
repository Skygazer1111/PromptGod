/**
 * PromptGod — Entropy-Based Secret Detection
 * Shannon entropy analysis and structural heuristics for detecting
 * unknown/custom API keys and secret values.
 *
 * Depends on: PromptGodFalsePositives, PromptGodRules
 */

const PromptGodEntropy = (() => {
  "use strict";

  const { SECRET_KEY_CONTEXT_RE, isFalsePositive, normalizeCandidate } = PromptGodFalsePositives;
  const { SECURITY_KEYWORD_RE } = PromptGodRules;

  // Entropy threshold: strings above this are likely random/secret
  const ENTROPY_THRESHOLD = 3.5;

  // Length bounds for candidate secrets
  const MIN_SECRET_LENGTH = 16;
  const MAX_SECRET_LENGTH = 512;

  /**
   * Shannon entropy — measures randomness of a string.
   * Normal English ≈ 2.5–3.0 bits/char, API keys ≈ 4.0–4.5 bits/char.
   * @param {string} str
   * @returns {number} Entropy in bits per character.
   */
  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  /**
   * Lower entropy barrier when the line/key signals a secret assignment.
   */
  function getEntropyThreshold(lineOrContext = "") {
    if (
      SECRET_KEY_CONTEXT_RE.test(lineOrContext) ||
      SECURITY_KEYWORD_RE.test(lineOrContext) ||
      /proxy_auth\s*=/i.test(lineOrContext)
    ) {
      return 3.0;
    }
    return ENTROPY_THRESHOLD;
  }

  /**
   * Structural heuristics: does a string look like an API key/secret?
   * Checks character composition, length, and mixed character classes.
   * @param {string} str
   * @returns {boolean}
   */
  function isLikelySecret(str, context = "") {
    if (!str || str.length < MIN_SECRET_LENGTH || str.length > MAX_SECRET_LENGTH) return false;

    const clean = normalizeCandidate(str);
    const ctx = context || "";

    // Pure hex digests and UUIDs are operational identifiers, not API secrets
    if (/^[0-9a-f]{40}$/i.test(clean) || /^[0-9a-f]{64}$/i.test(clean)) return false;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(clean)) {
      return false;
    }

    // Prefixed vendor secrets (cmp_sec_live_, acme_api_test_, etc.)
    if (/^[a-z]{2,}_(?:sec(?:ret)?|api)_(?:live_|test_)?[a-z0-9_]{16,}$/i.test(clean)) return true;

    // Dotted domain/namespace paths are infrastructure identifiers, not secrets
    if (/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+/.test(clean)) return false;

    // Underscore-separated lowercase identifiers are config names — unless assigned to a secret key
    if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test(clean) && !SECRET_KEY_CONTEXT_RE.test(ctx)) return false;

    // Must be primarily printable ASCII, no whitespace
    if (/\s/.test(str)) return false;

    // Count character classes
    const hasUpper = /[A-Z]/.test(str);
    const hasLower = /[a-z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    const hasSpecial = /[_\-+#%!=@$./]/.test(str);

    // Must use at least 2 character classes (mixed)
    const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (classCount < 2) return false;

    const isBase64Like = /^[A-Za-z0-9+/=_\-#$%!@]+$/.test(str);
    const isHexLike = /^[0-9a-fA-F]+$/.test(str) && str.length >= 32;
    const isAlphanumericPlus = /^[A-Za-z0-9_\-:.+/=#%!@$]+$/.test(str);

    if (!isBase64Like && !isHexLike && !isAlphanumericPlus) return false;

    const entropy = calculateEntropy(str);
    const threshold = getEntropyThreshold(ctx);
    if (entropy < threshold) return false;

    return true;
  }

  /**
   * Apply entropy-based detection and mask any newly found secrets.
   * Integrates with the main sanitize() pipeline.
   *
   * Depends on: PromptGodCandidates.detectUnknownSecrets (injected at call time)
   */
  function applyEntropyDetection(maskedText, extracted, seen, lineContext = "") {
    const secrets = PromptGodCandidates.detectUnknownSecrets(maskedText, lineContext);

    for (const secret of secrets) {
      const { value } = secret;

      // Skip if already caught by regex rules
      if (seen.has(value)) continue;

      // Apply partial masking: show first 1/4, star remaining 3/4 (preserving exact length)
      const visibleLen = Math.ceil(value.length / 4);
      const visiblePart = value.substring(0, visibleLen);
      const starredLen = value.length - visibleLen;
      const stars = visiblePart + "*".repeat(starredLen);

      maskedText = maskedText.replace(value, stars);
      seen.add(value);

      extracted.push({
        rule: "Entropy Detection (Auto)",
        original: value,
        masked: stars,
        description: `High-entropy string detected (${secret.entropy.toFixed(2)} bits/char)`,
      });
    }

    return maskedText;
  }

  return {
    calculateEntropy,
    getEntropyThreshold,
    isLikelySecret,
    applyEntropyDetection,
    ENTROPY_THRESHOLD,
    MIN_SECRET_LENGTH,
    MAX_SECRET_LENGTH,
  };
})();
