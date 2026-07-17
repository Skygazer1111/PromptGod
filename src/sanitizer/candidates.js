/**
 * PromptGod — Candidate Extraction & Unknown Secret Detection
 * Extracts potential secret values from text via key-value patterns
 * and standalone high-entropy token scanning.
 *
 * Depends on: PromptGodFalsePositives, PromptGodEntropy
 */

const PromptGodCandidates = (() => {
  "use strict";

  const { isFalsePositive } = PromptGodFalsePositives;
  const { isLikelySecret, calculateEntropy, MIN_SECRET_LENGTH } = PromptGodEntropy;

  /**
   * Extract candidate secret values from text using generic key-value patterns
   * and standalone high-entropy token detection.
   * @param {string} text
   * @returns {Array<{value: string, start: number, context: string}>}
   */
  function extractCandidates(text) {
    const candidates = [];
    const candidateValues = new Set();

    // ─── Pattern A: Key-value assignments ───
    // Matches: KEY = "value", KEY=value, "key": "value", key: value
    const kvPatterns = [
      // ENV style: KEY=value or KEY="value" or KEY='value'
      /(?:^|[\s;,])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^\s"'#;,}{\]\)]+)["']?/gm,
      // JSON style: "key": "value" or 'key': 'value'
      /["']([A-Za-z_][A-Za-z0-9_]*)["']\s*:\s*["']([^"']+)["']/g,
      // YAML style: key: value (unquoted)
      /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^\s#][^\n#]*)/gm,
    ];

    for (const pattern of kvPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      let iterations = 0;

      while ((match = regex.exec(text)) !== null && iterations < 500) {
        iterations++;
        const value = (match[2] || "").trim();

        if (value && !candidateValues.has(value) && value.length >= MIN_SECRET_LENGTH) {
          candidateValues.add(value);
          candidates.push({
            value,
            start: match.index,
            context: text.substring(
              Math.max(0, match.index - 50),
              Math.min(text.length, match.index + match[0].length + 50)
            ),
          });
        }
      }
    }

    // ─── Pattern B: Standalone high-entropy tokens ───
    // Match long alphanumeric+special tokens not already caught by key-value patterns
    // Note: `=` is excluded from the token charset — it's a delimiter, not part of secrets
    const tokenRegex = /(?:^|[\s"'=:,;({\[])([A-Za-z0-9_\-+/.]{16,256})(?=[\s"',;:=)}\]#]|$)/gm;
    let tokenMatch;
    let tokenIterations = 0;

    while ((tokenMatch = tokenRegex.exec(text)) !== null && tokenIterations < 500) {
      tokenIterations++;
      const token = (tokenMatch[1] || "").trim();

      // Skip tokens in JSON/YAML key position (followed by optional quote then colon)
      const afterPos = tokenMatch.index + tokenMatch[0].length;
      const afterStr = text.substring(afterPos, Math.min(text.length, afterPos + 5));
      if (/^["']?\s*:/.test(afterStr)) continue;

      if (token && !candidateValues.has(token) && token.length >= MIN_SECRET_LENGTH) {
        candidateValues.add(token);
        candidates.push({
          value: token,
          start: tokenMatch.index,
          context: text.substring(
            Math.max(0, tokenMatch.index - 50),
            Math.min(text.length, tokenMatch.index + tokenMatch[0].length + 50)
          ),
        });
      }
    }

    return candidates;
  }

  /**
   * Detect unknown secrets via entropy analysis.
   * Returns an array of detected secret objects.
   * @param {string} text
   * @returns {Array<{value: string, entropy: number}>}
   */
  function detectUnknownSecrets(text, lineContext = "") {
    if (!text || text.length < MIN_SECRET_LENGTH) return [];

    const candidates = extractCandidates(text);
    const secrets = [];

    for (const candidate of candidates) {
      const { value, context } = candidate;
      const fullContext = lineContext ? `${lineContext} ${context}` : context;

      // Run false positive filter
      if (isFalsePositive(value, fullContext)) continue;

      // Run structural + entropy check (line context lowers threshold for _SECRET/_KEY lines)
      if (isLikelySecret(value, fullContext)) {
        secrets.push({
          value,
          entropy: calculateEntropy(value),
        });
      }
    }

    return secrets;
  }

  return {
    extractCandidates,
    detectUnknownSecrets,
  };
})();
