/**
 * PromptGod — Rule Engine
 * Core regex execution loop: matches rules against text, deduplicates,
 * applies partial masking, and tracks extracted secrets.
 *
 * Depends on: PromptGodFalsePositives
 */

const PromptGodRuleEngine = (() => {
  "use strict";

  const { isFalsePositive, getMatchContext } = PromptGodFalsePositives;

  /**
   * Apply a set of rules to the text and return the masked result.
   */
  function applyRules(rules, maskedText, extracted, seen) {
    for (const rule of rules) {
      const regex = rule.regex;
      regex.lastIndex = 0;
      const captureGroup = rule.captureGroup !== undefined ? rule.captureGroup : 1;

      let match;
      const replacements = [];
      let iterations = 0;
      const MAX_ITERATIONS = 500; // Safety cap

      while ((match = regex.exec(maskedText)) !== null && iterations < MAX_ITERATIONS) {
        iterations++;
        const fullMatch = match[0];
        const sensitiveValue = captureGroup === 0 ? fullMatch : (match[captureGroup] || fullMatch);

        // Skip if already masked in a previous rule
        if (seen.has(sensitiveValue)) continue;

        // Skip very short matches (likely false positives)
        if (sensitiveValue.length < 6) continue;

        const matchContext = getMatchContext(maskedText, match.index, fullMatch.length);
        if (isFalsePositive(sensitiveValue, matchContext)) continue;

        // Show first 1/4 of the key, star the remaining 3/4 (preserving exact length)
        const visibleLen = Math.ceil(sensitiveValue.length / 4);
        const visiblePart = sensitiveValue.substring(0, visibleLen);
        const starredLen = sensitiveValue.length - visibleLen;
        const stars = visiblePart + "*".repeat(starredLen);

        replacements.push({ fullMatch, sensitiveValue, stars, captureGroup: rule.captureGroup });
        seen.add(sensitiveValue);

        extracted.push({
          rule: rule.name,
          original: sensitiveValue,
          masked: stars,
          description: rule.description,
        });
      }

      // Apply replacements in reverse order to preserve string indices
      for (const rep of replacements.reverse()) {
        if (rep.captureGroup) {
          const newFullMatch = rep.fullMatch.replace(rep.sensitiveValue, rep.stars);
          maskedText = maskedText.replace(rep.fullMatch, newFullMatch);
        } else {
          maskedText = maskedText.replace(rep.sensitiveValue, rep.stars);
        }
      }
    }

    return maskedText;
  }

  return {
    applyRules,
  };
})();
