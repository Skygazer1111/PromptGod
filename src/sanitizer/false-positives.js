/**
 * PromptGod — False Positive Detection
 * Filters out strings that look like secrets but aren't:
 * URLs, file paths, UUIDs, git hashes, CSS values, identifiers, etc.
 */

const PromptGodFalsePositives = (() => {
  "use strict";

  const SECRET_KEY_CONTEXT_RE = /[A-Z][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|_AUTH_|CREDENTIAL|ACCESS)[A-Z0-9_]*\s*[=:]\s*["']?/i;

  /**
   * Strip wrapping quotes/brackets before structural checks.
   */
  function normalizeCandidate(str) {
    return str.replace(/^['"[\]]+|['"[\]]+$/g, "").trim();
  }

  /**
   * Surrounding text for contextual false-positive checks.
   */
  function getMatchContext(text, index, length) {
    return text.substring(
      Math.max(0, index - 50),
      Math.min(text.length, index + length + 50)
    );
  }

  /**
   * False positive filter: exclude strings that look like secrets but aren't.
   * @param {string} str - The candidate secret string.
   * @param {string} context - Surrounding text for contextual checks.
   * @returns {boolean} True if this is a false positive (should NOT be masked).
   */
  function isFalsePositive(str, context = "") {
    const cleanStr = normalizeCandidate(str);
    const ctx = context || "";

    // ─── Operational identifiers (safe in logs / git output) ───
    // UUIDs — transaction_id, correlation_id, trace spans, etc.
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(cleanStr)) {
      return true;
    }

    // Git SHA-1 commit hash (40 hex)
    if (/^[0-9a-f]{40}$/i.test(cleanStr)) return true;

    // SHA-256 / SHA-512 content hashes (64 / 128 hex) — diagnostic, not credentials
    if (/^[0-9a-f]{64}$/i.test(cleanStr)) return true;
    if (/^[0-9a-f]{128}$/i.test(cleanStr)) return true;

    // Abbreviated git commit hash when git log/output context is present
    if (/^[0-9a-f]{7,39}$/i.test(cleanStr) && /\bcommit\s+$/i.test(ctx)) return true;

    // ─── URLs & repository paths ───
    if (/^https?:\/\//i.test(cleanStr) || /^ftp:\/\//i.test(cleanStr)) return true;
    if (/^\/\/[a-z0-9][a-z0-9.-]*\//i.test(cleanStr)) return true;
    if (/^(?:www\.)?(?:github|gitlab|bitbucket)\.com\//i.test(cleanStr)) return true;
    if (/^git@[\w.-]+:/i.test(cleanStr)) return true;
    if (/\.git$/i.test(cleanStr) && /[/.]/.test(cleanStr)) return true;

    // ─── Infrastructure domain identifiers ───
    // Kubernetes API groups, cloud provider namespaces, dotted package paths
    // Must be all-lowercase to avoid matching API keys like SG.xxx.yyy (SendGrid)
    if (/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+(\/([v]\d+[a-z0-9]*|[a-z][a-z0-9._-]*))*$/.test(cleanStr)) {
      return true;
    }

    // Hyphenated lowercase resource names (Kubernetes resources, Docker images, CLI tools)
    if (/^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)+$/.test(cleanStr)) return true;

    // Underscore-separated lowercase identifiers (config keys, field names)
    if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test(cleanStr)) {
      const digitRatio = (cleanStr.match(/[0-9]/g) || []).length / cleanStr.length;
      const secretKeyContext = SECRET_KEY_CONTEXT_RE.test(ctx);
      if (!secretKeyContext && (cleanStr.length < 24 || digitRatio < 0.25)) return true;
      if (secretKeyContext) return false;
    }

    // File names with common extensions
    if (/\.(ya?ml|json|toml|ini|cfg|conf|xml|html?|css|jsx?|tsx?|py|rb|go|rs|sh|bat|ps1|md|txt|log|env)$/i.test(cleanStr)) {
      return true;
    }

    // JSON/YAML property key context — candidate is followed by ": (key position)
    if (ctx && cleanStr.length < 60) {
      const afterCandidate = ctx.substring(ctx.indexOf(cleanStr) + cleanStr.length);
      if (/^["']?\s*:\s/.test(afterCandidate)) return true;
    }

    // Email addresses
    if (/^[^@]+@[^@]+\.[^@]+$/.test(cleanStr)) return true;

    // File paths (Unix or Windows)
    if (/^\/[a-z_]/i.test(cleanStr) || /^[A-Z]:\\/i.test(cleanStr)) return true;
    if (/^\.\//.test(cleanStr) || /^\.\.\//.test(cleanStr)) return true;

    // CSS/HTML values: hex colors (#fff, #ffffff), common CSS functions
    if (/^#[0-9a-fA-F]{3,8}$/.test(cleanStr)) return true;
    if (/^(rgb|hsl|rgba|hsla|url|calc|var)\(/i.test(cleanStr)) return true;

    // Package versions (semver-like)
    if (/^\d+\.\d+\.\d+/.test(cleanStr)) return true;

    // Common programming identifiers / camelCase / snake_case words that are code, not secrets
    if (/\(\)/.test(cleanStr) || /\.\w+\(/.test(cleanStr)) return true;

    // Repeated character strings (aaaaaaa, 1111111, etc.)
    if (/^(.)\1{7,}$/.test(cleanStr)) return true;

    // Key=value assignments (e.g., DB_HOST=localhost, APP_NAME=PromptGod)
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(cleanStr)) return true;

    const digitRatio = (cleanStr.match(/[0-9]/g) || []).length / cleanStr.length;
    if (/^[a-z]+([_-][a-z]+){2,}$/.test(cleanStr) && digitRatio === 0) return true;

    // ALL-UPPERCASE snake_case identifiers are ENV variable names, not secret values
    if (/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(cleanStr)) return true;

    // CamelCase or PascalCase identifiers (programming variable names, not secrets)
    if (/^[a-z][a-zA-Z0-9]*$/.test(cleanStr) && digitRatio < 0.3 && cleanStr.length < 30) return true;
    if (/^[A-Z][a-zA-Z0-9]*$/.test(cleanStr) && /[a-z]/.test(cleanStr) && digitRatio < 0.3 && cleanStr.length < 30) {
      return true;
    }

    // If already contains stars (already masked by a previous rule)
    if (/\*{4,}/.test(cleanStr)) return true;

    // JSON structural tokens
    if (/^[{}\[\]:,]+$/.test(cleanStr)) return true;

    const safePrefixes = [
      "data:image/",
      "data:application/",
      "sha256-",
      "sha384-",
      "sha512-",
      "integrity=",
    ];
    if (safePrefixes.some((p) => cleanStr.startsWith(p))) return true;

    return false;
  }

  return {
    isFalsePositive,
    normalizeCandidate,
    getMatchContext,
    SECRET_KEY_CONTEXT_RE,
  };
})();
