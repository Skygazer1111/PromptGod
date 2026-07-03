/**
 * PromptGod - Sanitizer Engine
 * Detects and masks sensitive data patterns in text.
 * Returns the masked text and an array of extracted secrets.
 */

const PromptGodSanitizer = (() => {
  // Default rulesets: each rule has a name, regex, and optional description.
  const DEFAULT_RULES = [
    // --- API Keys ---
    {
      name: "AWS Access Key",
      regex: /\b(AKIA[0-9A-Z]{16})\b/g,
      description: "AWS Access Key ID (starts with AKIA)",
    },
    {
      name: "AWS Secret Key",
      regex: /\b([A-Za-z0-9/+=]{40})\b/g,
      description: "AWS Secret Access Key (40 chars, base64-like)",
      // This is intentionally broad; we gate it behind context detection below.
      contextRequired: true,
    },
    {
      name: "OpenAI API Key",
      regex: /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
      description: "OpenAI API key (starts with sk-)",
    },
    {
      name: "GitHub Token (Classic)",
      regex: /\b(ghp_[A-Za-z0-9]{36,})\b/g,
      description: "GitHub Personal Access Token (classic)",
    },
    {
      name: "GitHub Token (Fine-grained)",
      regex: /\b(github_pat_[A-Za-z0-9_]{22,})\b/g,
      description: "GitHub Fine-grained Personal Access Token",
    },
    {
      name: "GitHub OAuth",
      regex: /\b(gho_[A-Za-z0-9]{36,})\b/g,
      description: "GitHub OAuth Access Token",
    },
    {
      name: "Slack Token",
      regex: /\b(xox[bprs]-[A-Za-z0-9-]{10,})\b/g,
      description: "Slack API Token",
    },
    {
      name: "Stripe Secret Key",
      regex: /\b(sk_live_[A-Za-z0-9]{20,})\b/g,
      description: "Stripe Secret API Key",
    },
    {
      name: "Stripe Publishable Key",
      regex: /\b(pk_live_[A-Za-z0-9]{20,})\b/g,
      description: "Stripe Publishable API Key",
    },
    {
      name: "Google API Key",
      regex: /\b(AIza[A-Za-z0-9_-]{35})\b/g,
      description: "Google API Key (starts with AIza)",
    },
    {
      name: "Twilio API Key",
      regex: /\b(SK[0-9a-fA-F]{32})\b/g,
      description: "Twilio API Key",
    },
    {
      name: "SendGrid API Key",
      regex: /\b(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,})\b/g,
      description: "SendGrid API Key",
    },
    {
      name: "Mailgun API Key",
      regex: /\b(key-[A-Za-z0-9]{32})\b/g,
      description: "Mailgun API Key",
    },
    {
      name: "Firebase API Key",
      regex: /\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/g,
      description: "Firebase Cloud Messaging Server Key",
    },
    {
      name: "Heroku API Key",
      regex: /\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/g,
      description: "Heroku API Key (UUID format)",
      contextRequired: true,
    },

    // --- Generic Patterns ---
    {
      name: "Bearer Token",
      regex: /Bearer\s+([A-Za-z0-9_\-.+/=]{20,})/gi,
      description: "Authorization Bearer token",
    },
    {
      name: "Basic Auth Header",
      regex: /Basic\s+([A-Za-z0-9+/=]{10,})/gi,
      description: "Authorization Basic credentials (base64)",
    },
    {
      name: "JWT Token",
      regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
      description: "JSON Web Token",
    },
    {
      name: "Private Key Block",
      regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
      description: "PEM Private Key",
    },

    // --- .env Style Key-Value Pairs ---
    {
      name: "ENV Variable (Secret/Key/Token/Password)",
      regex: /(?:^|[\s;,])([A-Z_]{2,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|API_KEY|AUTH|CREDENTIAL)[A-Z_]*)\s*=\s*["']?([^\s"'#;]+)["']?/gim,
      description: "Environment variable containing a secret value",
      captureGroup: 2, // mask only the value, not the key name
    },
    {
      name: "ENV Variable (Generic Assignment)",
      regex: /(?:^|[\s;,])(?:export\s+)?([A-Z_]{2,})\s*=\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?/gm,
      description: "Generic env assignment with a long value (likely a secret)",
      captureGroup: 2,
      contextRequired: true,
    },

    // --- Connection Strings ---
    {
      name: "Database Connection String",
      regex: /((?:mongodb|postgres|mysql|redis|amqp|mssql):\/\/[^\s"']+)/gi,
      description: "Database connection URI (may contain credentials)",
    },

    // --- Passwords in URLs ---
    {
      name: "Password in URL",
      regex: /:\/\/([^:]+):([^@]+)@/g,
      description: "Credentials embedded in a URL",
      captureGroup: 2,
    },
  ];

  /**
   * Sanitize a string by detecting and masking sensitive data.
   * @param {string} text - The input text to sanitize.
   * @param {Array} customRules - Optional array of additional rules [{name, regex, description}].
   * @returns {{ maskedText: string, extracted: Array<{rule: string, original: string, masked: string}> }}
   */
  function sanitize(text, customRules = []) {
    const allRules = [...DEFAULT_RULES.filter((r) => !r.contextRequired), ...customRules];
    const extracted = [];
    let maskedText = text;

    for (const rule of allRules) {
      // Reset regex lastIndex for global regexes
      rule.regex.lastIndex = 0;

      // We need to clone the regex to avoid mutation issues when re-running
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      const captureGroup = rule.captureGroup || 1;

      let match;
      const replacements = [];

      while ((match = regex.exec(maskedText)) !== null) {
        const fullMatch = match[0];
        const sensitiveValue = match[captureGroup] || match[0];
        const stars = "*".repeat(Math.min(sensitiveValue.length, 32));

        replacements.push({
          fullMatch,
          sensitiveValue,
          stars,
        });

        extracted.push({
          rule: rule.name,
          original: sensitiveValue,
          masked: stars,
          description: rule.description,
        });
      }

      // Apply replacements (from last to first to preserve indices)
      for (const rep of replacements.reverse()) {
        if (rule.captureGroup) {
          // Only replace the capture group portion within the full match
          const newFullMatch = rep.fullMatch.replace(rep.sensitiveValue, rep.stars);
          maskedText = maskedText.replace(rep.fullMatch, newFullMatch);
        } else {
          maskedText = maskedText.replace(rep.sensitiveValue, rep.stars);
        }
      }
    }

    // --- Context-gated rules ---
    // Only run context-required rules if the text looks like code/config
    if (looksLikeCodeOrConfig(text)) {
      const contextRules = DEFAULT_RULES.filter((r) => r.contextRequired);
      for (const rule of contextRules) {
        const regex = new RegExp(rule.regex.source, rule.regex.flags);
        const captureGroup = rule.captureGroup || 1;
        let match;
        const replacements = [];

        while ((match = regex.exec(maskedText)) !== null) {
          const fullMatch = match[0];
          const sensitiveValue = match[captureGroup] || match[0];
          const stars = "*".repeat(Math.min(sensitiveValue.length, 32));

          replacements.push({ fullMatch, sensitiveValue, stars });
          extracted.push({
            rule: rule.name,
            original: sensitiveValue,
            masked: stars,
            description: rule.description,
          });
        }

        for (const rep of replacements.reverse()) {
          if (rule.captureGroup) {
            const newFullMatch = rep.fullMatch.replace(rep.sensitiveValue, rep.stars);
            maskedText = maskedText.replace(rep.fullMatch, newFullMatch);
          } else {
            maskedText = maskedText.replace(rep.sensitiveValue, rep.stars);
          }
        }
      }
    }

    return { maskedText, extracted };
  }

  /**
   * Heuristic: does the text look like code or configuration?
   */
  function looksLikeCodeOrConfig(text) {
    const codeIndicators = [
      /^[\s]*(?:export\s+)?[A-Z_]+=.+/m, // ENV assignments
      /\bimport\s+/,                       // JS/Python imports
      /\brequire\s*\(/,                    // Node.js require
      /\bconst\s+/,                        // JS const
      /\blet\s+/,                          // JS let
      /\bvar\s+/,                          // JS var
      /\bdef\s+/,                          // Python def
      /\bclass\s+/,                        // Class declaration
      /[{}();]/,                           // Code punctuation
      /^\s*#/m,                            // Comments or env file
      /^\s*\/\//m,                         // JS comments
    ];
    return codeIndicators.some((re) => re.test(text));
  }

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
            // Escape the keyword and wrap in word boundaries
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

  // Public API
  return {
    sanitize,
    getRuleNames,
    buildCustomRules,
  };
})();

// Make available for both content scripts and test pages
if (typeof module !== "undefined" && module.exports) {
  module.exports = PromptGodSanitizer;
}
