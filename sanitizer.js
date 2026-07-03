/**
 * PromptGod - Sanitizer Engine v2.0
 * Comprehensive detection and masking of sensitive data patterns.
 * Optimized for performance on large text blocks.
 */

const PromptGodSanitizer = (() => {
  // =====================================================================
  // DEFAULT RULESETS — Comprehensive coverage
  // =====================================================================
  const DEFAULT_RULES = [
    // ─────────────────────────────────────────────────────────────────
    // Cloud Provider Keys
    // ─────────────────────────────────────────────────────────────────
    {
      name: "AWS Access Key",
      regex: /\b(AKIA[0-9A-Z]{16})\b/g,
      description: "AWS Access Key ID (starts with AKIA)",
    },
    {
      name: "AWS Secret Key",
      regex: /\b([A-Za-z0-9/+=]{40})\b/g,
      description: "AWS Secret Access Key (40 chars, base64-like)",
      contextRequired: true,
    },
    {
      name: "AWS Session Token",
      regex: /\b(FwoGZXIvYXdzE[A-Za-z0-9/+=]{100,})\b/g,
      description: "AWS Temporary Session Token",
    },
    {
      name: "Google API Key",
      regex: /\b(AIza[A-Za-z0-9_-]{35})\b/g,
      description: "Google API Key (starts with AIza)",
    },
    {
      name: "Google OAuth Client Secret",
      regex: /\b(GOCSPX-[A-Za-z0-9_-]{28})\b/g,
      description: "Google OAuth 2.0 Client Secret",
    },
    {
      name: "Google Cloud Service Account",
      regex: /("private_key"\s*:\s*"-----BEGIN[^"]+-----")/g,
      description: "Google Cloud Service Account private key in JSON",
    },
    {
      name: "Azure Storage Key",
      regex: /\b([A-Za-z0-9+/]{86}==)\b/g,
      description: "Azure Storage Account Key (88 chars base64)",
      contextRequired: true,
    },
    {
      name: "Azure AD Client Secret",
      regex: /\b([A-Za-z0-9~._-]{34,})\b/g,
      description: "Azure AD Application Client Secret",
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // AI / LLM Provider Keys
    // ─────────────────────────────────────────────────────────────────
    {
      name: "OpenAI API Key",
      regex: /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
      description: "OpenAI API key (starts with sk-)",
    },
    {
      name: "Anthropic API Key",
      regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
      description: "Anthropic/Claude API Key",
    },
    {
      name: "Google Gemini API Key",
      regex: /\b(AIzaSy[A-Za-z0-9_-]{33})\b/g,
      description: "Google Gemini / Vertex AI API Key",
    },
    {
      name: "Cohere API Key",
      regex: /\b([A-Za-z0-9]{40})\b/g,
      description: "Cohere API Key (40 char alphanumeric)",
      contextRequired: true,
    },
    {
      name: "HuggingFace Token",
      regex: /\b(hf_[A-Za-z0-9]{34,})\b/g,
      description: "HuggingFace Access Token",
    },
    {
      name: "Replicate API Token",
      regex: /\b(r8_[A-Za-z0-9]{38,})\b/g,
      description: "Replicate API Token",
    },

    // ─────────────────────────────────────────────────────────────────
    // Version Control & CI/CD
    // ─────────────────────────────────────────────────────────────────
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
      name: "GitHub App Token",
      regex: /\b(ghu_[A-Za-z0-9]{36,})\b/g,
      description: "GitHub App User-to-Server Token",
    },
    {
      name: "GitHub App Installation",
      regex: /\b(ghs_[A-Za-z0-9]{36,})\b/g,
      description: "GitHub App Installation Token",
    },
    {
      name: "GitLab Token",
      regex: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
      description: "GitLab Personal Access Token",
    },
    {
      name: "Bitbucket App Password",
      regex: /\b(ATBB[A-Za-z0-9]{32,})\b/g,
      description: "Bitbucket App Password",
    },
    {
      name: "npm Token",
      regex: /\b(npm_[A-Za-z0-9]{36,})\b/g,
      description: "npm Access Token",
    },
    {
      name: "PyPI API Token",
      regex: /\b(pypi-[A-Za-z0-9_-]{50,})\b/g,
      description: "PyPI API Token",
    },

    // ─────────────────────────────────────────────────────────────────
    // Communication & SaaS
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Slack Token",
      regex: /\b(xox[bprs]-[A-Za-z0-9-]{10,})\b/g,
      description: "Slack API Token",
    },
    {
      name: "Slack Webhook",
      regex: /(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+)/g,
      description: "Slack Incoming Webhook URL",
    },
    {
      name: "Discord Bot Token",
      regex: /\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g,
      description: "Discord Bot Token",
      contextRequired: true,
    },
    {
      name: "Discord Webhook",
      regex: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+)/g,
      description: "Discord Webhook URL",
    },
    {
      name: "Telegram Bot Token",
      regex: /\b(\d{8,10}:[A-Za-z0-9_-]{35})\b/g,
      description: "Telegram Bot API Token",
    },
    {
      name: "Twilio API Key",
      regex: /\b(SK[0-9a-fA-F]{32})\b/g,
      description: "Twilio API Key",
    },
    {
      name: "Twilio Auth Token",
      regex: /\b([0-9a-f]{32})\b/g,
      description: "Twilio Auth Token (32 hex chars)",
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // Payment & E-commerce
    // ─────────────────────────────────────────────────────────────────
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
      name: "Stripe Test Key",
      regex: /\b(sk_test_[A-Za-z0-9]{20,})\b/g,
      description: "Stripe Test Secret Key",
    },
    {
      name: "PayPal Client Secret",
      regex: /\b(EL[A-Za-z0-9_-]{60,})\b/g,
      description: "PayPal OAuth Client Secret",
      contextRequired: true,
    },
    {
      name: "Square Access Token",
      regex: /\b(sq0atp-[A-Za-z0-9_-]{22,})\b/g,
      description: "Square Access Token",
    },

    // ─────────────────────────────────────────────────────────────────
    // Email Services
    // ─────────────────────────────────────────────────────────────────
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
      name: "Mailchimp API Key",
      regex: /\b([a-f0-9]{32}-us\d{1,2})\b/g,
      description: "Mailchimp API Key",
    },
    {
      name: "Postmark Server Token",
      regex: /\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g,
      description: "Postmark Server API Token (UUID format)",
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // Infrastructure & Hosting
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Firebase Cloud Messaging Key",
      regex: /\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/g,
      description: "Firebase Cloud Messaging Server Key",
    },
    {
      name: "Heroku API Key",
      regex: /\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/g,
      description: "Heroku API Key (UUID format)",
      contextRequired: true,
    },
    {
      name: "Vercel Token",
      regex: /\b([A-Za-z0-9]{24})\b/g,
      description: "Vercel Deployment Token",
      contextRequired: true,
    },
    {
      name: "DigitalOcean Token",
      regex: /\b(dop_v1_[a-f0-9]{64})\b/g,
      description: "DigitalOcean Personal Access Token",
    },
    {
      name: "Netlify Token",
      regex: /\b([A-Za-z0-9_-]{40,50})\b/g,
      description: "Netlify Personal Access Token",
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // Auth Tokens & Sessions
    // ─────────────────────────────────────────────────────────────────
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
      name: "OAuth Access Token",
      regex: /\b(ya29\.[A-Za-z0-9_-]{50,})\b/g,
      description: "Google OAuth2 Access Token",
    },

    // ─────────────────────────────────────────────────────────────────
    // Cryptographic Material
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Private Key Block",
      regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g,
      description: "PEM/PGP Private Key",
    },
    {
      name: "SSH Private Key",
      regex: /(-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----)/g,
      description: "OpenSSH Private Key",
    },

    // ─────────────────────────────────────────────────────────────────
    // Sensitive Data Formats
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Credit Card (Visa)",
      regex: /\b(4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g,
      description: "Visa credit card number",
    },
    {
      name: "Credit Card (Mastercard)",
      regex: /\b(5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g,
      description: "Mastercard credit card number",
    },
    {
      name: "Credit Card (Amex)",
      regex: /\b(3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5})\b/g,
      description: "American Express credit card number",
    },
    {
      name: "US Social Security Number",
      regex: /\b(\d{3}-\d{2}-\d{4})\b/g,
      description: "US Social Security Number (XXX-XX-XXXX)",
      contextRequired: true,
    },
    {
      name: "IPv4 Private Address",
      regex: /\b((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b/g,
      description: "Private/internal IPv4 address",
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // .env / Config Key-Value Patterns
    // ─────────────────────────────────────────────────────────────────
    {
      name: "ENV Variable (Secret/Key/Token/Password)",
      regex: /(?:^|[\s;,])([A-Z_]{2,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|API_KEY|AUTH|CREDENTIAL|ACCESS)[A-Z_]*)\s*=\s*["']?([^\s"'#;]+)["']?/gim,
      description: "Environment variable containing a secret value",
      captureGroup: 2,
    },
    {
      name: "ENV Variable (Generic Assignment)",
      regex: /(?:^|[\s;,])(?:export\s+)?([A-Z_]{2,})\s*=\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?/gm,
      description: "Generic env assignment with a long value (likely a secret)",
      captureGroup: 2,
      contextRequired: true,
    },

    // ─────────────────────────────────────────────────────────────────
    // Connection Strings & URLs with Credentials
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Database Connection String",
      regex: /((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql|cockroachdb):\/\/[^\s"']+)/gi,
      description: "Database connection URI (may contain credentials)",
    },
    {
      name: "Password in URL",
      regex: /:\/\/([^:]+):([^@]+)@/g,
      description: "Credentials embedded in a URL",
      captureGroup: 2,
    },

    // ─────────────────────────────────────────────────────────────────
    // Miscellaneous
    // ─────────────────────────────────────────────────────────────────
    {
      name: "Mapbox Token",
      regex: /\b(pk\.[A-Za-z0-9_-]{60,})\b/g,
      description: "Mapbox Public Access Token",
    },
    {
      name: "Algolia API Key",
      regex: /\b([a-f0-9]{32})\b/g,
      description: "Algolia Search API Key (32 hex chars)",
      contextRequired: true,
    },
    {
      name: "Supabase Key",
      regex: /\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
      description: "Supabase anon/service role key (JWT)",
    },
    {
      name: "Sentry DSN",
      regex: /(https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/\d+)/g,
      description: "Sentry DSN with embedded auth key",
    },
    {
      name: "Datadog API Key",
      regex: /\b([a-f0-9]{32})\b/g,
      description: "Datadog API Key (32 hex chars)",
      contextRequired: true,
    },
  ];

  // =====================================================================
  // SANITIZE — Main detection + masking function
  // =====================================================================

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

    const allRules = [...DEFAULT_RULES.filter((r) => !r.contextRequired), ...customRules];
    const extracted = [];
    let maskedText = text;
    const seen = new Set(); // Deduplicate matched values

    maskedText = applyRules(allRules, maskedText, extracted, seen);

    // Context-gated rules: only run if text looks like code/config
    if (looksLikeCodeOrConfig(text)) {
      const contextRules = DEFAULT_RULES.filter((r) => r.contextRequired);
      maskedText = applyRules(contextRules, maskedText, extracted, seen);
    }

    return { maskedText, extracted };
  }

  /**
   * Apply a set of rules to the text and return the masked result.
   */
  function applyRules(rules, maskedText, extracted, seen) {
    for (const rule of rules) {
      // Clone regex to avoid lastIndex mutation
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      const captureGroup = rule.captureGroup || 1;

      let match;
      const replacements = [];
      let iterations = 0;
      const MAX_ITERATIONS = 500; // Safety cap

      while ((match = regex.exec(maskedText)) !== null && iterations < MAX_ITERATIONS) {
        iterations++;
        const fullMatch = match[0];
        const sensitiveValue = match[captureGroup] || match[0];

        // Skip if already masked in a previous rule
        if (seen.has(sensitiveValue)) continue;

        // Skip very short matches (likely false positives)
        if (sensitiveValue.length < 6) continue;

        const stars = "*".repeat(Math.min(sensitiveValue.length, 32));

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
  };
})();

// Make available for both content scripts and test pages
if (typeof module !== "undefined" && module.exports) {
  module.exports = PromptGodSanitizer;
}
