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

  // Pre-partition rules once at load time (avoids per-paste array filtering)
  const NON_CONTEXT_RULES = DEFAULT_RULES.filter((r) => !r.contextRequired);
  const CONTEXT_RULES = DEFAULT_RULES.filter((r) => r.contextRequired);

  // Fast pre-scan: skip full regex pipeline on obviously safe text (e.g. plain prose)
  const SECRET_HINT_RE =
    /(?:sk-(?:ant-)?|AKIA[0-9A-Z]|ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|hf_|npm_|pypi-|xox[bprs]-|Bearer\s|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN|AIza[A-Za-z0-9_-]|GOCSPX-|SG\.|key-[A-Za-z0-9]|dop_v1_|sq0atp-|r8_|pk_(?:live_|test_)|sk_(?:live_|test_)|hooks\.slack|whsec_|mongodb(?:\+srv)?:|postgres(?:ql)?:|mysql:|redis:|:\/\/[^:]+:[^@]+@|[A-Z_]{2,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|API_KEY|AUTH|CREDENTIAL|ACCESS)[A-Z_]*\s*=)/i;
  const LONG_TOKEN_RE = /[A-Za-z0-9_\-+/=]{20,}/;

  // Skip expensive entropy pass on very large pastes (regex rules still run)
  const MAX_ENTROPY_CHARS = 500_000;

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
  function mightContainSecrets(text) {
    if (!text || text.length < 8) return false;
    if (SECRET_HINT_RE.test(text)) return true;
    if (text.length >= 16 && LONG_TOKEN_RE.test(text)) return true;
    return false;
  }

  function sanitize(text, customRules = []) {
    // Performance guard: skip very short strings
    if (!text || text.length < 8) return { maskedText: text, extracted: [] };

    // Fast exit for plain prose / UI text with no secret-like patterns
    if (customRules.length === 0 && !mightContainSecrets(text)) {
      return { maskedText: text, extracted: [] };
    }

    const allRules = customRules.length > 0 ? [...NON_CONTEXT_RULES, ...customRules] : NON_CONTEXT_RULES;
    const extracted = [];
    let maskedText = text;
    const seen = new Set(); // Deduplicate matched values
    const isCodeOrConfig = looksLikeCodeOrConfig(text);

    maskedText = applyRules(allRules, maskedText, extracted, seen);

    // Context-gated rules: only run if text looks like code/config
    if (isCodeOrConfig) {
      maskedText = applyRules(CONTEXT_RULES, maskedText, extracted, seen);
    }

    // Entropy pass is expensive — only for config-like text or when regex already matched
    const runEntropy =
      text.length <= MAX_ENTROPY_CHARS &&
      (isCodeOrConfig || extracted.length > 0 || LONG_TOKEN_RE.test(text));
    if (runEntropy) {
      maskedText = applyEntropyDetection(maskedText, extracted, seen);
    }

    return { maskedText, extracted };
  }

  /**
   * Apply a set of rules to the text and return the masked result.
   */
  function applyRules(rules, maskedText, extracted, seen) {
    for (const rule of rules) {
      const regex = rule.regex;
      regex.lastIndex = 0;
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
  // ENTROPY-BASED AUTOMATIC KEY DETECTION
  // =====================================================================

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

  // Entropy threshold: strings above this are likely random/secret
  const ENTROPY_THRESHOLD = 3.5;

  // Length bounds for candidate secrets
  const MIN_SECRET_LENGTH = 16;
  const MAX_SECRET_LENGTH = 512;

  /**
   * Structural heuristics: does a string look like an API key/secret?
   * Checks character composition, length, and mixed character classes.
   * @param {string} str
   * @returns {boolean}
   */
  function isLikelySecret(str) {
    if (!str || str.length < MIN_SECRET_LENGTH || str.length > MAX_SECRET_LENGTH) return false;

    const clean = normalizeCandidate(str);

    // Pure hex digests and UUIDs are operational identifiers, not API secrets
    if (/^[0-9a-f]{40}$/i.test(clean) || /^[0-9a-f]{64}$/i.test(clean)) return false;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(clean)) {
      return false;
    }

    // Dotted domain/namespace paths are infrastructure identifiers, not secrets
    // e.g. networking.k8s.io/v1, apps.kubernetes.io, rbac.authorization.k8s.io/v1beta1
    // Must be all-lowercase to avoid matching API keys like SG.xxx.yyy (SendGrid)
    if (/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+/.test(clean)) return false;

    // Underscore-separated lowercase identifiers are code/config names, not secret values
    // e.g. encryption_key_v2, database_connection_string, app_secret_key
    if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test(clean)) return false;

    // Must be primarily printable ASCII, no whitespace
    if (/\s/.test(str)) return false;

    // Count character classes
    const hasUpper = /[A-Z]/.test(str);
    const hasLower = /[a-z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    const hasSpecial = /[_\-+/=.]/.test(str);

    // Must use at least 2 character classes (mixed)
    const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (classCount < 2) return false;

    // Check for known key character sets:
    // - Base64-like:  [A-Za-z0-9+/=]
    // - Hex:          [0-9a-fA-F]
    // - URL-safe B64: [A-Za-z0-9_-]
    // - Alphanumeric: [A-Za-z0-9]
    const isBase64Like = /^[A-Za-z0-9+/=_\-]+$/.test(str);
    const isHexLike = /^[0-9a-fA-F]+$/.test(str) && str.length >= 32;
    const isAlphanumericPlus = /^[A-Za-z0-9_\-:.+/=]+$/.test(str);

    if (!isBase64Like && !isHexLike && !isAlphanumericPlus) return false;

    // Check entropy threshold
    const entropy = calculateEntropy(str);
    if (entropy < ENTROPY_THRESHOLD) return false;

    return true;
  }

  // =====================================================================
  // FALSE POSITIVE / SAFE STRUCTURE DETECTION
  // =====================================================================

  /**
   * Strip wrapping quotes/brackets before structural checks.
   */
  function normalizeCandidate(str) {
    return str.replace(/^['"\[\]]+|['"\[\]]+$/g, "").trim();
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
    // e.g. networking.k8s.io/v1, apps.kubernetes.io, rbac.authorization.k8s.io/v1beta1
    // Must be all-lowercase to avoid matching API keys like SG.xxx.yyy (SendGrid)
    if (/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+(\/(v\d+[a-z0-9]*|[a-z][a-z0-9._-]*))*$/.test(cleanStr)) {
      return true;
    }

    // Hyphenated lowercase resource names (Kubernetes resources, Docker images, CLI tools)
    // e.g. ingress-nginx-controller, cert-manager, kube-system
    if (/^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)+$/.test(cleanStr)) return true;

    // Underscore-separated lowercase identifiers (config keys, field names)
    // e.g. encryption_key_v2, database_url, app_secret_key
    if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test(cleanStr)) return true;

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
  function detectUnknownSecrets(text) {
    if (!text || text.length < MIN_SECRET_LENGTH) return [];

    const candidates = extractCandidates(text);
    const secrets = [];

    for (const candidate of candidates) {
      const { value, context } = candidate;

      // Run false positive filter
      if (isFalsePositive(value, context)) continue;

      // Run structural + entropy check
      if (isLikelySecret(value)) {
        secrets.push({
          value,
          entropy: calculateEntropy(value),
        });
      }
    }

    return secrets;
  }

  /**
   * Apply entropy-based detection and mask any newly found secrets.
   * Integrates with the main sanitize() pipeline.
   */
  function applyEntropyDetection(maskedText, extracted, seen) {
    const secrets = detectUnknownSecrets(maskedText);

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
    detectUnknownSecrets,
    isLikelySecret,
    isFalsePositive,
  };
})();

// Make available for both content scripts and test pages
if (typeof module !== "undefined" && module.exports) {
  module.exports = PromptGodSanitizer;
}
