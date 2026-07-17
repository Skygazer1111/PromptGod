/**
 * PromptGod — Sanitizer Rules
 * Comprehensive detection patterns for sensitive data.
 * Loaded before other sanitizer modules.
 */

const PromptGodRules = (() => {
  "use strict";

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
      multiline: true,
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
      multiline: true,
    },
    {
      name: "SSH Private Key",
      regex: /(-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----)/g,
      description: "OpenSSH Private Key",
      multiline: true,
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
      regex: /(?:^|[-\s;,])([A-Z][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|API_KEY|_AUTH_|CREDENTIAL|ACCESS)[A-Z0-9_]*)\s*=\s*["']?([^"'\s;]+)["']?/gm,
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
      name: "Inline Credential Password",
      regex: /(?<=(?:\/\/|proxy_auth=|auth_proxy=|proxy_uri=)["']?[a-zA-Z0-9._-]+:)(.+)(?=@(?:[a-zA-Z0-9][\w.-]*\.[a-zA-Z0-9._-]+)(?::\d+)?)/gi,
      description: "Password between user: and @host (supports @, #, %, ! in password)",
      captureGroup: 0,
    },
    {
      name: "Custom Prefixed API Secret",
      regex: /\b([a-z]{2,}_(?:sec(?:ret)?|api)_(?:live_|test_)?[a-z0-9_]{16,})\b/gi,
      description: "Custom vendor-prefixed API secret (e.g. cmp_sec_live_...)",
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

  // Pre-partition rules once at load time into 3 tiers:
  // 1. MULTILINE — PEM/RSA blocks that legitimately span lines (run on full text)
  // 2. LINE_RULES — everything else (run per-line to prevent cross-line chomps)
  const MULTILINE_RULES = DEFAULT_RULES.filter((r) => r.multiline);
  const LINE_RULES_NON_CONTEXT = DEFAULT_RULES.filter((r) => !r.multiline && !r.contextRequired);
  const LINE_RULES_CONTEXT = DEFAULT_RULES.filter((r) => !r.multiline && r.contextRequired);

  // Fast pre-scan: skip full regex pipeline on obviously safe text (e.g. plain prose)
  const SECRET_HINT_RE =
    /(?:sk-(?:ant-)?|AKIA[0-9A-Z]|ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|hf_|npm_|pypi-|xox[bprs]-|Bearer\s|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN|AIza[A-Za-z0-9_-]|GOCSPX-|SG\.|key-[A-Za-z0-9]|dop_v1_|sq0atp-|r8_|pk_(?:live_|test_)|sk_(?:live_|test_)|hooks\.slack|whsec_|proxy_auth\s*=|_sec_(?:live_|test_)?|cmp_sec|mongodb(?:\+srv)?:|postgres(?:ql)?:|mysql:|redis:|:\/\/[^:]+:.+@|[A-Z_]{2,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|API_KEY|AUTH|CREDENTIAL|ACCESS)[A-Z_]*\s*=)/i;
  const LONG_TOKEN_RE = /[A-Za-z0-9_\-+#%!=@.$/:]{16,}/;
  const SECURITY_KEYWORD_RE = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL)/i;

  // Skip expensive entropy pass on very large pastes (regex rules still run)
  const MAX_ENTROPY_CHARS = 500_000;

  return {
    DEFAULT_RULES,
    MULTILINE_RULES,
    LINE_RULES_NON_CONTEXT,
    LINE_RULES_CONTEXT,
    SECRET_HINT_RE,
    LONG_TOKEN_RE,
    SECURITY_KEYWORD_RE,
    MAX_ENTROPY_CHARS,
  };
})();
