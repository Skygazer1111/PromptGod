// Quick Node.js test runner for the sanitizer engine
const S = require("./sanitizer.js");

let pass = 0;
let fail = 0;

function t(cond, name) {
  if (cond) {
    pass++;
    console.log("  ✅", name);
  } else {
    fail++;
    console.log("  ❌ FAIL:", name);
  }
}

console.log("\n=== 1. Hardcoded Regex Patterns ===");
t(S.sanitize("My key is sk-abc123XYZ456def789ghij").extracted.length > 0, "OpenAI key");
t(S.sanitize("Use key AKIAIOSFODNN7EXAMPLE here").extracted.length > 0, "AWS key");
t(S.sanitize("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij").extracted.length > 0, "GitHub token");
t(S.sanitize("Auth: github_pat_ABCDEFGHIJKLMNOPQRSTUVab").extracted.length > 0, "GitHub fine-grained");
t(S.sanitize("Key: AIzaSyD-abcdefghij1234567890klmnop-qr").extracted.length > 0, "Google API Key");
t(S.sanitize("Token: xoxb-123456789012-abcdefgh").extracted.length > 0, "Slack token");
t(S.sanitize("sk_test_ABCDEFGHIJKLmnopqrstuvwxyz").extracted.length > 0, "Stripe key");
t(S.sanitize("Token: hf_InvalidTokenForTestingPurposes12345").extracted.length > 0, "HuggingFace token");
t(S.sanitize("glpat-ABCDE12345FGHIJ67890xyz").extracted.length > 0, "GitLab token");
t(S.sanitize("SG.abcdefghijklmnopqrstuvwx.ABCDEFGHIJKLmnopqrstuvwx").extracted.length > 0, "SendGrid key");

console.log("\n=== 2. Partial Masking ===");
const pr = S.sanitize("Key: sk-abc123XYZ456def789ghij");
if (pr.extracted.length > 0) {
  const m = pr.extracted[0].masked;
  const o = pr.extracted[0].original;
  const vl = Math.ceil(o.length / 4);
  t(m.startsWith(o.substring(0, vl)), "First 1/4 visible");
  t(m.includes("*"), "Contains stars");
  t(!m.substring(vl).includes(o.substring(vl)), "Last 3/4 is masked");
}

console.log("\n=== 3. Custom-Named Keys ===");
t(S.sanitize('MY_CUSTOM_API_KEY="a8F3b7C9d2E1f4G5h6I7j8K9l0M1n2O3"').extracted.length > 0, "Custom env key");
t(S.sanitize('db_connection_secret="xK9mP2nQ7rS4tU6vW8yZ1aB3cD5eF0gH"').extracted.length > 0, "DB password custom name");
t(S.sanitize('{"myServiceToken": "Xt7yR9pL2mK4nQ6wS8vU0zA1bC3dE5fG"}').extracted.length > 0, "Custom JSON key");
t(S.sanitize("production_key: aB3cD5eF0gH7iJ9kL1mN2oP4qR6sT8uV").extracted.length > 0, "Custom YAML key");
t(S.sanitize('export INTERNAL_SERVICE_CREDENTIAL="pQ7rS4tU6vW8yZ1aB3cD5eF0gH2iJ9kL"').extracted.length > 0, "export custom key");
t(S.sanitize("WEBHOOK_SECRET='mK4nQ6wS8vU0zA1bC3dE5fG7iJ9kL2pR'").extracted.length > 0, "Single-quoted custom key");

console.log("\n=== 4. Entropy Detection ===");
t(S.isLikelySecret("aB3cD5eF0gH7iJ9kL1mN2oP4qR6sT8uV"), "High entropy base64");
t(S.isLikelySecret("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), "High entropy hex");
t(S.isLikelySecret("xK9m-P2nQ_7rS4tU-6vW8yZ_1aB3cD5eF"), "URL-safe base64");
t(S.isLikelySecret("aB3cD5eF0g+H7iJ9kL1/mN2oP4qR6sT8="), "Base64 with +/=");

console.log("\n=== 5. False Positive Resistance ===");
t(S.sanitize("The quick brown fox jumps over the lazy dog in the afternoon").extracted.length === 0, "English text — no false pos");
t(S.isFalsePositive("https://docs.example.com/api/v2/auth", ""), "URL is false positive");
t(S.isFalsePositive("/usr/local/bin/node_modules", ""), "Unix path is false positive");
t(S.isFalsePositive("C:\\Users\\skyga\\Documents", ""), "Windows path is false positive");
t(S.isFalsePositive("#7c3aed", ""), "CSS hex color is false positive");
t(S.isFalsePositive("16.14.2-alpine3.17", ""), "Semver is false positive");
t(S.isFalsePositive("document.getElementById()", ""), "Function call is false positive");
t(S.isFalsePositive("aaaaaaaaaaaaaaaa", ""), "Repeated chars is false positive");
t(S.isFalsePositive("my-custom-module-name", ""), "Hyphenated name is false positive");
t(S.isFalsePositive("data:image/png;base64,iVBOR", ""), "Data URI is false positive");
t(S.isFalsePositive("sha256-ABCDabcd1234567890abcdef", ""), "SRI hash is false positive");
t(S.isFalsePositive("user.name@example.com", ""), "Email is false positive");
t(S.isFalsePositive("DB_HOST=localhost", ""), "Key=value assignment is false positive");
t(S.isFalsePositive("APP_NAME=PromptGod", ""), "Key=value assignment is false positive (2)");
t(!S.isLikelySecret("abc123"), "Short string not secret");
t(!S.isLikelySecret(""), "Empty string not secret");
t(!S.isLikelySecret("this has spaces in it yes"), "Spaces not secret");
t(S.isFalsePositive("OAUTH_ENCRYPTION_KEY", ""), "UPPERCASE env var name is false positive");
t(S.isFalsePositive("STRIPE_WEBHOOK_SECRET", ""), "STRIPE_WEBHOOK_SECRET is false positive");
t(S.isFalsePositive("AWS_DEFAULT_REGION", ""), "AWS_DEFAULT_REGION is false positive");
t(S.isFalsePositive("SENDGRID_API_KEY", ""), "SENDGRID_API_KEY is false positive");
t(S.isFalsePositive("SLACK_WEBHOOK_URL", ""), "SLACK_WEBHOOK_URL is false positive");
t(S.isFalsePositive("S3_BUCKET_NAME", ""), "S3_BUCKET_NAME is false positive");

console.log("\n=== 6. Multi-line / Mixed Content ===");
const envFile = `# Database config
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
MY_SUPER_SECRET_KEY=aB3cD5eF0gH7iJ9kL1mN2oP4qR6sT8uV
APP_NAME=PromptGod
CUSTOM_AUTH_TOKEN=xK9mP2nQ7rS4tU6vW8yZ1aB3cD5eF0gH
LOG_LEVEL=debug`;

const er = S.sanitize(envFile);
t(er.extracted.length >= 2, ".env detects secrets (" + er.extracted.length + " found)");
t(er.maskedText.includes("DB_HOST=localhost"), ".env preserves DB_HOST=localhost");
t(er.maskedText.includes("APP_NAME=PromptGod"), ".env preserves APP_NAME=PromptGod");
t(er.maskedText.includes("LOG_LEVEL=debug"), ".env preserves LOG_LEVEL=debug");

const jsonConfig = `{
  "appName": "MyApp",
  "version": "2.1.0",
  "apiSecret": "Xt7yR9pL2mK4nQ6wS8vU0zA1bC3dE5fG",
  "debug": true,
  "serviceToken": "pQ7rS4tU6vW8yZ1aB3cD5eF0gH2iJ9kL",
  "region": "us-east-1"
}`;
const jr = S.sanitize(jsonConfig);
t(jr.extracted.length >= 2, "JSON detects secrets (" + jr.extracted.length + " found)");
t(jr.maskedText.includes('"appName": "MyApp"'), "JSON preserves appName");

// User's real-world .env test case — verify key names are NOT starred
const realEnv = `APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:v3fS92+N1zK8qLpX7xMv4bNjw93D0sZ1a2C3e4F5g6H=
APP_URL=https://core-api.internal.prod.net
PORT=8443
DATABASE_URL=postgresql://db_admin_prod:P%40ssw0rd_9872!@pg-cluster-01.internal.net:5432/finance_db?sslmode=require
DB_POOL_MAX=20
REDIS_HOST=redis-cache-private.c3.us-east-1.cache.amazonaws.com
REDIS_PORT=6379
REDIS_PASSWORD=rc_7a90efbc61a0b3e5d7c8192a
JWT_SECRET=8f4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
OKTA_CLIENT_ID=0oa1abc2def3GHI4j5k6
OKTA_CLIENT_SECRET=okta_sk_prod_9F8E7D6C5B4A3G2F1E0D
OAUTH_ENCRYPTION_KEY=6c8b201a74d2fe9365e10cf4a859b207
STRIPE_API_KEY=sk_test_51NxABC123xyz789QWERTYUIOPasdfghjkl00M1N2O3P4Q5R6S7T8U9V0W
STRIPE_WEBHOOK_SECRET=whsec_7b82c39d01e2f3a4b5c6d7e8f9a0b1c2
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-west-2
S3_BUCKET_NAME=prod-user-tax-documents-us-west-2
SENDGRID_API_KEY=SG.v1_aBcDeFgHiJkLmNoPqRsTuV.wXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/dummy/webhook/url_for_testing`;

const rr = S.sanitize(realEnv);
t(rr.extracted.length >= 5, "Real .env: detects multiple secrets (" + rr.extracted.length + " found)");
// Key names must be fully visible (NOT starred)
t(rr.maskedText.includes("OAUTH_ENCRYPTION_KEY="), "Real .env: OAUTH_ENCRYPTION_KEY name preserved");
t(rr.maskedText.includes("STRIPE_WEBHOOK_SECRET="), "Real .env: STRIPE_WEBHOOK_SECRET name preserved");
t(rr.maskedText.includes("STRIPE_API_KEY="), "Real .env: STRIPE_API_KEY name preserved");
t(rr.maskedText.includes("AWS_DEFAULT_REGION=us-west-2"), "Real .env: AWS_DEFAULT_REGION fully preserved");
t(rr.maskedText.includes("SENDGRID_API_KEY="), "Real .env: SENDGRID_API_KEY name preserved");
t(rr.maskedText.includes("SLACK_WEBHOOK_URL="), "Real .env: SLACK_WEBHOOK_URL name preserved");
t(rr.maskedText.includes("S3_BUCKET_NAME="), "Real .env: S3_BUCKET_NAME name preserved");
t(rr.maskedText.includes("APP_ENV=production"), "Real .env: safe APP_ENV preserved");
t(rr.maskedText.includes("DB_POOL_MAX=20"), "Real .env: safe DB_POOL_MAX preserved");

console.log("\n=== 7. Edge Cases ===");
t(S.sanitize("").extracted.length === 0, "Empty string: no errors");
t(S.sanitize(null).maskedText === null, "Null returns null");
t(S.sanitize(undefined).maskedText === undefined, "Undefined returns undefined");
t(S.sanitize("hi").extracted.length === 0, "Short string skipped");
t(S.sanitize("!@#$%^&*()_+-=[]{}|;:',.<>?/~`").extracted.length === 0, "Special chars only: no FP");
t(S.sanitize("sk-abc123XYZ456def789ghij is my key").extracted.length > 0, "Key at start detected");
t(S.sanitize("My key is sk-abc123XYZ456def789ghij").extracted.length > 0, "Key at end detected");
t(S.sanitize("Key1: sk-abc123XYZ456def789ghij and Key2: sk-abc123XYZ456def789ghij").extracted.length === 1, "Duplicate keys deduplicated");

console.log("\n=== 8. Entropy Function ===");
t(S.calculateEntropy("aaaaaaaaaa") === 0, "Repeated char: entropy = 0");
t(Math.abs(S.calculateEntropy("abababababababab") - 1.0) < 0.01, "Two chars: entropy ≈ 1.0");
t(S.calculateEntropy("aB3cD5eF0gH7iJ9kL1mN2oP4qR6sT8uV") > 3.5, "Random string: entropy > 3.5");
t(S.calculateEntropy("password") < 3.5, "Word 'password': entropy < 3.5");
t(S.calculateEntropy("") === 0, "Empty: entropy = 0");
t(S.calculateEntropy(null) === 0, "Null: entropy = 0");

console.log(`\n${"=".repeat(50)}`);
console.log(`RESULTS: ${pass} passed, ${fail} failed, ${pass + fail} total`);
console.log("=".repeat(50));
process.exit(fail > 0 ? 1 : 0);
