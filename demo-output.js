const S = require("./sanitizer.js");
const env = `APP_ENV=production
APP_KEY=base64:v3fS92+N1zK8qLpX7xMv4bNjw93D0sZ1a2C3e4F5g6H=
DATABASE_URL=postgresql://db_admin_prod:P%40ssw0rd_9872!@pg-cluster-01.internal.net:5432/finance_db?sslmode=require
JWT_SECRET=8f4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
OAUTH_ENCRYPTION_KEY=6c8b201a74d2fe9365e10cf4a859b207
STRIPE_API_KEY=sk_test_51NxABC123xyz789QWERTYUIOPasdfghjkl00M1N2O3P4Q5R6S7T8U9V0W
STRIPE_WEBHOOK_SECRET=whsec_7b82c39d01e2f3a4b5c6d7e8f9a0b1c2
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_DEFAULT_REGION=us-west-2
S3_BUCKET_NAME=prod-user-tax-documents-us-west-2
SENDGRID_API_KEY=SG.v1_aBcDeFgHiJkLmNoPqRsTuV.wXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/dummy/webhook/url_for_testing`;

const result = S.sanitize(env);
console.log("=== MASKED OUTPUT ===\n");
console.log(result.maskedText);
console.log("\n=== DETECTED SECRETS ===\n");
result.extracted.forEach(e => console.log(`[${e.rule}] ${e.original} → ${e.masked}`));
