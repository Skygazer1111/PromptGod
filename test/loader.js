/**
 * PromptGod — Node.js Test Loader
 * Shims the browser global scope so the IIFE-based sanitizer modules
 * can be loaded via require() in Node.js for testing.
 *
 * Strategy: Concatenate all module source files and evaluate as a single
 * script. This mirrors how Chrome loads multiple content_scripts files
 * into a shared global scope where const declarations are visible across files.
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SANITIZER_DIR = path.join(__dirname, "..", "src", "sanitizer");

// Load order matters — each module depends on the previous ones
const modules = [
  "rules.js",
  "false-positives.js",
  "entropy.js",
  "candidates.js",
  "rule-engine.js",
  "sanitizer.js",
];

// Concatenate all module source into a single script
let combinedSource = "";
for (const mod of modules) {
  const filePath = path.join(SANITIZER_DIR, mod);
  combinedSource += fs.readFileSync(filePath, "utf-8") + "\n";
}

// Append an expression that yields the final PromptGodSanitizer value
combinedSource += "\nPromptGodSanitizer;\n";

// Create context with all needed globals
const sandbox = {
  console,
  Math,
  Date,
  Set,
  Array,
  RegExp,
  Object,
  String,
  Number,
  Boolean,
  JSON,
  Map,
  WeakMap,
  WeakSet,
  Symbol,
  Promise,
  Proxy,
  Reflect,
  parseInt,
  parseFloat,
  isNaN,
  isFinite,
  undefined,
  Infinity,
  NaN,
  Error,
  TypeError,
  RangeError,
  SyntaxError,
  URIError,
  encodeURIComponent,
  decodeURIComponent,
  // Node module shim (sanitizer.js checks typeof module)
  module: { exports: {} },
};

vm.createContext(sandbox);

// Run the combined script — returns the last expression value (PromptGodSanitizer)
const result = vm.runInContext(combinedSource, sandbox, {
  filename: "sanitizer-combined.js",
});

module.exports = result;
