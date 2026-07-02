#!/usr/bin/env node
// install.mjs — wire the pre-check hooks into ~/.claude/settings.json (idempotent).
import fs from "node:fs";
import path from "node:path";
import { PATHS, STATE_DIR, SKILL_DIR, ensureDir, readJsonc, writeJson } from "./lib.mjs";
import { loadSettings, saveSettings, syncHooks, addDenyBackstop, SETTINGS_PATH } from "./settings.mjs";

const USER_RULES_TEMPLATE = `{
  // Your overrides for the pre-check rule library. Deep-merged over rules.default.json.
  //   - Append rules:   "extraDeny" | "extraAllow" | "extraSensitive": [ {"id","re","note"} ]
  //   - Disable a default rule by id, e.g.  "disabled": ["ask.ssh"]
  // 're' is a JavaScript regex source (case-insensitive).
  "extraAllow": [],
  "extraDeny": [],
  "extraSensitive": [],
  "disabled": []
}
`;

// 1) state dirs
for (const d of [STATE_DIR, path.dirname(PATHS.cache), path.dirname(PATHS.log), path.dirname(PATHS.enabledMarker)]) ensureDir(d);

// 2) config + user rules (don't clobber existing)
if (!fs.existsSync(PATHS.config)) fs.copyFileSync(PATHS.configDefault, PATHS.config);
if (!fs.existsSync(PATHS.rulesUser)) fs.writeFileSync(PATHS.rulesUser, USER_RULES_TEMPLATE);
fs.writeFileSync(PATHS.enabledMarker, "on\n");

const cfg = readJsonc(PATHS.config);

// 2b) migration: adopt the narrower read-gate default for installs that still carry the
// old passthrough read category, so secret reads via the Read tool get caught.
if (cfg.categories?.read?.match === "^(Read|Glob|Grep)$") {
  cfg.categories.read = { match: "^Read$", mode: "gate" };
  writeJson(PATHS.config, cfg);
  console.log("  - migrated read category -> ^Read$ (gate) for secret-read protection");
}

// 3) settings.json merge
let settings;
try { settings = loadSettings(); }
catch (e) { console.error(`x Could not parse ${SETTINGS_PATH}: ${e.message}\n  Fix the JSON and re-run install.`); process.exit(1); }

syncHooks(settings, cfg);
const denyAdded = addDenyBackstop(settings);
saveSettings(settings);

// 4) record install
ensureDir(path.dirname(PATHS.install));
fs.writeFileSync(PATHS.install, JSON.stringify({ version: 1, ts: new Date().toISOString(), settingsPath: SETTINGS_PATH, denyAdded, skillDir: SKILL_DIR }, null, 2) + "\n");

console.log("OK pre-check installed.");
console.log(`  - Hooks added to ${SETTINGS_PATH} (backup at settings.json.precheck.bak)`);
console.log(`  - Deny backstop entries added: ${denyAdded.length}`);
console.log(`  - State + config: ${STATE_DIR}`);
console.log("  - Gated categories: " + Object.entries(cfg.categories).filter(([, d]) => d.mode === "gate").map(([n]) => n).join(", "));
console.log(`  - Haiku veto: ${cfg.llm?.enabled ? "on" : "off"}`);
console.log("\n  Next: `node bin/manage.mjs sync` to calibrate against your existing permissions,");
console.log("  and run /hooks to confirm the two PreToolUse hooks are registered.");
