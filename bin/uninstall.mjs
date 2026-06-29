#!/usr/bin/env node
// uninstall.mjs — remove ONLY the pre-check hooks + deny backstop from settings.json.
import fs from "node:fs";
import { PATHS, STATE_DIR } from "./lib.mjs";
import { loadSettings, saveSettings, removeOurHooks, removeDenyBackstop, SETTINGS_PATH } from "./settings.mjs";

let settings;
try { settings = loadSettings(); }
catch (e) { console.error(`x Could not parse ${SETTINGS_PATH}: ${e.message}`); process.exit(1); }

removeOurHooks(settings);
removeDenyBackstop(settings);
saveSettings(settings);

try { fs.rmSync(PATHS.enabledMarker, { force: true }); } catch { /* ignore */ }

console.log("OK pre-check uninstalled.");
console.log(`  - Hooks + deny backstop removed from ${SETTINGS_PATH}`);
console.log(`  - Your user state was kept at ${STATE_DIR} (config, cache, logs).`);
console.log(`    Delete that folder to wipe everything, or re-run install to re-enable.`);
