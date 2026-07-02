// lib.mjs — shared helpers for the pre-check skill (no external deps).
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

export const SKILL_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const STATE_DIR = path.join(os.homedir(), ".claude", "precheck");
export const SETTINGS_PATH = path.join(os.homedir(), ".claude", "settings.json");

export const PATHS = {
  config: path.join(STATE_DIR, "config.json"),
  rulesDefault: path.join(SKILL_DIR, "rules", "rules.default.json"),
  configDefault: path.join(SKILL_DIR, "config.default.json"),
  vetoPrompt: path.join(SKILL_DIR, "prompts", "veto.prompt.txt"),
  rulesUser: path.join(STATE_DIR, "rules.user.json"),
  rulesSynced: path.join(STATE_DIR, "rules.synced.json"),
  cache: path.join(STATE_DIR, "cache", "decisions.json"),
  log: path.join(STATE_DIR, "logs", "decisions.jsonl"),
  enabledMarker: path.join(STATE_DIR, "state", "enabled"),
  install: path.join(STATE_DIR, "state", "install.json"),
  grants: path.join(STATE_DIR, "state", "grants.json"),
};

// Lenient JSON: tolerates // and /* */ comments and trailing commas (string-aware).
export function parseJsonc(text) {
  let out = "";
  let inStr = false, quote = "", esc = false, i = 0;
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (inStr) {
      out += c;
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === quote) inStr = false;
      i++; continue;
    }
    if (c === '"' || c === "'") { inStr = true; quote = c; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  out = out.replace(/,(\s*[}\]])/g, "$1"); // strip trailing commas
  return JSON.parse(out);
}

export function readJsonc(file, fallback = undefined) {
  try { return parseJsonc(fs.readFileSync(file, "utf8")); }
  catch (e) { if (fallback !== undefined) return fallback; throw e; }
}

export function readJson(file, fallback = undefined) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (e) { if (fallback !== undefined) return fallback; throw e; }
}

export function deepMerge(base, over) {
  if (over === undefined) return base;
  if (Array.isArray(base) || Array.isArray(over)) return over;
  if (typeof base !== "object" || base === null) return over;
  if (typeof over !== "object" || over === null) return over;
  const out = { ...base };
  for (const k of Object.keys(over)) out[k] = deepMerge(base[k], over[k]);
  return out;
}

export function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }

export function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n");
}

// Convert a "Bash(npx *)" or plain "npx *" glob into an anchored, case-insensitive RegExp.
export function globToRegex(glob) {
  let g = String(glob).trim();
  const m = /^[A-Za-z]+\((.*)\)$/.exec(g); // strip a Tool(...) wrapper
  if (m) g = m[1];
  let re = "";
  for (const ch of g) {
    if (ch === "*") re += ".*";
    else if (/[.+?^${}()|[\]\\]/.test(ch)) re += "\\" + ch;
    else re += ch; // letters, digits, spaces, dashes kept literally
  }
  return new RegExp("^" + re + "$", "i");
}

export function homedir() { return os.homedir(); }
