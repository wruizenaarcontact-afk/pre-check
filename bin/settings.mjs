// settings.mjs — read/modify ~/.claude/settings.json for the pre-check hooks.
import fs from "node:fs";
import path from "node:path";
import { SETTINGS_PATH, PATHS, SKILL_DIR } from "./lib.mjs";
export { SETTINGS_PATH };

// The prompt template's first sentence — used to recognize OUR prompt hook on uninstall.
export const VETO_SENTINEL = "command-safety reviewer for a developer's Claude Code session";

// Catastrophic literals that must be blocked even if the hook fails-open. A settings
// `deny` rule wins over any hook `allow`, so this is the unbypassable floor.
export const DENY_BACKSTOP = [
  "Bash(sudo *)", "Bash(rm -rf /*)", "Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(rm -rf ~/*)",
  "Bash(*--no-preserve-root*)", "Bash(mkfs *)", "Bash(dd of=/dev/*)",
  "Bash(curl * | sh)", "Bash(curl * | bash)", "Bash(wget * | sh)", "Bash(wget * | bash)",
  "Bash(* | nc *)", "Bash(shutdown *)", "Bash(reboot *)",
];

export function loadSettings() {
  const raw = fs.readFileSync(SETTINGS_PATH, "utf8");
  return JSON.parse(raw); // settings.json is strict JSON
}

export function saveSettings(obj) {
  // one-time backup
  const bak = SETTINGS_PATH + ".precheck.bak";
  if (!fs.existsSync(bak)) { try { fs.copyFileSync(SETTINGS_PATH, bak); } catch { /* ignore */ } }
  const tmp = SETTINGS_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  fs.renameSync(tmp, SETTINGS_PATH);
}

function fwd(p) { return p.replace(/\\/g, "/"); }

export function nodeCommand() {
  const node = fwd(process.execPath);
  const script = fwd(path.join(SKILL_DIR, "bin", "precheck.mjs"));
  return `"${node}" "${script}"`;
}

export function postCommand() {
  const node = fwd(process.execPath);
  const script = fwd(path.join(SKILL_DIR, "bin", "postcheck.mjs"));
  return `"${node}" "${script}"`;
}

// Build the command-hook matcher from the union of gate-mode category regexes.
export function gatedMatcher(cfg) {
  const parts = [];
  for (const def of Object.values(cfg.categories || {})) {
    if (def && def.mode === "gate" && def.match) parts.push(def.match);
  }
  return parts.join("|");
}

export function isOurGroup(group) {
  const hooks = (group && group.hooks) || [];
  return hooks.some((h) => (h.command || "").includes("precheck.mjs") || (h.command || "").includes("postcheck.mjs"))
    || hooks.some((h) => h.type === "prompt" && (h.prompt || "").includes(VETO_SENTINEL));
}

export function removeOurHooks(settings) {
  if (!settings.hooks) return settings;
  for (const evt of ["PreToolUse", "PostToolUse"]) {
    if (Array.isArray(settings.hooks[evt])) {
      settings.hooks[evt] = settings.hooks[evt].filter((g) => !isOurGroup(g));
      if (settings.hooks[evt].length === 0) delete settings.hooks[evt];
    }
  }
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  return settings;
}

// Reconcile our hook groups to match the current config (remove + re-add fresh).
export function syncHooks(settings, cfg) {
  removeOurHooks(settings);
  const matcher = gatedMatcher(cfg);
  if (!matcher) return settings; // nothing gated

  settings.hooks = settings.hooks || {};
  settings.hooks.PreToolUse = settings.hooks.PreToolUse || [];

  // (A) deterministic command gate
  settings.hooks.PreToolUse.push({
    matcher,
    hooks: [{ type: "command", command: nodeCommand(), statusMessage: "pre-check: evaluating safety…", timeout: 30 }],
  });

  // (B) keyless Haiku veto — only when LLM on AND bash is gated
  const bashGated = cfg.categories?.bash?.mode === "gate";
  if (cfg.llm?.enabled && bashGated) {
    const veto = fs.readFileSync(PATHS.vetoPrompt, "utf8");
    const ifScope = (cfg.riskyScope || []).join("|");
    const hook = { type: "prompt", prompt: veto, timeout: cfg.llm.timeoutSeconds || 25 };
    if (cfg.llm.model) hook.model = cfg.llm.model;
    if (ifScope) hook.if = ifScope;
    settings.hooks.PreToolUse.push({ matcher: "Bash", hooks: [hook] });
  }

  // (C) learning capture — a PostToolUse hook records approved "asks" so they stop prompting.
  if (cfg.learning?.enabled !== false) {
    settings.hooks.PostToolUse = settings.hooks.PostToolUse || [];
    settings.hooks.PostToolUse.push({
      matcher,
      hooks: [{ type: "command", command: postCommand(), statusMessage: "pre-check: learning…", timeout: 15 }],
    });
  }
  return settings;
}

export function addDenyBackstop(settings) {
  settings.permissions = settings.permissions || {};
  const deny = settings.permissions.deny || (settings.permissions.deny = []);
  const added = [];
  for (const d of DENY_BACKSTOP) { if (!deny.includes(d)) { deny.push(d); added.push(d); } }
  return added;
}

export function removeDenyBackstop(settings) {
  const deny = settings.permissions && settings.permissions.deny;
  if (!Array.isArray(deny)) return;
  settings.permissions.deny = deny.filter((d) => !DENY_BACKSTOP.includes(d));
  if (settings.permissions.deny.length === 0) delete settings.permissions.deny;
}
