#!/usr/bin/env node
// manage.mjs — operator CLI for the pre-check gate.
//   status | menu | on | off | mode <enforce|report>
//   set <cat> <gate|passthrough> | category add|remove ... | llm <on|off> [model]
//   sync | rules | logs [N] | clear-cache
//   grant-once "<cmd>" | promote "<cmd>" | decline-promote "<cmd>"
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { PATHS, STATE_DIR, SKILL_DIR, readJsonc, readJson, writeJson, ensureDir, globToRegex } from "./lib.mjs";
import { loadSettings, saveSettings, syncHooks, removeOurHooks, isOurGroup, SETTINGS_PATH } from "./settings.mjs";

const args = process.argv.slice(2);
const cmd = (args[0] || "status").toLowerCase();

const nowSec = () => Math.floor(Date.now() / 1000);
function getConfig() {
  if (!fs.existsSync(PATHS.config)) { fail("config not found — run install first (node bin/install.mjs)"); }
  return readJsonc(PATHS.config);
}
function setConfig(cfg) { writeJson(PATHS.config, cfg); }
function fail(msg) { console.error("x " + msg); process.exit(1); }
function ok(msg) { console.log("OK " + msg); }
function grantSig(c) { return crypto.createHash("sha256").update(String(c).trim().replace(/\s+/g, " ")).digest("hex"); }

function reconcile(cfg) {
  try { const s = loadSettings(); syncHooks(s, cfg); saveSettings(s); }
  catch (e) { console.error("  warn: could not reconcile settings.json: " + e.message); }
}
function hooksInstalled() {
  try { const s = loadSettings(); return !!(s.hooks?.PreToolUse || []).some(isOurGroup); } catch { return false; }
}
function tailLines(file, n) {
  try { return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).slice(-n); } catch { return []; }
}

// ── status / menu ─────────────────────────────────────────────────────────────
function cmdStatus() {
  const cfg = getConfig();
  console.log("pre-check status");
  console.log("  enabled:        " + (cfg.enabled !== false));
  console.log("  mode:           " + (cfg.mode || "enforce") + (cfg.mode === "report" ? "  (dry-run: logs, enforces nothing)" : ""));
  console.log("  hooks installed:" + (hooksInstalled() ? " yes" : " NO (run install)"));
  console.log("  categories:");
  for (const [n, d] of Object.entries(cfg.categories || {})) console.log(`     - ${n.padEnd(6)} ${String(d.mode).padEnd(11)} (${d.match})`);
  console.log("  Haiku veto:     " + (cfg.llm?.enabled ? `on (${cfg.llm.model || "default"})` : "off"));
  console.log("  riskyScope:     " + (cfg.riskyScope?.length || 0) + " patterns");
  console.log("  cache entries:  " + Object.keys(readJson(PATHS.cache, {}) || {}).length);
  const grants = readJson(PATHS.grants, {}) || {};
  const liveGrants = Object.values(grants).filter((g) => g.remaining > 0 && (!g.exp || g.exp >= nowSec())).length;
  console.log("  live grants:    " + liveGrants);

  // decision counts + top rules from the log
  const lines = tailLines(PATHS.log, 2000);
  const counts = {}, rules = {};
  for (const l of lines) { try { const r = JSON.parse(l); if (!r.decision) continue; const d = r.enforced === false ? `would:${r.wouldBe}` : r.decision; counts[d] = (counts[d] || 0) + 1; if (r.ruleId) rules[r.ruleId] = (rules[r.ruleId] || 0) + 1; } catch { /* skip */ } }
  console.log(`  decisions (last ${lines.length}): ` + (Object.entries(counts).map(([k, v]) => `${k}=${v}`).join("  ") || "none yet"));
  const top = Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (top.length) console.log("  top rules:      " + top.map(([k, v]) => `${k}(${v})`).join("  "));
}

function cmdMenu() {
  console.log(`/pre-check — auto-approve / safety gate.  Ask me to run any of these:

  STATUS      "pre-check status"                 → current state, categories, counts
  ON / OFF    "turn pre-check off" / "on"        → master switch (off = normal prompting)
  MODE        "pre-check dry-run" / "enforce"    → report-only (log, don't block) vs enforce
  RISK        "risk trusting" / "balanced"       → prompt appetite (cautious | balanced | trusting)
  COMPANION   "companion on" / "off"             → combo with Claude Code Auto mode (saves classifier tokens)
  SAVINGS     "pre-check savings"                → estimated classifier round-trips / tokens avoided
  CATEGORY    "gate web" / "stop gating edits"   → set bash|edit|read|web|mcp to gate|passthrough
  ADD CAT     "gate the Gmail MCP tools"         → add a custom category (tool-name regex)
  HAIKU VETO  "turn the Haiku veto off/on"       → keyless LLM veto for marginal commands
  CALIBRATE   "sync with my permissions"         → import settings.json allow-list (reviewed)
  RULES       "let me edit the rules"            → where to add extraAllow/extraDeny
  LOGS        "show the pre-check log"           → recent decisions
  EXPORT      "export feedback"                  → redacted, shareable usage report
  ESCALATE    (automatic on a hard deny)         → I ask you, then one-time grant + retry

Everything runs via  node ~/.claude/skills/pre-check/bin/manage.mjs <command>.`);
}

// ── toggles ─────────────────────────────────────────────────────────────────
function cmdOnOff(on) {
  const cfg = getConfig();
  cfg.enabled = on;
  setConfig(cfg);
  ensureDir(path.dirname(PATHS.enabledMarker));
  if (on) fs.writeFileSync(PATHS.enabledMarker, "on\n"); else fs.rmSync(PATHS.enabledMarker, { force: true });
  // The Haiku veto is a separate prompt hook that can't read our config, so a real on/off must
  // ADD/REMOVE the hooks in settings.json — not just flip the flag (else the veto keeps firing).
  try {
    const s = loadSettings();
    if (on) syncHooks(s, cfg); else removeOurHooks(s);
    saveSettings(s);
  } catch (e) { console.error("  warn: could not update settings.json hooks: " + e.message); }
  ok(`gate is now ${on ? "ON" : "OFF"}` + (on ? "" : " (hooks removed; normal Claude Code prompting applies)"));
}

function cmdMode() {
  const m = (args[1] || "").toLowerCase();
  if (!["enforce", "report"].includes(m)) fail("usage: mode <enforce|report>");
  const cfg = getConfig();
  cfg.mode = m;
  setConfig(cfg);
  ok(`mode = ${m}` + (m === "report" ? " (dry-run: logs would-be decisions, enforces nothing)" : ""));
}

function cmdSet() {
  const cat = args[1], mode = args[2];
  if (!cat || !["gate", "passthrough"].includes(mode)) fail("usage: set <category> <gate|passthrough>");
  const cfg = getConfig();
  if (!cfg.categories?.[cat]) fail(`unknown category '${cat}'. Known: ${Object.keys(cfg.categories || {}).join(", ")}`);
  cfg.categories[cat].mode = mode;
  setConfig(cfg); reconcile(cfg);
  ok(`category '${cat}' -> ${mode}`);
}

function cmdCategory() {
  const sub = (args[1] || "").toLowerCase();
  const cfg = getConfig();
  if (sub === "add") {
    const [, , name, regex, mode = "gate"] = args;
    if (!name || !regex) fail('usage: category add <name> "<toolNameRegex>" [gate|passthrough]');
    try { new RegExp(regex); } catch { fail("invalid regex: " + regex); }
    cfg.categories[name] = { match: regex, mode: mode === "passthrough" ? "passthrough" : "gate" };
    setConfig(cfg); reconcile(cfg);
    ok(`added category '${name}' = ${regex} (${cfg.categories[name].mode})`);
  } else if (sub === "remove") {
    const name = args[2];
    if (!name || !cfg.categories?.[name]) fail("usage: category remove <existing-name>");
    delete cfg.categories[name];
    setConfig(cfg); reconcile(cfg);
    ok(`removed category '${name}'`);
  } else fail("usage: category add|remove ...");
}

function cmdLlm() {
  const state = (args[1] || "").toLowerCase();
  if (!["on", "off"].includes(state)) fail("usage: llm <on|off> [model]");
  const cfg = getConfig();
  cfg.llm = cfg.llm || {};
  cfg.llm.enabled = state === "on";
  if (args[2]) cfg.llm.model = args[2];
  setConfig(cfg); reconcile(cfg);
  ok(`Haiku veto ${state}` + (cfg.llm.model ? ` (model: ${cfg.llm.model})` : ""));
}

// ── calibrate (AI-assisted sync) ──────────────────────────────────────────────
function cmdSync() {
  const cfg = getConfig();
  let settings;
  try { settings = loadSettings(); } catch (e) { fail("could not read settings.json: " + e.message); }
  const perms = settings.permissions || {};
  const ss = cfg.syncSettings || {};
  const out = { _generated: true, _note: "Generated by `manage.mjs sync` from settings.json. Re-runnable; do not hand-edit.", ts: new Date().toISOString(), syncedTrust: [], denyBash: [], sensitiveBash: [] };

  const bashGlobs = (arr) => (arr || []).filter((p) => typeof p === "string" && /^Bash\(/.test(p));
  let i = 0;
  if (ss.importAllow !== false) {
    for (const p of bashGlobs(perms.allow)) out.syncedTrust.push({ id: `synced.allow.${i++}`, re: globToRegex(p).source, note: `trusted via settings.json allow (${p})` });
  }
  if (ss.mirrorDenyAsk !== false) {
    for (const p of bashGlobs(perms.deny)) out.denyBash.push({ id: `synced.deny.${i++}`, re: globToRegex(p).source, note: `mirrors settings.json deny (${p})` });
    for (const p of bashGlobs(perms.ask)) out.sensitiveBash.push({ id: `synced.ask.${i++}`, re: globToRegex(p).source, note: `mirrors settings.json ask (${p})` });
  }
  writeJson(PATHS.rulesSynced, out);

  ok("calibrated against settings.json permissions");
  console.log(`  - imported trust:   ${out.syncedTrust.length}  (rescues unknowns; can NEVER override a deny/sensitive rule)`);
  console.log(`  - mirrored deny:    ${out.denyBash.length}`);
  console.log(`  - mirrored ask:     ${out.sensitiveBash.length}`);
  console.log(`  - written to:       ${PATHS.rulesSynced}`);

  // ── review report for the agent to reason over (Change 4) ──
  const broad = bashGlobs(perms.allow).filter((p) => /\*/.test(p));
  console.log("\n  REVIEW (for Claude): imported trust cannot override the gate's deny/sensitive rules,");
  console.log("  so broad allows stay safe. Dangerous sub-cases that remain DENIED regardless:");
  console.log("    git → force-push / reset --hard / clean -fd; rm → rm -rf of / ~ or system paths;");
  console.log("    sudo, curl|sh, DROP/TRUNCATE, cloud/k8s/terraform delete, npm i -g.");
  if (broad.length) {
    console.log(`  ${broad.length} broad allow pattern(s) imported (examples):`);
    for (const p of broad.slice(0, 10)) console.log("    - " + p);
    console.log("  If any should be tightened further, add a scoped extraDeny in rules.user.json.");
  }
}

// ── escalation: one-time grants + adaptive promotion ──────────────────────────
function cmdGrantOnce() {
  const command = args[1];
  if (!command) fail('usage: grant-once "<exact command>"');
  const cfg = getConfig();
  const esc = cfg.escalation || {};
  const g = readJson(PATHS.grants, {}) || {};
  const sig = grantSig(command);
  const e = g[sig] || { cmd: command, approvals: 0, declined: false, declineCount: 0 };
  e.cmd = command;
  e.remaining = 1;
  e.exp = nowSec() + (esc.ttlSeconds || 300);
  e.approvals = (e.approvals || 0) + 1;
  g[sig] = e;
  ensureDir(path.dirname(PATHS.grants));
  fs.writeFileSync(PATHS.grants, JSON.stringify(g, null, 2));
  ok(`one-time grant issued (valid ${esc.ttlSeconds || 300}s, single use). Retry the command now.`);
  const threshold = esc.promoteAfter || 3;
  if (e.approvals >= threshold && !e.declined) {
    console.log(`  PROMOTE-SUGGESTED: you have approved this command ${e.approvals}× — ask the user if they`);
    console.log(`  want it permanent. If yes: manage.mjs promote "<command>".  If no: manage.mjs decline-promote "<command>".`);
  }
}

function cmdPromote() {
  const command = args[1];
  if (!command) fail('usage: promote "<exact command>"');
  const user = fs.existsSync(PATHS.rulesUser) ? (readJsonc(PATHS.rulesUser, {}) || {}) : {};
  user.extraAllow = user.extraAllow || [];
  const re = globToRegex(command).source; // exact (no glob chars) → anchored exact match
  if (!user.extraAllow.some((r) => r && r.re === re)) {
    user.extraAllow.push({ id: `promoted.${user.extraAllow.length}`, re, note: `promoted from repeated one-time grants (${command})` });
  }
  writeJson(PATHS.rulesUser, user);
  // clear the ledger entry
  const g = readJson(PATHS.grants, {}) || {};
  delete g[grantSig(command)];
  fs.writeFileSync(PATHS.grants, JSON.stringify(g, null, 2));
  ok(`promoted to a permanent scoped allow (rules.user.json). It will no longer be denied.`);
}

function cmdDeclinePromote() {
  const command = args[1];
  if (!command) fail('usage: decline-promote "<exact command>"');
  const g = readJson(PATHS.grants, {}) || {};
  const sig = grantSig(command);
  const e = g[sig] || { cmd: command, approvals: 0, declineCount: 0 };
  e.declined = true; e.declineCount = (e.declineCount || 0) + 1; e.approvals = 0;
  g[sig] = e;
  ensureDir(path.dirname(PATHS.grants));
  fs.writeFileSync(PATHS.grants, JSON.stringify(g, null, 2));
  ok("kept as one-time-grant only; will re-offer promotion after a few more approvals.");
}

// ── misc ─────────────────────────────────────────────────────────────────────
function cmdRules() {
  if (!fs.existsSync(PATHS.rulesUser)) fail("run install first");
  console.log("Default rules:  " + PATHS.rulesDefault);
  console.log("Your overrides: " + PATHS.rulesUser);
  console.log("Synced (sync):  " + PATHS.rulesSynced);
  console.log("\nEdit your overrides file to add extraAllow / extraDeny / extraSensitive or disable rules by id.");
}

function cmdLogs() {
  const n = parseInt(args[1], 10) || 20;
  const lines = tailLines(PATHS.log, n);
  if (!lines.length) { console.log("(no decisions logged yet)"); return; }
  for (const l of lines) {
    try {
      const r = JSON.parse(l);
      const dec = r.enforced === false ? `would:${r.wouldBe}` : (r.decision || "?");
      console.log(`${r.ts}  ${dec.toUpperCase().padEnd(11)} ${r.category}/${r.ruleId}${r.viaLlmNet ? " [llm]" : ""}${r.cacheHit ? " [cache]" : ""}  ${(r.snippet || "").slice(0, 80)}`);
    } catch { console.log(l); }
  }
}

function cmdClearCache() {
  ensureDir(path.dirname(PATHS.cache));
  fs.writeFileSync(PATHS.cache, "{}");
  ok("decision cache cleared");
}

// ── feedback export (redacted, shareable) ─────────────────────────────────────
function skillVersion() {
  try { const t = fs.readFileSync(path.join(SKILL_DIR, "SKILL.md"), "utf8"); const m = /^version:\s*(.+)$/m.exec(t); return m ? m[1].trim() : "unknown"; }
  catch { return "unknown"; }
}
function redactToken(tok) {
  const t = String(tok || "").replace(/^['"]|['"]$/g, "");
  if (!t) return "<empty>";
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) return "<env=>";                                  // VAR=value assignment
  if (/[\/\\]/.test(t) || /^[A-Za-z]:$/i.test(t) || t.startsWith("~") || t.startsWith(".")) return "<path>";
  if (/^[A-Za-z][\w.-]{0,39}$/.test(t)) return t;                                            // a plain command name
  return "<other>";
}
// A command "shape": redacted first token + salted hash of the rest. Emits no raw text, but the
// same command maps to the same shape within one export so frequencies still aggregate.
function shapeOf(snippet, salt) {
  const s = String(snippet || "").trim();
  if (!s) return "<empty>";
  if (/^[0-9a-f]{12}$/.test(s)) return "hash:" + s;                                          // logCommandText:false already hashed it
  const first = s.split(/\s+/)[0] || "";
  const rest = s.slice(first.length);
  const h = crypto.createHash("sha256").update(salt + rest).digest("hex").slice(0, 8);
  return redactToken(first) + (rest.trim() ? "#" + h : "");
}
function cmdExportFeedback() {
  const raw = args.includes("--raw");
  const consent = args.includes("--i-consent");
  if (raw && !consent) fail("--raw includes real command text — re-run with:  export-feedback --raw --i-consent");
  const cfg = getConfig();
  const salt = crypto.randomBytes(8).toString("hex");
  const lines = tailLines(PATHS.log, 100000);

  const totals = {}, byCategory = {}, byRule = {}, friction = {};
  let records = 0, errors = 0, firstTs = null, lastTs = null;
  for (const l of lines) {
    let r; try { r = JSON.parse(l); } catch { continue; }
    if (r.event === "error") { errors++; continue; }
    if (!r.decision) continue;
    records++;
    if (r.ts) { if (!firstTs) firstTs = r.ts; lastTs = r.ts; }
    const dec = r.enforced === false ? `would:${r.wouldBe}` : r.decision;
    totals[dec] = (totals[dec] || 0) + 1;
    const cat = r.category || "?";
    (byCategory[cat] = byCategory[cat] || {})[dec] = (byCategory[cat][dec] || 0) + 1;
    if (r.ruleId) byRule[r.ruleId] = (byRule[r.ruleId] || 0) + 1;
    const eff = r.enforced === false ? r.wouldBe : r.decision;              // what caused friction
    if (eff === "ask" || eff === "deny") {
      const shape = raw ? String(r.snippet || "") : shapeOf(r.snippet, salt);
      const key = `${r.ruleId || "?"} | ${shape}`;
      friction[key] = (friction[key] || 0) + 1;
    }
  }
  const topRules = Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 15);
  const topFriction = Object.entries(friction).sort((a, b) => b[1] - a[1]).slice(0, 25);

  const report = {
    _banner: raw
      ? "pre-check feedback export — RAW MODE: contains real command text you chose to share. Review before sending."
      : "pre-check feedback export — redacted: decision counts + command SHAPES only (first token + salted hash); no raw command text or file contents.",
    _privacy: "Please review before sharing. Share via the pre-check repo issues to help improve the rules.",
    generatedAt: new Date().toISOString(),
    redacted: !raw,
    config: {
      version: skillVersion(),
      mode: cfg.mode || "enforce",
      risk: cfg.risk || "balanced",
      llm: cfg.llm?.enabled ? (cfg.llm.model || "on") : "off",
      logCommandText: cfg.logging?.logCommandText !== false,
      categories: Object.fromEntries(Object.entries(cfg.categories || {}).map(([k, v]) => [k, v.mode])),
    },
    window: { records, errors, firstTs, lastTs },
    totals,
    byCategory,
    topRules: topRules.map(([id, n]) => ({ id, n })),
    topFriction: topFriction.map(([group, n]) => ({ group, n })),
  };

  const dir = path.join(STATE_DIR, "export");
  ensureDir(dir);
  let idx = 1;
  while (fs.existsSync(path.join(dir, `feedback-${idx}.json`))) idx++;
  const outFile = path.join(dir, `feedback-${idx}.json`);
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2) + "\n");

  ok(`feedback export written: ${outFile}` + (raw ? "   (RAW — contains real commands)" : "   (redacted)"));
  console.log(`  records: ${records}  errors: ${errors}  window: ${firstTs || "?"} .. ${lastTs || "?"}`);
  console.log("  decisions: " + (Object.entries(totals).map(([k, v]) => `${k}=${v}`).join("  ") || "none yet"));
  if (topRules.length) console.log("  top rules: " + topRules.slice(0, 8).map(([k, v]) => `${k}(${v})`).join("  "));
  console.log(raw ? "  RAW file — review before sharing." : "  Redacted — safe to share; contains no raw command text.");
}

// ── risk dial (decisionPolicy preset) ─────────────────────────────────────────
const RISK_PRESETS = {
  cautious: { decisionPolicy: { marginalWhenLlmOn: "ask",   marginalWhenLlmOff: "ask" },   threshold: 3 },
  balanced: { decisionPolicy: { marginalWhenLlmOn: "allow", marginalWhenLlmOff: "ask" },   threshold: 1 },
  trusting: { decisionPolicy: { marginalWhenLlmOn: "allow", marginalWhenLlmOff: "allow" }, threshold: 1 },
};
function cmdRisk() {
  const preset = (args[1] || "").toLowerCase();
  if (!RISK_PRESETS[preset]) fail("usage: risk <cautious|balanced|trusting>");
  const cfg = getConfig();
  const p = RISK_PRESETS[preset];
  cfg.decisionPolicy = { ...(cfg.decisionPolicy || {}), ...p.decisionPolicy };
  cfg.learning = cfg.learning || {};
  cfg.learning.threshold = p.threshold;
  cfg.risk = preset;
  setConfig(cfg);
  ok(`risk preset = ${preset}`);
  console.log(`  marginal risk-scoped (veto): ${p.decisionPolicy.marginalWhenLlmOn === "allow" ? "veto-allow" : "ask"}`);
  console.log(`  marginal true-unknown:       ${p.decisionPolicy.marginalWhenLlmOff === "allow" ? "allow" : "ask"}`);
  console.log(`  learn approved asks after:   ${p.threshold}`);
  console.log("  deny rules + settings.json deny backstop + secret-read asks are UNCHANGED in every preset.");
}

// ── companion mode (combo with Claude Code Auto mode) ─────────────────────────
function cmdCompanion() {
  const state = (args[1] || "").toLowerCase();
  if (!["on", "off"].includes(state)) fail("usage: companion <on|off>");
  const cfg = getConfig();
  if (state === "on") {
    if (!fs.existsSync(PATHS.companionBackup)) {              // snapshot what we change (don't clobber an existing backup)
      writeJson(PATHS.companionBackup, {
        companion: cfg.companion === true,
        llm: !!(cfg.llm && cfg.llm.enabled),
        promoteToSettings: !!(cfg.syncSettings && cfg.syncSettings.promoteToSettings),
      });
    }
    cfg.companion = true;
    cfg.llm = cfg.llm || {}; cfg.llm.enabled = false;                                  // zero pre-check tokens (removes veto hook)
    cfg.syncSettings = cfg.syncSettings || {}; cfg.syncSettings.promoteToSettings = true; // learned-safe -> narrow settings allows
    setConfig(cfg); reconcile(cfg);
    ok("companion mode ON (optimized for Claude Code Auto mode)");
    console.log("  - Haiku veto:        off (no pre-check tokens)");
    console.log("  - ambiguous asks:    deferred to Auto mode's classifier (no double-prompt)");
    console.log("  - allow/deny:        resolved by pre-check (each skips a classifier round-trip)");
    console.log("  - promoteToSettings: on (learned-safe commands -> narrow settings.json allows)");
    console.log("  pre-check also auto-enters this behavior whenever the session is in Auto mode. `/pre-check savings` to see the estimate.");
  } else {
    const b = readJson(PATHS.companionBackup, null);
    cfg.companion = b ? !!b.companion : false;
    cfg.llm = cfg.llm || {}; cfg.llm.enabled = b ? !!b.llm : true;
    cfg.syncSettings = cfg.syncSettings || {}; cfg.syncSettings.promoteToSettings = b ? !!b.promoteToSettings : false;
    setConfig(cfg); reconcile(cfg);
    try { fs.rmSync(PATHS.companionBackup, { force: true }); } catch { /* ignore */ }
    ok("companion mode OFF (restored prior config)");
  }
}

// ── savings counter (classifier round-trips pre-check avoided under Auto mode) ─
function cmdSavings() {
  const cfg = getConfig();
  const per = cfg.savings?.tokensPerClassifierCall || 2500;
  const lines = tailLines(PATHS.log, 100000);
  let allow = 0, deny = 0, deferred = 0, total = 0;
  for (const l of lines) {
    let r; try { r = JSON.parse(l); } catch { continue; }
    if (!r.autoMode) continue;                                        // only Auto-mode decisions count
    total++;
    if (r.deferred) deferred++;
    else if (r.decision === "allow") allow++;
    else if (r.decision === "deny") deny++;
  }
  const avoided = allow + deny;
  const comma = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  ok("pre-check savings under Claude Code Auto mode");
  console.log(`  Auto-mode decisions logged:   ${total}`);
  console.log(`  resolved by pre-check:        ${avoided}  (allow=${allow}, deny=${deny})  <- classifier round-trips avoided`);
  console.log(`  deferred to the classifier:   ${deferred}`);
  console.log(`  estimated tokens saved:       ~${comma(avoided * per)}  (at ~${per}/call)`);
  console.log("  deny-skips are confirmed (pre-check short-circuits); allow-skips assume a hook allow bypasses");
  console.log("  the classifier. Measure exactly via /status token usage with companion off vs on.");
}

// ── dispatch ─────────────────────────────────────────────────────────────────
switch (cmd) {
  case "status": cmdStatus(); break;
  case "menu": case "help": cmdMenu(); break;
  case "on": cmdOnOff(true); break;
  case "off": cmdOnOff(false); break;
  case "mode": cmdMode(); break;
  case "set": cmdSet(); break;
  case "category": cmdCategory(); break;
  case "llm": cmdLlm(); break;
  case "sync": cmdSync(); break;
  case "grant-once": cmdGrantOnce(); break;
  case "promote": cmdPromote(); break;
  case "decline-promote": cmdDeclinePromote(); break;
  case "rules": cmdRules(); break;
  case "logs": cmdLogs(); break;
  case "clear-cache": cmdClearCache(); break;
  case "export-feedback": case "export": cmdExportFeedback(); break;
  case "risk": cmdRisk(); break;
  case "companion": cmdCompanion(); break;
  case "savings": cmdSavings(); break;
  default: cmdMenu();
}
