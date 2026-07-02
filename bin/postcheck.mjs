#!/usr/bin/env node
// postcheck.mjs — PostToolUse learning capture for pre-check.
//
// A tool that RAN was approved (auto-allowed, or the user approved an "ask"). If this call's RAW
// verdict WOULD have been "ask", we record an approval in the learning store; after `threshold`
// approvals the deterministic gate auto-allows it next time (see consumeLearned in precheck.mjs).
//
// The learning store is a LOCAL lookup — it is NEVER sent to the Haiku veto. Secret reads
// (cfg.learning.neverLearn) are never learned. Dependency-free, no LLM, best-effort, prints
// nothing, and stays silent on any error.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PATHS, learnSig, readJson, ensureDir, globToRegex } from "./lib.mjs";
import {
  loadConfig, loadRules, categorize, evaluateBash, evaluatePowershell, evaluatePath,
  findRoot, loadProjectContext, applyProjectContext, isoNow, readStdin,
} from "./precheck.mjs";

function recordLearned(category, target, ruleId, cfg) {
  const lc = cfg.learning || {};
  if (lc.enabled === false) return;
  if ((lc.neverLearn || []).includes(ruleId)) return;
  try {
    ensureDir(path.dirname(PATHS.learned));
    const l = readJson(PATHS.learned, {}) || {};
    const sig = learnSig(category, target);
    const e = l[sig] || { category, approvals: 0 };
    e.approvals = (e.approvals || 0) + 1;
    e.ruleId = ruleId;
    e.ts = isoNow();
    e.snippet = String(target).slice(0, 200);
    l[sig] = e;
    fs.writeFileSync(PATHS.learned, JSON.stringify(l));
  } catch { /* best-effort */ }
}

function main() {
  let input;
  try { input = JSON.parse(readStdin()); } catch { return; }

  let cfg;
  try { cfg = loadConfig(); } catch { return; }
  if (cfg.enabled === false && process.env.PRECHECK_TEST !== "1") return;
  if (cfg.learning?.enabled === false) return;

  const cat = categorize(input.tool_name || "", cfg.categories || {});
  if (!cat || cat.mode === "passthrough") return;
  if (!["bash", "powershell", "edit", "read"].includes(cat.name)) return; // only learnable categories

  let rules;
  try { rules = loadRules(); } catch { return; }
  const ti = input.tool_input || {};
  const cwd = input.cwd || process.cwd();
  const riskyRx = (cfg.riskyScope || []).map(globToRegex);
  const root = findRoot(cwd, cfg.projectRoot?.markers || []);
  try { applyProjectContext(rules, loadProjectContext(root)); } catch { /* best-effort */ }

  let target = "";
  if (cat.name === "bash" || cat.name === "powershell") target = (ti.command || "").trim();
  else if (cat.name === "edit") target = ti.file_path || ti.notebook_path || "";
  else target = ti.file_path || ti.path || ti.pattern || "";
  if (!target) return;

  // Re-run the RAW verdict (no cache, no grants, no learned override) to see if this call would
  // have prompted. Only approved *asks* are worth learning.
  let verdict;
  try {
    if (cat.name === "bash") verdict = evaluateBash(target, rules, riskyRx, cfg);
    else if (cat.name === "powershell") verdict = evaluatePowershell(target, rules, riskyRx, cfg);
    else if (cat.name === "edit") verdict = evaluatePath(target, cwd, root, rules, "edit");
    else verdict = evaluatePath(target, cwd, root, rules, "read");
  } catch { return; }
  if (verdict.decision !== "ask") return;

  recordLearned(cat.name, target, verdict.id, cfg);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) { try { main(); } catch { /* silent — learning is best-effort */ } }
