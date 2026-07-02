# pre-check — security model & limits

**Read this before trusting pre-check for anything that matters.**

## What pre-check is (and isn't)

pre-check is a **guardrail, not a sandbox.** Its trust model is **command-name allowlisting**: it
recognizes safe verbs (`ls`, `git commit`, `npm test`, …), blocks known-dangerous ones (`rm -rf /`,
`git push --force`, `curl | sh`, …), and asks you about secret reads and true unknowns. That makes it
very good at stopping **footguns and mistakes**, and a useful (not airtight) net against
**prompt-injection** — but it is a heuristic filter, not an OS-level boundary.

> **For untrusted input, pair pre-check with real OS/container sandboxing.** pre-check is layer 1
> (stops accidents, catches most injection, keeps a human on secrets); a sandbox is layer 2.

## The one boundary to understand: interpreters run what you feed them

Because it trusts your toolchain, the moment pre-check allows an interpreter it trusts the code that
interpreter runs. `node script.js`, `npm run <script>`, `tsx file.ts`, `deno run <url>`, `python file.py`
are **allowed** — they run *code you point them at*. That's by design (it's how dev works).

**Inline eval, module-preload, remote and stdin execution are different and are gated:**
`node -e '<code>'` / `-p`, `-r`/`--require`/`--import`/`--loader` (preload), `deno run <url|npm:|jsr:>`,
`deno run -` / `node /dev/stdin`, `deno eval`, `bun -e`, `bunx` run code *from the command string,
a preloaded module, a remote source, or stdin* (the sharp edge under prompt-injection). A tokenizing
classifier (robust to quoting like `node '-e'`, and to app-level flags after the script such as
`node server.js -p 8080`) routes these to a **deterministic ask** — and the learning cache remembers
your approval, so a given form prompts only the first time. Hardened in the 2026-07 audit (F1) and its
two adversarial-verification rounds.

## Known limits & residuals

| # | Limit | Behavior | Mitigation |
|---|---|---|---|
| F1 | Interpreters run code you point them at | `node file.js`, `npm run x` → allow | Inline eval / preload (`-r`) / remote / stdin → **ask** (learned once approved); sandbox for untrusted input |
| F2/F3 | Regex evasion via **variable indirection** (`X=rm; $X -rf /`) and `$(…)` substitution | Downgraded to **ask/veto**, never silent-allow on `balanced` | Quote/backslash splits (`s""udo`, `\sudo`, `curl \| "sh"`) *are* caught |
| F5 | `#` is **not** treated as a shell comment | Fail-safe **over-block** (`ls # rm -rf /` → deny) | Intentional; blocks comment-hiding tricks |
| F6 | The **`trusting`** risk preset skips the veto on true-unknowns | Obfuscated marginals can silent-allow **on `trusting` only** | Default `balanced` keeps the human/veto backstop |
| F7 | **MCP / Web are passthrough** | External sends/deletes (Gmail, repo delete, DB purge) aren't gated by pre-check | Rules exist; enable with `manage set mcp gate` |

None of these is a silent-allow of a *known-dangerous* command on the default `balanced` preset — the
worst case is that an *obfuscated* dangerous command reaches **you** (ask) instead of being auto-denied.
The unbypassable `settings.json` `permissions.deny` backstop catches the catastrophic literals even if a
hook fails open.

## 2026-07 audit & fixes

A black-box + offline audit (~40 live tool calls, ~200 offline evaluations) confirmed the design is
well-tuned and produced findings F1–F7. The full pre-fix report is archived at
[docs/audit-2026-07.md](docs/audit-2026-07.md). Fixed since:

- **F1** — interpreter inline-eval / module-preload (`-r`/`--require`/`--loader`) / remote (`deno run <url>`) /
  stdin execution routed to a deterministic **ask** via a tokenizing classifier (was a silent allow). Two
  adversarial-verification rounds closed quoted-flag bypasses (`node '-e'`) and app-flag false-denies.
- **F4** — the fork-bomb rule was dead code (unit-splitting shredded it); moved to `denyPipeline` (raw-command, pre-split).
- **F2/F3** — quote/backslash obfuscation (`s""udo`, `su'd'o`, `\sudo`, `curl | "sh"`) is now de-obfuscated before matching.

Variable-indirection and command-substitution evasion remain *documented residuals* — they degrade to
ask/veto, not silent-allow. Closing them fully is out of scope for a regex gate (that's the sandbox's job).

## Testing

The audit's evasion matrix is codified as a regression suite:

```bash
node bin/_security.mjs   # evasion + interpreter regressions
node bin/_selftest.mjs   # offline rule verdicts
node bin/_e2e.mjs        # runtime behavior (grants, learning, PowerShell, …)
```

Re-run `bin/_security.mjs` after any rule change.

## A note on ask-rate stats

`manage export-feedback` shows decision counts, but the cumulative log spans config changes. In
particular the `path.claude-config` counter is inflated by history from before that rule was narrowed
(it once matched *every* file under `~/.claude/`; it now matches only `settings.json`/hooks). **Re-measure
with a fresh export after a few days of real use before tuning** — and do **not** blanket-`extraAllow`
`path.claude-config`, since that would un-gate edits to your live `settings.json`. Prefer the learning
cache to pull the ask-rate down.
