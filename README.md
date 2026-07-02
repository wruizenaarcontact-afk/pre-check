# pre-check — an auto-approve / safety gate for Claude Code

Stop babysitting Claude Code. `pre-check` is a **PreToolUse hook** that evaluates every shell
command, file edit, and file read *before* it would prompt you, and:

- ✅ **auto-approves** routine development work, so you can walk away,
- ⛔ **denies** dangerous commands — Claude gets the reason and *reroutes silently* (no stalling),
- ❓ **prompts you** only for true unknowns and raw secret reads.

It's **deny-heavy on purpose**: dangerous work is blocked (so unattended runs keep going) rather
than queued as a prompt. A denied command isn't a dead end — Claude can escalate it to you for a
one-time, audited exception (see below).

It's configurable per tool category, learns nothing it shouldn't (a private decision
cache, never your real permissions), and is fully reversible.

## How it works

Three cooperating hooks, driven by one config file:

1. **Deterministic gate** (`bin/precheck.mjs`) — a dependency-free Node script that splits
   a Bash **or PowerShell** command into sub-commands and matches them against curated allow /
   deny / sensitive rule lists. Instant, free, offline, no API key. Returns `allow` / `deny` / `ask`.
2. **Keyless Haiku veto** (a `type:"prompt"` hook) — for *marginal, risk-scoped* commands
   only, a fast model judges safety using your **existing Claude Code session — no API
   key** (it spends subscription tokens). Because hooks merge most-restrictive-wins, it can
   only ever *veto* (tighten), never loosen.
3. **Learning capture** (`bin/postcheck.mjs`, a PostToolUse hook) — records commands you
   approved so the gate stops asking about them (see below). Local only; never calls the model.

The deterministic deny-list plus a tiny **unbypassable `permissions.deny` backstop** (sudo,
`rm -rf /`, `curl | sh`, …) are the real safety floor. The LLM is a bonus net.

```
command ──▶ pre-check ──▶ allow  (runs, no prompt)
                       ├▶ deny   (blocked; Claude reroutes; can escalate for a 1-time grant)
                       └▶ ask    (true unknown / secret read — you decide)
                          ── settings.json `deny` always wins over any allow ──
```

### Graceful escalation (deny → last-resort unlock)

When Claude hits a hard deny it can't work around, it asks *you* (via a question), and on approval
issues a **one-time grant** — the gate allows that exact command once, then consumes it. Approve the
same command a few times and it offers to **promote** it to a permanent scoped rule. So force-push,
DB migrations, etc. stay denied by default but remain possible, deliberately and audited.

## Install (60 seconds)

Requires Node.js on PATH. Clone into your Claude skills directory and run the installer:

```bash
git clone https://github.com/wruizenaarcontact-afk/pre-check.git ~/.claude/skills/pre-check
node ~/.claude/skills/pre-check/bin/install.mjs   # merges hooks into ~/.claude/settings.json
node ~/.claude/skills/pre-check/bin/manage.mjs sync   # calibrate to your existing permissions
```

Run `/hooks` in Claude Code to confirm two `PreToolUse` hooks registered. The installer
backs up your `settings.json` to `settings.json.precheck.bak` and never touches your
existing allow-list.

Uninstall (removes only what it added):

```bash
node ~/.claude/skills/pre-check/bin/uninstall.mjs
```

## Turn it on/off

```bash
node ~/.claude/skills/pre-check/bin/manage.mjs off          # master switch (REMOVES the hooks; normal prompting)
node ~/.claude/skills/pre-check/bin/manage.mjs mode report   # dry-run: log would-be decisions, enforce nothing
node ~/.claude/skills/pre-check/bin/manage.mjs risk trusting  # prompt appetite: cautious | balanced | trusting
node ~/.claude/skills/pre-check/bin/manage.mjs set web gate  # gate/ignore a category: bash|powershell|edit|read|web|mcp
node ~/.claude/skills/pre-check/bin/manage.mjs llm off       # disable the Haiku veto (pattern-only)
node ~/.claude/skills/pre-check/bin/manage.mjs export-feedback  # redacted, shareable usage report
node ~/.claude/skills/pre-check/bin/manage.mjs companion on  # combo with Claude Code Auto mode (saves tokens)
node ~/.claude/skills/pre-check/bin/manage.mjs savings       # est. classifier round-trips / tokens avoided
node ~/.claude/skills/pre-check/bin/uninstall.mjs            # full removal
```

`off` genuinely removes the hooks (the Haiku veto is a separate hook that can't read a flag), so it
fully stops. Use `mode report` for a dry-run tuning day before trusting it. Default gated categories:
`bash`, `powershell`, `edit`, `read` (secret reads only); `web`, `mcp` pass through (still prompt you).
Add your own category (tool-name regex → mode):

```bash
node ~/.claude/skills/pre-check/bin/manage.mjs category add gmail "^mcp__claude_ai_Gmail__" gate
```

## What it catches

| Class | Examples | Verdict |
|---|---|---|
| Destructive | `rm -rf /`, `git push --force`, `git clean -fdx`, `DROP TABLE`, `kubectl delete`, `terraform destroy` | deny |
| Privilege / system | `sudo`, `chmod 777 /`, `mkfs`, `dd of=/dev/…`, `shutdown` | deny |
| Remote code / exfil | `curl … \| sh`, `wget … \| bash`, `… \| nc`, `eval $(curl …)`, `pip install http://…`, `npm i -g` | deny |
| Dangerous-but-legit | `git reset --hard`, `--force-with-lease`, `chmod -R`, `ssh`/`scp`, `docker prune`, DB mutations/migrations | deny (escalate if needed) |
| Secret reads | reading a *foreign* `.env`/`id_rsa`/`~/.aws` (Bash **or** the Read tool); your own in-project `.env` is allowed | ask |
| PowerShell | `Remove-Item -Recurse -Force`, `Invoke-Expression`, `iwr … \| iex`, `Set-ExecutionPolicy`, `Stop-Computer` deny; `Get-*`, `Test-Path` allow | deny / allow |
| Routine dev work | `ls`, `git commit`, `npm test`, `make`, `pytest`, build-dir `rm -rf node_modules`, in-project edits | allow |
| Marginal + risky | `npx <unknown>`, an unusual network call | Haiku veto |
| True unknown | an unrecognized command with no risk signal | ask (learned after 1 approval) |

Rules are data — tune them in `~/.claude/precheck/rules.user.json` (`extraAllow` /
`extraDeny` / `extraSensitive`, or `disabled: ["rule.id"]`) and per-project in
`.precheck-context.yaml` (see `examples/`). No code changes needed.

## Fewer prompts: the learning cache + risk dial

pre-check **learns**. When you approve an `ask`, a PostToolUse hook records it and the gate
auto-allows that exact command next time — so any given prompt fires at most once. It's a local
approval-count lookup (`~/.claude/precheck/state/learned.json`), **never** sent to the Haiku veto,
so it adds zero token cost. Secret reads are the exception — never learned, they always re-ask.

The **risk dial** (`manage risk <preset>`) sets how much is decided for you:

| preset | true-unknown command | risk-scoped unknown | learns after |
|---|---|---|---|
| `cautious` | ask | ask | 3 approvals |
| **`balanced`** (default) | ask | Haiku veto | 1 approval |
| `trusting` | allow | Haiku veto | 1 approval |

Deny rules, the `settings.json` deny backstop, and secret-read asks stay put in **every** preset.

## Companion mode: combo with Claude Code Auto mode

[Auto mode](https://code.claude.com/docs/en/permission-modes#eliminate-prompts-with-auto-mode) runs a
server-side classifier on every non-trivial action (each a token round-trip). pre-check pairs with it as
a **free, deterministic layer**: when the session is in Auto mode, pre-check **auto-enters companion
behavior** — it emits only `allow`/`deny` and **defers every `ask` to the classifier** (no
double-prompting), so each allow/deny it resolves **skips a classifier round-trip**.

```bash
node …/bin/manage.mjs companion on   # + turns the Haiku veto off (zero pre-check tokens) & promoteToSettings
node …/bin/manage.mjs savings        # estimate the classifier round-trips / tokens avoided
```

`deny`-skips are confirmed (pre-check short-circuits, and it's a backstop during classifier outages);
`allow`-skips assume a hook `allow` bypasses the classifier (very likely) or ride the docs-guaranteed
narrow-allow-rule path (`promoteToSettings`). Measure it exactly with `/status` token usage, companion
off vs on. `companion off` restores your prior config.

## Share what tripped you up

`manage export-feedback` writes a **redacted** report (`~/.claude/precheck/export/`) of what the
gate decided — decision counts and command *shapes* (first token + salted hash), never raw command
text or file contents — so you can see which rules ask too often, or share it to help improve
pre-check. `--raw --i-consent` includes real commands (review before sending).

## Calibration with your existing permissions

`sync` imports your `settings.json` `permissions.allow` Bash patterns as **synced trust** and
mirrors `deny`/`ask`. Synced trust only *rescues unrecognized commands you already allow — it can
never override a deny/sensitive rule*. So a broad `Bash(git *)` is trusted for ordinary git, but
force-push / `reset --hard` stay denied. `sync` prints a **review** of your broad allows + the
dangerous sub-cases that remain denied, so you (or Claude) can add scoped `extraDeny` if wanted.
Writing back to `settings.json` is opt-in only (`promoteToSettings`, default off).

## Limitations & honest caveats

- **Not a sandbox.** It's a heuristic filter — see [SECURITY.md](SECURITY.md) for the threat model,
  the 2026-07 audit, and known residuals. The parser is conservative (unparseable → marginal, never a
  silent allow), but a determined obfuscated payload could still slip past. Pair with OS sandboxing
  for untrusted input.
- **Interpreters run what you feed them.** `node file.js`, `npm run x` are allowed (that's dev). Inline
  eval (`node -e`/`-p`), module preload (`-r`/`--require`/`--loader`), remote (`deno run <url>`) and stdin
  execution are caught by a tokenizing classifier and **asked** (learned once you approve). Variable
  indirection (`X=rm; $X …`) degrades to ask/veto, not silent-allow.
- **`trusting` widens the surface.** On the `trusting` preset, obfuscated true-unknowns can auto-allow
  (no veto). Use the default `balanced` when handling untrusted input.
- **MCP / Web are passthrough** — external sends/deletes aren't gated (enable with `set mcp gate`).
- **Hooks may fail-open on timeout** — which is why the unbypassable settings `deny` backstop
  exists for the catastrophic literals.
- **The Haiku veto costs subscription tokens** and adds ~1–3s on risk-scoped commands only
  (turn it off with `llm off` for fully instant, free, pattern-only operation).
- **LLM verdicts aren't cached** (the veto is a separate hook). Promote frequently-vetoed
  patterns into `extraDeny` to make them deterministic + cached.
- **Hook changes hot-reload**, but a running session may keep the previously-loaded hooks until
  the file watcher catches up — after `install`/`on`/`off`, run `/hooks` to confirm, and restart
  the session if it hasn't picked the change up.
- **Deny-heavy by design.** Dangerous commands are denied (Claude reroutes), not queued as prompts.
  The rare legitimate case goes through the one-time escalation grant, which learns via promotion.

## Files

- `bin/precheck.mjs` — the gate engine · `bin/postcheck.mjs` — PostToolUse learning capture ·
  `bin/manage.mjs` — operator CLI · `bin/install.mjs` / `bin/uninstall.mjs` — settings.json wiring
- `rules/rules.default.json` — the shipped rule library (per-rule `note`s) ·
  `config.default.json` — documented defaults · `prompts/veto.prompt.txt` — the Haiku prompt
- User state (never committed): `~/.claude/precheck/` (config, cache, logs, synced rules, grants, learned)
- `bin/_selftest.mjs` (offline rule tests), `bin/_e2e.mjs` (runtime tests: grants, report mode,
  read gating, escalation, learning cache, risk dial, PowerShell, export), and `bin/_security.mjs`
  (evasion / interpreter regressions) — run with
  `node bin/_selftest.mjs && node bin/_e2e.mjs && node bin/_security.mjs`
- `SECURITY.md` — threat model, 2026-07 audit, and known residuals.

MIT licensed. See `SKILL.md` for the agent-facing operator manual, `SECURITY.md` for the threat model.
