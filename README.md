# pre-check — an auto-approve / safety gate for Claude Code

Stop babysitting Claude Code. `pre-check` is a **PreToolUse hook** that evaluates every
shell command (and file edit) *before* it would prompt you, and:

- ✅ **auto-approves** routine development work, so you can walk away,
- ⛔ **blocks** dangerous commands (Claude gets the reason and self-corrects),
- ❓ **prompts you** only for genuinely ambiguous calls.

It's configurable per tool category, learns nothing it shouldn't (a private decision
cache, never your real permissions), and is fully reversible.

## How it works

Two cooperating hooks, driven by one config file:

1. **Deterministic gate** (`bin/precheck.mjs`) — a dependency-free Node script that splits
   a command into sub-commands and matches them against curated allow / deny / sensitive
   rule lists. Instant, free, offline, no API key. Returns `allow` / `deny` / `ask`.
2. **Keyless Haiku veto** (a `type:"prompt"` hook) — for *marginal, risk-scoped* commands
   only, a fast model judges safety using your **existing Claude Code session — no API
   key** (it spends subscription tokens). Because hooks merge most-restrictive-wins, it can
   only ever *veto* (tighten), never loosen.

The deterministic deny-list plus a tiny **unbypassable `permissions.deny` backstop** (sudo,
`rm -rf /`, `curl | sh`, …) are the real safety floor. The LLM is a bonus net.

```
command ──▶ pre-check ──▶ allow  (runs, no prompt)
                       ├▶ deny   (blocked; Claude told why → goes safer)
                       └▶ ask    (you decide)   ── settings.json `deny` always wins ──
```

## Install (60 seconds)

Requires Node.js on PATH. Clone into your Claude skills directory and run the installer:

```bash
git clone <repo> ~/.claude/skills/pre-check
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

## Turn it on/off (four levers)

```bash
node ~/.claude/skills/pre-check/bin/manage.mjs off          # master switch: back to normal prompting
node ~/.claude/skills/pre-check/bin/manage.mjs set web gate  # gate/ignore a category: bash|edit|read|web|mcp
node ~/.claude/skills/pre-check/bin/manage.mjs llm off       # disable the Haiku veto (pattern-only)
node ~/.claude/skills/pre-check/bin/uninstall.mjs            # full removal
```

Default: `bash` + `edit` are gated; `read`, `web`, `mcp` pass through (still prompt you).
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
| Credentials / DB | reading `.env`/`id_rsa`/`~/.aws`, prod DB mutations, force-with-lease | ask |
| Routine dev work | `ls`, `git commit`, `npm test`, `make`, `pytest`, build-dir `rm -rf node_modules`, in-project edits | allow |
| Marginal + risky | `npx <unknown>`, an unusual network call | Haiku veto |

Rules are data — tune them in `~/.claude/precheck/rules.user.json` (`extraAllow` /
`extraDeny` / `extraSensitive`, or `disabled: ["rule.id"]`) and per-project in
`.precheck-context.yaml` (see `examples/`). No code changes needed.

## Calibration with your existing permissions

`sync` imports your `settings.json` `permissions.allow` Bash patterns as **trusted** (the
gate will never deny what you already allowed) and mirrors `deny`/`ask` for consistency.
Note: a broad allow like `Bash(git push *)` therefore lets the gate allow `git push --force`
too — review broad allows, or add a scoped `extraDeny`, if you want the gate to override them.
Writing back to `settings.json` is opt-in only (`promoteToSettings`, default off).

## Limitations & honest caveats

- **Not a sandbox.** It's a heuristic filter. The command parser is conservative — anything
  it can't parse becomes *marginal* (veto or ask), never a silent allow — but a determined,
  obfuscated payload could still slip past the patterns. The `permissions.deny` backstop and
  the Haiku veto are extra layers, not guarantees.
- **Hooks may fail-open on timeout** — which is why the unbypassable settings `deny` backstop
  exists for the catastrophic literals.
- **The Haiku veto costs subscription tokens** and adds ~1–3s on risk-scoped commands only
  (turn it off with `llm off` for fully instant, free, pattern-only operation).
- **LLM verdicts aren't cached** (the veto is a separate hook). Promote frequently-vetoed
  patterns into `extraDeny` to make them deterministic + cached.

## Files

- `bin/precheck.mjs` — the gate engine · `bin/manage.mjs` — operator CLI ·
  `bin/install.mjs` / `bin/uninstall.mjs` — settings.json wiring
- `rules/rules.default.json` — the shipped rule library (per-rule `note`s) ·
  `config.default.json` — documented defaults · `prompts/veto.prompt.txt` — the Haiku prompt
- User state (never committed): `~/.claude/precheck/` (config, cache, logs, synced rules)
- `bin/_selftest.mjs` — `node bin/_selftest.mjs` runs the offline verification suite

MIT licensed. See `SKILL.md` for the agent-facing operator manual.
