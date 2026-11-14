# shush — instructions for Claude

## Workflow rule: find a skill before starting new work

Before starting any new process or feature (a new phase, a new kind of task, a new
tool or testing workflow), unless a suitable skill is already installed:

1. Run `/find-skills` to search for a skill that fits the workflow (checks `skills.sh` and GitHub).
2. Vet candidate skills against the 4 gates in `/find-skills`:
   - **Provenance**: Official sources (`sveltejs`, `tauri-apps`, `anthropics`, `vercel-labs`) or >1k installs / >500 stars. Reject unverified <50 star repos.
   - **Security Audit**: Zero prompt-injection, no hidden data exfiltration, no `curl | sh`, no secret probing.
   - **Stack Compatibility**: Must match active stack versions (Svelte 5 runes, Tauri v2, zeroization). Reject obsolete patterns.
   - **Signal Density**: Actionable rules, concrete examples, and checklists over conversational fluff.
3. Install the vetted match, then run it and follow it for the work.

If installing is blocked (for example by permission rules), say so, give the user the
install command, and continue with the closest equivalent approach.

Exception: unattended `/issue` workers never run `/find-skills` or install skills. They report
a suggestion on the `SKILLS:` line of their final report, and the `/issue` banner shows it, so
the owner decides whether to run `/find-skills` in an interactive session.

## Installed project skills

- `.claude/skills/svelte-core-bestpractices`, `.claude/skills/svelte-code-writer`: official
  Svelte skills (vendored from `sveltejs/ai-tools`, MIT). Follow them for every `.svelte` /
  `.svelte.ts` change. The `npx @sveltejs/mcp svelte-autofixer` step needs the user to allow
  running that package; until then validate with `npm run check` in `src/`.
- `.claude/skills/frontend-design`: Anthropic's design-direction skill (vendored). Follow it for any UI or
  site redesign: write a token plan, review it against the brief, then build and screenshot.
- `.claude/skills/animation-performance`: frame-budget rules for CSS/JS motion (vendored from
  `emilkowalski/skills`, pinned in `skills-lock.json`). Follow it when adding or changing any
  animation, transition, shadow or filter on the site or in the app (e.g. the Spindle disc/lid).
- `web-design-guidelines` (user-level): UI / accessibility review.

## Testing the desktop app

Drive the UI over the Chrome DevTools Protocol, never with mouse/keyboard input (the user may be
working on the same machine). See `docs/testing/README.md` for the per-phase scripts and harness:

- Launch with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9222 --remote-debugging-address=127.0.0.1"`.
- Point the debug build at a scratch vault with `SHUSH_VAULT_PATH=<scratch>\vault.shush`. Never use
  the real `%APPDATA%\com.shush.vault` vault for testing.
- Simplest: dot-source `.claude/scripts/issue-env.ps1` in the same command. It puts cargo on PATH and
  sets `CDP_PORT` + the WebView2 CDP flag (9222 in the main checkout, `10000 + N` in the issue-N
  worktree) and a scratch `SHUSH_VAULT_PATH`, so parallel runs never share a port or profile.

## Trying merged work in the installed app

`.claude/scripts/install-main.ps1` builds `origin/main` (or `-Ref <branch>`) as a release NSIS
installer in its own worktree, backs up the vault files, and installs it silently over the owner's
shush (`-CloseApp -Launch` to restart it, `-Status` to see what is installed). Stopgap until the
signed update feed (#103) and in-app updater (#78). Only run it when the owner asks: it replaces
their real app.

## GitHub Issue Clearing (`/issue`)

When resolving issues via `/issue`:
- **`/issue`**: Resolves one issue (top severity or specific number), files discovered bugs/features, runs tests, PRs & merges, then stops and prompts for `/clear` to save tokens.
- **Prioritize by severity**: `severity:critical` > `severity:high` > `severity:medium` > `severity:low`.
- **File discovered issues**: If bugs, architectural flaws, or high-value feature ideas are spotted during work, file them immediately with `gh issue create`.
- **Verify rigorously**: Ensure `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --manifest-path src-tauri/Cargo.toml`, and `npm run check` in `src/` all pass cleanly.
- **Branch & PR Lifecycle**: Always create a feature branch (`fix/issue-<num>-<slug>`), commit, push, create a PR (`gh pr create`), and squash-merge (`gh pr merge --squash --delete-branch --admin`).
- **Merge policy**: `route-issue.ps1` returns `merge: auto | review`. `review` (crypto, sync, file
  format, memory hygiene, browser bridge, release/updater/signing/CI, or severity high/critical)
  means the runner opens the PR labelled `ai-review` and stops; the `pr-reviewer` agent (Opus)
  then re-runs every check, reviews and fixes the diff, and merges it. It escalates to the owner
  (label `needs-review`, with a plain-language question) only for a decision that is genuinely
  theirs. `/issue` skips issues whose PR is labelled `needs-review`.
- **Context discipline**: Run `/clear` after completing an issue to keep token usage minimal.
- **Runners**: Claude (Sonnet by default; Opus for critical, or high crypto/sync) writes all code, UI
  and tests. AGY gets Markdown-only docs/spec issues, opens a PR, and never merges; the dispatcher
  merges it through `.claude/scripts/agy-gate.ps1`. Rules live in `.claude/scripts/route-issue.ps1`.
- **Parallel runs**: each worktree gets its own leased cargo target slot (`issue-worktree.ps1 -Status`)
  and shares main's `src/node_modules` read-only; never `npm install` in a worktree (use `-OwnNodeModules`).

