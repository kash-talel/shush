# shush — instructions for Claude

## Workflow rule: find a skill before starting new work

Before starting any new process or feature (a new phase, a new kind of task, a new
tool or testing workflow), unless a suitable skill is already installed:

run `/find-skills`, vet candidates against its four gates (provenance, security audit, stack
compatibility with Svelte 5 runes / Tauri v2, signal density), install the vetted match, and
follow it for the work.

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

**Uninstalling for tests:** When a test (e.g. installer E2E, upgrade flow) requires uninstalling
the currently installed version of shush on the owner's machine, you may proceed without stopping
to ask — the owner has approved this. Back up vault files first (as `install-main.ps1` does).
This applies to every agent, including unattended `/issue` workers and the `pr-reviewer`: closing
the running shush app for such a test is allowed, and "it would replace the installed app" is not
a reason to leave a test out. Copying the real vault files to a backup is allowed; opening or
changing them is not (tests still use a scratch `SHUSH_VAULT_PATH`). When the test is done, leave
a working shush installed (`install-main.ps1 -CloseApp -Launch` puts `origin/main` back).

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

The procedure lives in `.claude/skills/issue/SKILL.md` and the `issue-worker` / `pr-reviewer`
agents; routing and review rules live only in `.claude/scripts/Policy.ps1`. For any work outside
`/issue`: branch, verify with `.claude/scripts/verify.ps1`, open a PR, and merge only through
`.claude/scripts/merge-pr.ps1` (it waits for CI and stops sensitive diffs, or routine ones with first-pass review findings, with exit 4 for the `pr-reviewer`; pass `-Reviewed`
only after such a review or when the owner explicitly asked for the merge); never
`gh pr merge --admin`. Run `/clear` after each `/issue`.

