# Releasing shush

Cutting a release is: merge one PR, approve one deployment. Issue #103 is the design; #78 is the
in-app updater that consumes the feed.

## Happy path

1. Merge Conventional-Commit PRs to `main` (`feat:`, `fix:`, ... PR titles are checked by CI).
2. release-please keeps a "chore(main): release X.Y.Z" PR open. It bumps every version file
   (`src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, `src/package.json`, `src/package-lock.json`,
   `src-tauri/tauri.conf.json`) and `CHANGELOG.md`. CI runs on it (the App token makes that happen).
3. Merge that PR. `release.yml` then, in one run: creates tag `vX.Y.Z` + a draft release, builds
   (no secrets), and pauses at the **release** environment.
4. Approve the deployment. `publish` signs the installer and `release.json`, attests provenance
   and SBOMs, uploads everything to the draft, then publishes it. With immutable releases on, the
   tag and assets are frozen from that moment.
5. `pages.yml` runs (called from `release.yml`) and refreshes `/updates/stable/`.

Pre-release (beta): add a `Release-As: 0.3.0-beta.1` footer to a commit on `main`. A version with
a `-` is published as a pre-release and goes to `/updates/beta/`, never to `stable`. Pre-releases
ship the NSIS installer only (no `.msi`): WiX accepts only a numeric pre-release identifier.

## Dry run

Actions, Release, "Run workflow" (`workflow_dispatch`): builds, runs the PE hardening check and
the smoke test, uploads the `shush-windows-build` artifact. It never publishes and uses no secrets.

## What a release contains

`shush_X.Y.Z_x64-setup.exe` (+ `.sig`), `shush_x64-setup.exe` (same file, stable name), the `.msi`,
`release.json` + `release.json.minisig`, `SHA256SUMS.txt`, `sbom-rust.cdx.json`, `sbom-npm.cdx.json`.

## Update feed

Served from GitHub Pages (a published immutable release can't hold a file re-signed weekly):

```
/updates/stable/{release.json, release.json.minisig, latest.json, freshness.json, freshness.json.minisig}
/updates/beta/...    (only when a pre-release exists)
```

- `release.json` (signed by the **release key**) pins version, installer URL, sha256 and size.
  Pages copies it verbatim from the release.
- `freshness.json` (signed by the **timestamp key**) pins the sha256 of that exact `release.json`
  and a 14-day expiry. `pages.yml` re-signs it on every deploy and by weekly cron
  (Mondays 04:17 UTC). If the cron fails for 14 days every client reports "can't confirm you are
  up to date": a failed cron run is the alert, do not ignore it.
- Until the `TIMESTAMP_SIGNING_KEY` secret exists, the site still deploys but the feed is skipped.

## Yank and roll forward

Never edit a published release. To pull a bad version: add it (one per line) to
`.github/feed-yanked.txt` and merge. The feed then points at the previous good release, which
stops new installs of the bad one. Clients that already installed the yanked version refuse the
older release as a rollback (the app's rollback protection) and report an error rather than "up to
date" until the fix ships, so ship `X.Y.Z+1` quickly and then remove the yank line if you like
(the feed always serves the newest non-yanked release). For a security fix set `security` /
`min_supported` by editing `make-release-json.ps1` arguments in `release.yml`.

## Keys and secrets (each lives in exactly one place)

| Secret / variable | Environment | Purpose |
|---|---|---|
| `RELEASE_SIGNING_KEY`, `RELEASE_SIGNING_KEY_PASSWORD` | `release` | signs installer `.sig` and `release.json` |
| `TIMESTAMP_SIGNING_KEY`, `TIMESTAMP_SIGNING_KEY_PASSWORD` | `feed` | signs `freshness.json` only |
| `RELEASE_APP_ID` (variable), `RELEASE_APP_PRIVATE_KEY` | repository | GitHub App that opens the release PR and creates the tag |
| SignPath token (#165, blocked) | `codesign` | Authenticode signing, not yet wired |

Generate keys with `npx --prefix src tauri signer generate -w <file> -p <password>`: one each for
release, release-next (offline only, pinned in the app so rotation needs no bootstrap) and
timestamp. The `build` job has no access to any of them. Keep an offline backup of every private
key. The release **public** key goes in `plugins.updater.pubkey` and in the app's trust anchors (#78).

Key formats differ: `tauri signer generate` writes the `.pub` file as base64 of a whole minisign
public-key file. `plugins.updater.pubkey` takes that string as is. The app's trust anchors
(`PinnedKey::from_base64` in `src-tauri/src/update/mod.rs`) take only the raw key, the second line
of the decoded text (it starts with `RW`):

```powershell
([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content release.key.pub -Raw).Trim())) -split "`n")[1].Trim()
```

Rotation: ship a release signed with the current key that pins the next key, then switch
`RELEASE_SIGNING_KEY` to release-next. Compromise: rotate the timestamp key by shipping an app
update (release key still good); if the release key leaked, yank everything signed since the leak,
rotate to release-next, and tell users to reinstall manually from a verified download.

## One-time repository setup (needs the owner, cannot be done by a workflow)

- Settings, General, Releases: enable **immutable releases**.
- Create the GitHub App (contents + pull requests, this repo only) and set `RELEASE_APP_ID` / `RELEASE_APP_PRIVATE_KEY`. Until `RELEASE_APP_ID` exists the release-please job is skipped, so pushes to `main` do not fail.
- Environments: `release` (required reviewer, deployment rule `v*` tags only is not possible for a branch-run job: restrict to `main`), `feed` (`main` only), `github-pages`.
- Rulesets: `refs/tags/v*` (only the release App may create; update and delete blocked, admin bypass for emergencies); `main` (require CI and the `PR title (Conventional Commits)` check from `pr-title.yml`).
- Generate the three keys and store the secrets as in the table above.

## How users verify a download

```powershell
gh release verify vX.Y.Z -R kash-talel/shush
gh release verify-asset vX.Y.Z shush_x64-setup.exe -R kash-talel/shush
gh attestation verify shush_x64-setup.exe -R kash-talel/shush
Get-FileHash .\shush_x64-setup.exe -Algorithm SHA256   # compare with SHA256SUMS.txt
```
