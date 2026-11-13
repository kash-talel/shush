# Phase 7b: extension and host registration (issue #53)

## Automated (run by `cargo test`)

- `os::native_host` registers and unregisters the three per-user keys under a scratch
  `HKCU\Software\ShushTest\...` root (never the real browser keys), checks the manifests pin
  exactly the shush extension, and checks the pinned Chromium id matches `extension/manifest.json`.
- `bridge::pairing::javascript_extension_pairs_with_the_host` runs `extension/pairing-cli.mjs`
  under Node (skipped without Node) and redeems its SPAKE2 message and proof against the Rust
  host, proving the extension's pairing and the derived pair key interoperate.

## CDP check of the Settings toggle (manual script)

Run the debug app per `docs/testing/README.md` with a scratch `SHUSH_VAULT_PATH` and
`SHUSH_NMH_REGISTRY_ROOT=Software\ShushTest\Manual` so the real browser keys stay untouched.
Over CDP: unlock, open Settings, tick "Allow browsers to talk to shush", then confirm
`reg query HKCU\Software\ShushTest\Manual /s` lists the three `NativeMessagingHosts\com.shush.vault`
keys and the `native-messaging\` manifests exist beside the scratch vault; untick and confirm both
are gone. Delete `HKCU\Software\ShushTest\Manual` afterwards.

## Extension against a test page (still to do)

Load `extension/` unpacked in Edge (`--load-extension`, driven over CDP), enable browser support
with the real registry root, pair with the code from Settings, and fill a local test login form
on `http://localhost`. Not yet scripted; the extension has so far been checked for syntax and
for pairing interoperability only.
