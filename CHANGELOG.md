# Changelog

## [0.1.2](https://github.com/kash-talel/shush/compare/v0.1.1...v0.1.2) (2026-11-14)


### Features

* **#103:** release-please pipeline, attested immutable releases, signed update feed ([#174](https://github.com/kash-talel/shush/issues/174)) ([dee410c](https://github.com/kash-talel/shush/commit/dee410c56b08b17cc49af031cce921399e5d7191))
* **#72:** attest build provenance for release installers ([#164](https://github.com/kash-talel/shush/issues/164)) ([064a4f7](https://github.com/kash-talel/shush/commit/064a4f77a62ee45c322667341cf44425f1f2c0b4))
* **#78:** offline verification core for the signed update feed ([#167](https://github.com/kash-talel/shush/issues/167)) ([079d12c](https://github.com/kash-talel/shush/commit/079d12ce5e6150e2a1047cae6556af0ab3c37647))
* **agy:** add /issue skill and workspace rules for Gemini 3.8 Flash runner ([#85](https://github.com/kash-talel/shush/issues/85)) ([29ec691](https://github.com/kash-talel/shush/commit/29ec6913592e8f4b391542f7e4604cd6ed095765))
* **artwork:** stage master 3-layer jewel case sources, pipeline script, and site update ([#126](https://github.com/kash-talel/shush/issues/126)) ([cdcb5ba](https://github.com/kash-talel/shush/commit/cdcb5bae4dce7a646e17d3868c7388d276f74fd4))


### Bug Fixes

* **release:** build frontend in src/, run tauri from the repo root ([#183](https://github.com/kash-talel/shush/issues/183)) ([49ebc28](https://github.com/kash-talel/shush/commit/49ebc28))
* **#100:** add reseal action to unlock screen via back button and Esc ([#105](https://github.com/kash-talel/shush/issues/105)) ([214bb28](https://github.com/kash-talel/shush/commit/214bb282066c639c0233415da41c1a8bb0275ffe))
* **#101:** remove tagline text and vertically center disc on installer sidebar ([#104](https://github.com/kash-talel/shush/issues/104)) ([ed97c52](https://github.com/kash-talel/shush/commit/ed97c52358f9f861b6b95d55bd30b42d98dd80f1))
* **#10:** assert live key is non-zero and test lock-vs-mutation ordering ([#79](https://github.com/kash-talel/shush/issues/79)) ([9fd9fe9](https://github.com/kash-talel/shush/commit/9fd9fe9b15489b1aea0350a77a4d2786f5e8b9c8))
* **#110:** normalize verbatim prefix in sibling_exe_junction test ([#111](https://github.com/kash-talel/shush/issues/111)) ([29ea318](https://github.com/kash-talel/shush/commit/29ea318bc7b36d408cea6ff8d7be3286e61858a3))
* **#114:** format pairing code with hyphens and auto-normalize input ([#122](https://github.com/kash-talel/shush/issues/122)) ([d074f00](https://github.com/kash-talel/shush/commit/d074f00695ca59db913078329f3af187a2993b7a))
* **#11:** flush vault replacement rename to disk with MOVEFILE_WRITE_THROUGH ([#81](https://github.com/kash-talel/shush/issues/81)) ([e0c1efc](https://github.com/kash-talel/shush/commit/e0c1efc87e20defed5b5d6b1dae49343f425071d))
* **#123:** fix cargo fmt check, clippy lints, and add them to runner verification ([#124](https://github.com/kash-talel/shush/issues/124)) ([bd113a1](https://github.com/kash-talel/shush/commit/bd113a150d2b23f9f10cedbee3b321b9428ab241))
* **#125:** update static logos, app icons, and installer graphics with jewel case artwork ([#128](https://github.com/kash-talel/shush/issues/128)) ([f7ac594](https://github.com/kash-talel/shush/commit/f7ac5944ce77d5205a1288509d7d056439426e5b))
* **#126:** remove 3D case rectangular box halo and decouple stationary CD hub ([#129](https://github.com/kash-talel/shush/issues/129)) ([aa461cd](https://github.com/kash-talel/shush/commit/aa461cd150ce1beaf18b7405017ae04f88759834))
* **#126:** stationary tray hub, drop rectangular shadows on app jewel case ([#133](https://github.com/kash-talel/shush/issues/133)) ([fb9f322](https://github.com/kash-talel/shush/commit/fb9f322da225fe3d64753a1b18eca640a8abb1a2))
* **#127:** theme the UI by vault colour, clean disc tinting, onboarding disc colour ([#135](https://github.com/kash-talel/shush/issues/135)) ([b9ce033](https://github.com/kash-talel/shush/commit/b9ce033a7a4c1404443da48b3de50633adcd07a4))
* **#12:** clear half-formatted clipboard secrets and clear on app exit ([#83](https://github.com/kash-talel/shush/issues/83)) ([38e0ad2](https://github.com/kash-talel/shush/commit/38e0ad2577941f9cc04865275e1fb2b24c035be8))
* **#13:** replace SendInput auto-type in spec with extension-verified fill ([#90](https://github.com/kash-talel/shush/issues/90)) ([04821de](https://github.com/kash-talel/shush/commit/04821de71040f7a5e1418ab653762699e4b48584))
* **#14:** spec uses Ctrl+Alt+Space, window title is a hint only, hotkey failure fallback ([#93](https://github.com/kash-talel/shush/issues/93)) ([0e00ca2](https://github.com/kash-talel/shush/commit/0e00ca26b173a9f92a06eef5dafcf48b06ebde32))
* **#17:** spec guided CSV export instead of browser profile decryption ([#136](https://github.com/kash-talel/shush/issues/136)) ([74a0171](https://github.com/kash-talel/shush/commit/74a0171b480d6acd9ccec6b0c75c97f457038fc5))
* **#18:** specify PAKE pairing, pinned peers and windowed discovery for LAN sync ([#94](https://github.com/kash-talel/shush/issues/94)) ([bc16538](https://github.com/kash-talel/shush/commit/bc16538050477be0717ec1920f7ab627f9e65477))
* **#19:** deletion tombstones, history purge, canonical import identity; no wall-clock merges ([#139](https://github.com/kash-talel/shush/issues/139)) ([de9fa2d](https://github.com/kash-talel/shush/commit/de9fa2d86b563ca001794eb2de281a0e63ff02a2))
* **#21:** document sequential Argon2 lanes, realistic timings, benchmark caps ([#141](https://github.com/kash-talel/shush/issues/141)) ([5128607](https://github.com/kash-talel/shush/commit/51286072f2dd04db2716ba9e7262b8aaf1b99c44))
* **#22:** self-describing checksummed keyfiles, corruption detected before KDF ([#142](https://github.com/kash-talel/shush/issues/142)) ([c56738c](https://github.com/kash-talel/shush/commit/c56738c9487f29e6b63bf565e4da2235a4d8b914))
* **#23:** reconcile inconsistencies across master spec, architecture plan, and security model ([#95](https://github.com/kash-talel/shush/issues/95)) ([8fd0067](https://github.com/kash-talel/shush/commit/8fd0067715ece8016dc04299f2094d5ecbf15075))
* **#24:** honour Steam Guard secrets; document URI-based OTP params ([#146](https://github.com/kash-talel/shush/issues/146)) ([e31c5a5](https://github.com/kash-talel/shush/commit/e31c5a5f609da29da2ba90593b7d95e19279751c))
* **#25:** air-gapped mode defaults on; define single network gate and HIBP padding ([#148](https://github.com/kash-talel/shush/issues/148)) ([2e02c50](https://github.com/kash-talel/shush/commit/2e02c50d586d5c9de951e2f9e70a3008918e2085))
* **#26:** specify vault lifecycle (rekey, migration, version policy, restore) ([#150](https://github.com/kash-talel/shush/issues/150)) ([a531c25](https://github.com/kash-talel/shush/commit/a531c250379453ec96ac41733cdb254584e0f525))
* **#27:** render recovery kit in-window with opt-in password handwriting box and zero disk residue ([#98](https://github.com/kash-talel/shush/issues/98)) ([90fc6e0](https://github.com/kash-talel/shush/commit/90fc6e05cd8afb6d38c857fcc1396843032f8caa))
* **#43:** persist delete throttle state and monotonic deadline across app restarts ([#102](https://github.com/kash-talel/shush/issues/102)) ([c537d57](https://github.com/kash-talel/shush/commit/c537d5719b2f816d3b29e41d7f516d08efd088ba))
* **#44:** document vaults.json security model and add lock screen privacy toggle ([#108](https://github.com/kash-talel/shush/issues/108)) ([83d14fe](https://github.com/kash-talel/shush/commit/83d14fed428f4c16bc49f95c867901eb3c036522))
* **#45:** provide safe UI actions and Explorer fallback for corrupt or missing vaults ([#109](https://github.com/kash-talel/shush/issues/109)) ([52345f3](https://github.com/kash-talel/shush/commit/52345f303b562c84d78dafa4828258478a5c6aae))
* **#46:** allow hiding default vault with safety net when other vaults exist ([#107](https://github.com/kash-talel/shush/issues/107)) ([9c72a54](https://github.com/kash-talel/shush/commit/9c72a5402762bfeaae009ac70614c327d5a8f74c))
* **#48:** unlock vaults on read-only media in read-only mode ([#112](https://github.com/kash-talel/shush/issues/112)) ([5438f7b](https://github.com/kash-talel/shush/commit/5438f7b570a5e10b26eec9ceaf3798d0872fda68))
* **#49:** recover from VAULT_CHANGED_ON_DISK without locking ([#118](https://github.com/kash-talel/shush/issues/118)) ([3794e8c](https://github.com/kash-talel/shush/commit/3794e8ccd74ef11222750f7b1adaef37f4bb827d))
* **#51:** shush-host.exe native-messaging relay ([#154](https://github.com/kash-talel/shush/issues/154)) ([073d084](https://github.com/kash-talel/shush/commit/073d084ace90be9da0edbc3145863ebd5a79a52f))
* **#52:** wire the browser bridge into the app ([#151](https://github.com/kash-talel/shush/issues/151)) ([647a7da](https://github.com/kash-talel/shush/commit/647a7dad82be8d7ebed028ba714369e60d8c2d98))
* **#53:** MV3 extension and per-user host registration ([#158](https://github.com/kash-talel/shush/issues/158)) ([0a6d8e6](https://github.com/kash-talel/shush/commit/0a6d8e645f64bb20e90455cba9c69c1bced16064))
* **#54:** use SPAKE2 PAKE for browser bridge pairing ([#116](https://github.com/kash-talel/shush/issues/116)) ([a6e4c3d](https://github.com/kash-talel/shush/commit/a6e4c3d19d10544915c5cebdbf8f7b1f85f376fa))
* **#56:** isolate debug build single-instance and WebView2 data folder ([#117](https://github.com/kash-talel/shush/issues/117)) ([e55ec39](https://github.com/kash-talel/shush/commit/e55ec39ec06b0eebfe7c1ace2ed8be20d4f973d4))
* **#59:** raw byte IPC unlock body and page-locked decrypted payload ([#119](https://github.com/kash-talel/shush/issues/119)) ([78770e3](https://github.com/kash-talel/shush/commit/78770e3611046b460b65857ca0d156f672135aa2))
* **#63:** make case toggle keyboard-operable and respect reduced-motion ([#120](https://github.com/kash-talel/shush/issues/120)) ([640c795](https://github.com/kash-talel/shush/commit/640c795ea28fb2baf80218006b50637340af1dc9))
* **#68:** require current password to set duress; warn about sync folders ([#161](https://github.com/kash-talel/shush/issues/161)) ([c5866cb](https://github.com/kash-talel/shush/commit/c5866cb4b905fe2c4900de6dcf4607df64f28188))
* **#68:** review fixes — timing test password, Confirm placeholder, e2e re-auth checks ([#162](https://github.com/kash-talel/shush/issues/162)) ([2b027d7](https://github.com/kash-talel/shush/commit/2b027d75d5109267442c3169265114017cfdf514))
* **#80:** detect cloud-sync conflicted copies and stale .tmp, surface on unlock screen ([#169](https://github.com/kash-talel/shush/issues/169)) ([061264d](https://github.com/kash-talel/shush/commit/061264df28d4ea80b20b745b5c23ee2c16a0148d))
* **#82:** clear clipboard secret on WM_ENDSESSION (logoff/shutdown) ([#172](https://github.com/kash-talel/shush/issues/172)) ([796a459](https://github.com/kash-talel/shush/commit/796a459e4108197d13e0812bf0e2a395761a2ee1))
* **#89:** canonicalize peer and own paths for junctioned installs in os::pipe ([#96](https://github.com/kash-talel/shush/issues/96)) ([427e87b](https://github.com/kash-talel/shush/commit/427e87b8ae8a3d22b1ce5be2b9752c5e01946652))
* **#97:** do not canonicalize peer path in is_sibling_exe (TOCTOU) ([#99](https://github.com/kash-talel/shush/issues/99)) ([12d140c](https://github.com/kash-talel/shush/commit/12d140c23a1eb64873adabd1ab3b1a84ff2ef6fb))
* **issue:** harden /issue dispatch after review ([#87](https://github.com/kash-talel/shush/issues/87)) ([1c92100](https://github.com/kash-talel/shush/commit/1c9210042d936269469ade4eec8ca7717a008a08))
* **issue:** run every /issue runner in an isolated worktree ([#88](https://github.com/kash-talel/shush/issues/88)) ([aabe38a](https://github.com/kash-talel/shush/commit/aabe38a9e953ba5cda00c11622f7e41913617635))
* **site:** remove tray hinge tab cutout artifact, enhance compact disc badge, and add cache-busters ([#130](https://github.com/kash-talel/shush/issues/130)) ([887e505](https://github.com/kash-talel/shush/commit/887e50566d62f82a47ae93cc837b81bd22c3b53e))


### Miscellaneous Chores

* release 0.1.2 ([#181](https://github.com/kash-talel/shush/issues/181)) ([bf3d4b6](https://github.com/kash-talel/shush/commit/bf3d4b665e100e2b473792743dea82bf595b8858))
