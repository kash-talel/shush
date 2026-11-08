// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut builder = shush_lib::builder();

    // Must be registered first on release builds: a second launch (e.g. double-clicking the
    // desktop shortcut again) focuses the running instance instead of
    // starting another process that could write the vault (issue #9).
    //
    // In debug builds, don't conflict with an installed shush instance (issue #56).
    // The single-instance lock is keyed on a distinct debug identifier below,
    // isolating it from the installed app (`com.shush.vault`). Testing scripts can
    // also skip single-instance entirely by setting `SHUSH_NO_SINGLE_INSTANCE`.
    #[cfg(debug_assertions)]
    let skip_single_instance = std::env::var_os("SHUSH_NO_SINGLE_INSTANCE").is_some();
    #[cfg(not(debug_assertions))]
    let skip_single_instance = false;

    if !skip_single_instance {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            shush_lib::show_main_window(app);
        }));
    }

    let mut context = tauri::generate_context!();
    #[cfg(debug_assertions)]
    {
        // Key debug builds on a distinct identifier so the single-instance mutex
        // and default WebView2 / app data directories never clash with installed shush.
        let vault_path = std::env::var_os("SHUSH_VAULT_PATH");
        context.config_mut().identifier =
            shush_lib::debug_app_identifier(vault_path.as_deref().map(std::path::Path::new));
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .build(context)
        .expect("error while building shush")
        .run(|_app, event| {
            // Spec §6.3: a copied secret must not outlive the app, whichever
            // path exits it (tray quit, programmatic exit, ...). Clears only if
            // the clipboard still holds shush's content.
            if let tauri::RunEvent::Exit = event {
                shush_lib::os::clipboard::clear_if_ours();
            }
        });
}
